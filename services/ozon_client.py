"""
Ozon 请求客户端 — 使用 curl_cffi 发起请求，自动处理 403 challenge

与 ozon_api.py 中 OzonApi 的核心逻辑一致。
"""

import json
import logging
import re
import threading
import time
from typing import Optional

import requests
from curl_cffi import Session

from app.config import settings
from utils.random_tools import (
    rand_get_user_agent,
    random_fingerprint,
    extract_chrome_version,
)

logger = logging.getLogger("ozon_client")

# ============================================================
# 公共常量
# ============================================================

_OZON_HEADERS = {
    'accept': 'application/json',
    'accept-language': 'zh-CN,zh;q=0.9',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': 'https://www.ozon.ru/?__rr=4&abt_att=1',
    'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
    'x-o3-app-name': 'dweb_client',
}

_SELLER_HEADERS = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'zh-Hans',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'origin': 'https://seller.ozon.ru',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': 'https://seller.ozon.ru/app/analytics/what-to-sell/ozon-bestsellers?__rr=1',
    'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
    'x-o3-app-name': 'seller-ui',
}


# ============================================================
# 指纹缓存
# ============================================================

_fingerprint_cache: tuple | None = None
_fingerprint_lock = threading.Lock()


def _generate_fingerprint_config() -> tuple:
    """生成随机指纹配置（模块级缓存，只请求一次）"""
    global _fingerprint_cache
    if _fingerprint_cache is not None:
        return _fingerprint_cache

    with _fingerprint_lock:
        if _fingerprint_cache is not None:
            return _fingerprint_cache

        ua = _OZON_HEADERS['user-agent']
        impersonate = "chrome136"
        unmasked_vendor = ""
        unmasked_renderer = ""

        ua_model = rand_get_user_agent(version="140,141,142,143,144")
        if ua_model:
            ua = ua_model.ua
            impersonate = extract_chrome_version(ua)
            try:
                client_hints_json = json.dumps(ua_model.clientHints.model_dump(by_alias=True))
                fp_model = random_fingerprint(ua, client_hints_json)
                if fp_model:
                    unmasked_vendor = fp_model.webglConfig.unmaskedVendor
                    unmasked_renderer = fp_model.webglConfig.unmaskedRenderer
            except Exception:
                pass
            logger.info(f"[指纹] UA={ua}, impersonate={impersonate}, vendor={unmasked_vendor}")
        else:
            logger.debug("[指纹] 获取随机UA失败, 使用默认配置")

        version = impersonate.replace("chrome", "")
        ozon_headers = dict(_OZON_HEADERS)
        ozon_headers.update({
            'user-agent': ua,
            'sec-ch-ua': f'"Google Chrome";v="{version}", "Chromium";v="{version}", "Not A(Brand";v="24"',
        })
        seller_headers = dict(_SELLER_HEADERS)
        seller_headers.update({
            'user-agent': ua,
            'sec-ch-ua': f'"Google Chrome";v="{version}", "Chromium";v="{version}", "Not A(Brand";v="24"',
        })

        _fingerprint_cache = (ua, impersonate, unmasked_vendor, unmasked_renderer, ozon_headers, seller_headers)
        return _fingerprint_cache


# ============================================================
# 工具函数
# ============================================================

def parse_cookies_to_dict(cookie_string: str) -> dict:
    if not cookie_string:
        return {}
    cookie_dict = {}
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookie_dict[key.strip()] = value.strip()
    return cookie_dict


def _build_proxies(proxy: str) -> Optional[dict]:
    if proxy:
        return {
            "http": f"socks5://{proxy}",
            "https": f"socks5://{proxy}",
        }
    return None


def _is_access_blocked(response) -> bool:
    text = response.text
    if 'id="challenge" type="hidden" value' in text:
        return False
    if 'id="captcha-input" type="hidden" value' in text:
        return False
    return 'Доступ ограничен' in text


def _extract_redirect_url(html: str) -> str | None:
    pattern = r'location\.replace\(["\'](.+?)["\']\)'
    match = re.search(pattern, html)
    if match:
        url = match.group(1)
        url = url.replace(r'\/', '/')
        url = url.encode().decode('unicode_escape')
        return url
    return None


def get_token_and_fp(challenge: str, user_agent: str = "",
                     unmasked_vendor: str = "", unmasked_renderer: str = "") -> tuple[str, str]:
    """调用 challenge 解析服务获取 token 和 fp"""
    json_data = {
        "challenge": challenge,
        "user_agent": user_agent,
        "unmasked_vendor": unmasked_vendor,
        "unmasked_renderer": unmasked_renderer,
    }
    for _ in range(3):
        try:
            resp = requests.post(
                f"{settings.challenge_host}/api/v1/ozon_abt/get_token_and_fp",
                json=json_data, timeout=30,
            )
            data = resp.json().get("data", {})
            return data.get("token", ""), data.get("fp", "")
        except Exception as e:
            logger.debug(f"[challenge] get_token_and_fp 异常: {e}")
    return "", ""


# ============================================================
# OzonClient — 单次请求客户端
# ============================================================

class OzonClient:
    """为每个 API 请求创建的轻量客户端，使用 curl_cffi Session"""

    def __init__(self, cookies_str: str = "", proxy: str = ""):
        self._cookies = parse_cookies_to_dict(cookies_str)
        self._proxies = _build_proxies(proxy)
        (self._ua, self._impersonate, self._unmasked_vendor, self._unmasked_renderer,
         self._ozon_headers, self._seller_headers) = _generate_fingerprint_config()
        self._session = Session(impersonate=self._impersonate)
        if self._cookies:
            self._session.cookies.update(self._cookies)
        self.last_error: str = ""

    def _handle_challenge(self, response) -> bool:
        """处理 403 challenge，返回 True 表示已处理（应重试）"""
        if response.status_code != 403:
            return False
        try:
            challenge = re.findall(
                r'id="challenge" type="hidden" value="(.*?)">', response.text
            )[0]
        except IndexError:
            try:
                challenge = re.findall(
                    r'id="captcha-input" type="hidden" value="(.*?)">', response.text
                )[0]
            except IndexError:
                logger.debug(f"[challenge] 403 但未找到 challenge 字段, body[:200]={response.text[:200]}")
                return False

        logger.debug(f"[challenge] 正在处理 403 challenge...")
        token, fp = get_token_and_fp(
            challenge, self._ua, self._unmasked_vendor, self._unmasked_renderer
        )
        json_data = {'token': token, 'fp': fp, 'error': ''}
        resp = self._session.post(
            'https://www.ozon.ru/abt/result',
            headers=self._ozon_headers,
            json=json_data,
            proxies=self._proxies,
        )
        for key, value in resp.cookies.items():
            self._cookies[key] = value
        return True

    def _reset_session(self):
        """重置 session（遭遇封锁时）"""
        logger.debug("[session] 访问被封锁, 重置 session")
        self._session = Session(impersonate=self._impersonate)
        if self._cookies:
            self._session.cookies.update(self._cookies)
        try:
            response = self._session.get(
                'https://www.ozon.ru',
                cookies=self._cookies,
                headers=self._ozon_headers,
                proxies=self._proxies,
            )
            self._handle_challenge(response)
        except Exception as e:
            logger.debug(f"[session] 重置 session 请求 ozon.ru 失败: {e}")

    # ── 商品页面 ──

    def get_page_data(self, sku: str) -> dict:
        params = {'url': f'/product/{sku}'}
        for attempt in range(3):
            try:
                response = self._session.get(
                    'https://www.ozon.ru/api/entrypoint-api.bx/page/json/v2',
                    params=params, cookies=self._cookies,
                    headers=self._ozon_headers, proxies=self._proxies,
                )
                if response.status_code != 200 and response.status_code != 403:
                    self.last_error = f"status_code={response.status_code}"
                    continue
                if _is_access_blocked(response):
                    self.last_error = "access_blocked"
                    self._reset_session()
                    continue
                if self._handle_challenge(response):
                    self.last_error = "403_challenge"
                    continue
                return response.json()
            except Exception as e:
                self.last_error = f"exception: {e}"
        return {}

    # ── 翻页 ──

    def get_next_page(self, uri: str = "") -> dict:
        if not uri:
            uri = "/?layout_container=pdpPage2column&layout_page_index=1"
        params = {'url': uri.replace('&__rr=1', "")}
        for attempt in range(3):
            try:
                response = self._session.get(
                    'https://www.ozon.ru/api/entrypoint-api.bx/page/json/v2',
                    params=params, cookies=self._cookies,
                    proxies=self._proxies, headers=self._ozon_headers,
                )
                if response.status_code != 200 and response.status_code != 403:
                    self.last_error = f"status_code={response.status_code}"
                    continue
                if _is_access_blocked(response):
                    self.last_error = "access_blocked"
                    self._reset_session()
                    continue
                if self._handle_challenge(response):
                    self.last_error = "403_challenge"
                    continue
                return response.json()
            except Exception as e:
                self.last_error = f"exception: {e}"
        return {}

    # ── 搜索 ──

    def search(self, search_text: str) -> str:
        """搜索关键词，返回 HTML"""
        params = {'text': search_text, 'from_global': 'true'}
        for attempt in range(3):
            try:
                response = self._session.get(
                    'https://www.ozon.ru/search',
                    params=params, cookies=self._cookies,
                    proxies=self._proxies, headers=self._ozon_headers,
                )
                if response.status_code != 200 and response.status_code != 403:
                    self.last_error = f"status_code={response.status_code}"
                    continue
                if _is_access_blocked(response):
                    self.last_error = "access_blocked"
                    self._reset_session()
                    continue
                if self._handle_challenge(response):
                    self.last_error = "403_challenge"
                    continue
                html = response.text
                redirect_url = _extract_redirect_url(html)
                if redirect_url:
                    if redirect_url.startswith('/'):
                        redirect_url = 'https://www.ozon.ru' + redirect_url
                    response = self._session.get(
                        redirect_url, cookies=self._cookies,
                        headers=self._ozon_headers, proxies=self._proxies,
                    )
                    if response.status_code != 200 and response.status_code != 403:
                        self.last_error = f"redirect status_code={response.status_code}"
                        continue
                    if _is_access_blocked(response):
                        self.last_error = "redirect access_blocked"
                        self._reset_session()
                        time.sleep(5)
                        continue
                    if self._handle_challenge(response):
                        self.last_error = "redirect 403_challenge"
                        continue
                    html = response.text
                return html
            except Exception as e:
                self.last_error = f"exception: {e}"
        return ""

    # ── 店铺页面 ──

    def get_shop_page(self, shop_url: str) -> str:
        """获取店铺页面 HTML"""
        for attempt in range(5):
            try:
                response = self._session.get(
                    shop_url, cookies=self._cookies,
                    headers=self._ozon_headers, proxies=self._proxies,
                )
                if response.status_code != 200 and response.status_code != 403:
                    self.last_error = f"status_code={response.status_code}"
                    continue
                if _is_access_blocked(response):
                    self.last_error = "access_blocked"
                    self._reset_session()
                    continue
                if self._handle_challenge(response):
                    self.last_error = "403_challenge"
                    continue
                html = response.text
                redirect_url = _extract_redirect_url(html)
                if redirect_url:
                    if redirect_url.startswith('/'):
                        redirect_url = 'https://www.ozon.ru' + redirect_url
                    response = self._session.get(
                        redirect_url, cookies=self._cookies,
                        headers=self._ozon_headers, proxies=self._proxies,
                    )
                    if response.status_code != 200 and response.status_code != 403:
                        self.last_error = f"redirect status_code={response.status_code}"
                        continue
                    if _is_access_blocked(response):
                        self.last_error = "redirect access_blocked"
                        self._reset_session()
                        time.sleep(5)
                        continue
                    if self._handle_challenge(response):
                        self.last_error = "redirect 403_challenge"
                        continue
                    html = response.text
                return html
            except Exception as e:
                self.last_error = f"exception: {e}"
        return ""

    # ── 跟卖商家 ──

    def get_other_offers(self, sku: str) -> dict:
        params = {'url': f"/modal/otherOffersFromSellers?product_id={sku}&page_changed=true"}
        for attempt in range(3):
            try:
                response = self._session.get(
                    'https://www.ozon.ru/api/entrypoint-api.bx/page/json/v2',
                    params=params, cookies=self._cookies,
                    headers=self._ozon_headers, proxies=self._proxies,
                )
                if response.status_code != 200 and response.status_code != 403:
                    self.last_error = f"status_code={response.status_code}"
                    continue
                if _is_access_blocked(response):
                    self.last_error = "access_blocked"
                    self._reset_session()
                    continue
                if self._handle_challenge(response):
                    self.last_error = "403_challenge"
                    continue
                return response.json()
            except Exception as e:
                self.last_error = f"exception: {e}"
        return {}

    # ── 店铺经营天数 ──

    def get_store_created_days(self, seller_id: str) -> dict:
        params = {'url': f"/modal/shop-in-shop-info?seller_id={seller_id}&page_changed=true"}
        for attempt in range(3):
            try:
                response = self._session.get(
                    'https://www.ozon.ru/api/entrypoint-api.bx/page/json/v2',
                    params=params, cookies=self._cookies,
                    headers=self._ozon_headers, proxies=self._proxies,
                )
                if response.status_code != 200 and response.status_code != 403:
                    self.last_error = f"status_code={response.status_code}"
                    continue
                if _is_access_blocked(response):
                    self.last_error = "access_blocked"
                    self._reset_session()
                    continue
                if self._handle_challenge(response):
                    self.last_error = "403_challenge"
                    continue
                return response.json()
            except Exception as e:
                self.last_error = f"exception: {e}"
        return {}

    # ── 卖家后台数据 ──

    def get_seller_data(self, company_id: str, sku: str) -> dict:
        json_data = {
            'limit': '50',
            'offset': '0',
            'filter': {
                'stock': 'any_stock',
                'period': 'monthly',
                'categories': [],
                'sku': f'{sku}',
            },
            'sort': {
                'key': 'sum_missed_gmv_desc',
            },
        }
        cookies_str = '; '.join(f'{k}={v}' for k, v in self._cookies.items())
        headers = {
            **self._seller_headers,
            'x-o3-company-id': f'{company_id}',
            'x-o3-language': 'zh-Hans',
            'x-o3-page-type': 'analytics_platform',
            'cookie': cookies_str,
        }
        for attempt in range(3):
            try:
                response = self._session.post(
                    'https://seller.ozon.ru/api/site/seller-analytics/what_to_sell/data/v3',
                    headers=headers,
                    json=json_data,
                )
                return response.json()
            except Exception as e:
                self.last_error = f"exception: {e}"
        return {}
