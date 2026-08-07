"""
Ozon 请求客户端 — 使用 curl_cffi 发起请求，自动处理 403 challenge

challenge 默认在本地求解（services/ozon_challenge），不依赖外部服务；
求解失败时可回退到 OZON_CHALLENGE_HOST。
"""

import logging
import re
import time
from typing import Optional

import requests
from curl_cffi import Session

from app.config import settings
from services.ozon_captcha.captcha_solver import build_captcha_result
from services.ozon_challenge import UaProfile, is_js_challenge, solve_challenge
from services.ozon_challenge.profile import get_profile

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
# 指纹档案
# ============================================================

def _headers_for(profile: UaProfile) -> tuple[dict, dict]:
    """
    按档案改写两套请求头。

    user-agent 与 sec-ch-ua 必须和 fp 里的值完全一致：
    browser_2 的 CRC32 是拿 user-agent 算的，hev.brands 又要和 sec-ch-ua 对得上。
    """
    patch = profile.nav_headers()
    ozon_headers = {**_OZON_HEADERS, **patch}
    seller_headers = {**_SELLER_HEADERS, **patch}
    return ozon_headers, seller_headers


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
    """
    调用外部 challenge 解析服务获取 token 和 fp。

    本地求解（services/ozon_challenge）上线后这条路只作回退：
    本地拿得到整页 HTML，能算出 browser_2 和调用栈；这里只有 challenge 串，
    信息量更少。/api/v1/ozon_abt/get_token_and_fp 接口仍然透传到这里。
    """
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

    def __init__(self, cookies_str: str = "", proxy: str = "", profile: UaProfile | None = None):
        self._cookies = parse_cookies_to_dict(cookies_str)
        self._proxies = _build_proxies(proxy)
        # 每个客户端取一份档案（来自进程级档案池），而不是全进程共用一套指纹
        self._profile = profile or get_profile(settings.profile_pool_size)
        self._impersonate = self._profile.impersonate
        self._ozon_headers, self._seller_headers = _headers_for(self._profile)
        self._session = Session(impersonate=self._impersonate)
        if self._cookies:
            self._session.cookies.update(self._cookies)
        self.last_error: str = ""

    @property
    def profile(self) -> UaProfile:
        return self._profile

    def _merge_cookies(self, resp) -> None:
        for key, value in resp.cookies.items():
            self._cookies[key] = value

    def _solve_js_challenge(self, response) -> bool:
        """本地求解 JS challenge 并提交 /abt/result"""
        try:
            result = solve_challenge(response.text, str(response.url), self._profile)
        except Exception as e:
            logger.debug(f"[challenge] 本地求解失败: {e}")
            return False

        resp = self._session.post(
            'https://www.ozon.ru/abt/result',
            headers=self._ozon_headers,
            json=result.result_payload(),
            proxies=self._proxies,
        )
        self._merge_cookies(resp)
        logger.debug(f"[challenge] 本地求解已提交, status={resp.status_code} "
                     f"pow={result.pow_ms}ms browser_2={result.browser_2}")
        return True

    def _solve_js_challenge_remote(self, response) -> bool:
        """回退：把 challenge 串交给外部服务换 token/fp"""
        m = re.search(r'id="challenge" type="hidden" value="(.*?)">', response.text)
        if not m:
            return False
        token, fp = get_token_and_fp(
            m.group(1), self._profile.user_agent,
            self._profile.unmasked_vendor, self._profile.unmasked_renderer,
        )
        if not token and not fp:
            return False
        resp = self._session.post(
            'https://www.ozon.ru/abt/result',
            headers=self._ozon_headers,
            json={'token': token, 'fp': fp, 'error': ''},
            proxies=self._proxies,
        )
        self._merge_cookies(resp)
        logger.debug(f"[challenge] 远程求解已提交, status={resp.status_code}")
        return True

    def _solve_captcha(self, response) -> bool:
        """滑块验证码页：本地识别滑块并提交 /abt/captcha/result"""
        m = re.search(r'id="captcha-input" type="hidden" value="(.*?)">', response.text)
        if not m:
            return False
        try:
            result = build_captcha_result(m.group(1), self._profile.user_agent)
        except Exception as e:
            logger.debug(f"[captcha] 滑块求解失败: {e}")
            return False

        resp = self._session.post(
            'https://www.ozon.ru/abt/captcha/result',
            headers=self._ozon_headers,
            json={'token': result['token'], 'fp': result['fp'], 'error': ''},
            proxies=self._proxies,
        )
        self._merge_cookies(resp)
        logger.debug(f"[captcha] 已提交, status={resp.status_code} slider_x={result['slider_x']}")
        return True

    def _handle_challenge(self, response) -> bool:
        """
        处理 403 关卡，返回 True 表示已处理（调用方应重试）。

        不同出口 IP 下发的关卡不一样：JS 挑战页 / 滑块验证码页 / 直接封禁页，
        三者的解法和提交地址都不同。
        """
        if response.status_code != 403:
            return False

        text = response.text
        if is_js_challenge(text):
            if settings.local_challenge and self._solve_js_challenge(response):
                return True
            if settings.challenge_remote_fallback:
                return self._solve_js_challenge_remote(response)
            return False

        if 'id="captcha-input" type="hidden" value' in text:
            return self._solve_captcha(response)

        logger.debug(f"[challenge] 403 但未找到关卡字段, body[:200]={text[:200]}")
        return False

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
