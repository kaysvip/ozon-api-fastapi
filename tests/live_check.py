"""
实网连通性检查：抓一次真实挑战页，本地求解并提交 /abt/result。

pytest 不会收集本文件（文件名不以 test_ 开头）——它要打真实网络，
结果取决于出口 IP，不适合当单元测试。

    uv run python tests/live_check.py                    # 直连
    uv run python tests/live_check.py http://127.0.0.1:7890
    uv run python tests/live_check.py socks5://user:pass@host:1080

不同出口 IP 下发的关卡不一样：JS 挑战页 / 滑块验证码页 / 直接封禁页。
从被硬封的 IP 出去只会拿到封禁页（静态 4KB、零 script），此时脚本会
明确告诉你「这个 IP 拿不到挑战页」，而不是报求解失败。
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from curl_cffi import requests  # noqa: E402

from services.ozon_challenge import build_profile, is_js_challenge, solve_challenge  # noqa: E402

PRODUCT_URL = ("https://www.ozon.ru/product/"
               "zhilet-uteplennyy-everly-wear-zhiletka-zhenskaya-uteplennaya-2857830919/?__rr=1")

NAV_HEADERS = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,'
              'image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    'priority': 'u=0, i',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
}


def classify(text: str) -> str:
    if is_js_challenge(text):
        return "js_challenge"
    if 'id="captcha-input" type="hidden" value' in text:
        return "captcha"
    if 'Доступ ограничен' in text or '<script' not in text:
        return "blocked"
    return "ok"


def main(proxy: str | None, tries: int = 5) -> int:
    profile = build_profile()
    print(f"档案: {profile.user_agent}")
    print(f"      impersonate={profile.impersonate} 显卡={profile.unmasked_renderer[:60]}...")
    print(f"      sec-ch-ua={profile.sec_ch_ua}")
    print(f"代理: {proxy or '直连'}\n")

    headers = {**NAV_HEADERS, **profile.nav_headers()}

    for attempt in range(1, tries + 1):
        sess = requests.Session(impersonate=profile.impersonate, proxy=proxy, verify=False)
        try:
            resp = sess.get(PRODUCT_URL, headers=headers, timeout=60)
        except Exception as exc:
            print(f"[{attempt}] 取页失败: {type(exc).__name__}: {exc}")
            continue
        resp.encoding = "utf-8"
        kind = classify(resp.text)
        title = re.search(r"<title>(.*?)</title>", resp.text)
        print(f"[{attempt}] {resp.status_code} {len(resp.text)}B 关卡={kind} "
              f"title={title.group(1) if title else '?'}")

        if kind == "ok":
            print("    这个出口没有触发关卡，页面直接可用")
            return 0
        if kind == "blocked":
            print("    直接封禁页（无 script），这个 IP 拿不到挑战页 —— 换出口再试")
            continue
        if kind == "captcha":
            print("    下发的是滑块验证码页，不是 JS 挑战页；本脚本只验 JS 挑战")
            continue

        # ── JS 挑战页：本地求解并提交 ──
        try:
            result = solve_challenge(resp.text, str(resp.url), profile)
        except Exception as exc:
            print(f"    本地求解失败: {type(exc).__name__}: {exc}")
            return 1

        print(f"    求解 OK: browser_2={result.browser_2} pow={result.pow_ms}ms "
              f"pzc={result.difficulty_nonce} fp={len(result.fp)}B")

        submit_headers = {
            'accept': '*/*',
            'accept-language': NAV_HEADERS['accept-language'],
            'content-type': 'application/json;charset=UTF-8',
            'origin': 'https://www.ozon.ru',
            'referer': str(resp.url),
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            **profile.nav_headers(),
        }
        r2 = sess.post("https://www.ozon.ru/abt/result", headers=submit_headers,
                       json=result.result_payload(), timeout=60)
        print(f"    提交: {r2.status_code} {r2.text[:200]}")
        passed = '"ok":true' in r2.text.replace(" ", "")
        print(f"    => {'PASSED' if passed else 'FAILED'}")
        if passed:
            print(f"    abt_data={sess.cookies.get('abt_data', '')[:60]}...")
            return 0
        return 1

    print("\n连续多次都没拿到 JS 挑战页")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else None))
