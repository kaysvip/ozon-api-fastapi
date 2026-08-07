"""
fp 组装与加密。

fp 是一个 32 键的大对象：静态底板（fp_base.json，真实浏览器抓包）
+ 指纹档案（UaProfile）+ 本次请求的动态值。键序由 FP_KEY_ORDER 定死，
序列化后直接参与加密，错一个字符就废。
"""

import copy
import json
import random
import re
from pathlib import Path

from services.ozon_challenge.dynamic import build_dynamic
from services.ozon_challenge.profile import UaProfile
from services.ozon_challenge.proof import PowResult, build_browser_2
from services.ozon_crypto import (
    derive_kdf_key,
    insert_marker,
    js_json_dumps,
    js_number_to_string,
    kdf_encrypt,
    md5_hex,
    parse_challenge,
    xor_with_token,
)

__all__ = ["FP_KEY_ORDER", "load_fp_base", "build_fp", "apply_profile"]

_FP_BASE_PATH = Path(__file__).with_name("fp_base.json")
_FP_BASE_CACHE: dict | None = None

FP_KEY_ORDER = [
    "challenge", "user_agent", "browser", "props", "screen_1", "screen_2", "screen_3",
    "touch", "battery", "location", "context", "storage", "hev", "media_devices",
    "navigator", "performance", "video", "webgl", "canvas", "fn_1", "fn_2", "fn_3",
    "ts", "nonce", "pzs", "pzc", "css", "rtc", "fonts", "browser_2", "timings", "ctm",
]

_ORIGIN_RE = re.compile(r"^(\w+://[^/?#]+).*$")


def load_fp_base() -> dict:
    global _FP_BASE_CACHE
    if _FP_BASE_CACHE is None:
        with _FP_BASE_PATH.open(encoding="utf-8") as f:
            _FP_BASE_CACHE = json.load(f)
    return copy.deepcopy(_FP_BASE_CACHE)


def _set(node: dict, key: str, value) -> None:
    """只允许改已存在的键——底板结构变了要立刻报错，而不是悄悄多塞一个字段"""
    if key not in node:
        raise KeyError(f"fp_base 里没有键 {key!r}，底板结构可能已变")
    node[key] = value


def apply_profile(fp: dict, profile: UaProfile) -> None:
    """把指纹档案写进 fp 的各个角落，保证 UA / 客户端提示 / 屏幕 / 显卡彼此自洽"""
    _set(fp, "user_agent", profile.user_agent)

    hev = fp["hev"]
    _set(hev, "architecture", profile.architecture)
    _set(hev, "bitness", profile.bitness)
    _set(hev, "brands", profile.brands)
    _set(hev, "fullVersionList", profile.full_version_list)
    _set(hev, "platformVersion", profile.platform_version)
    _set(hev, "uaFullVersion", profile.edge_full)

    nav = fp["navigator"]["@proto:Navigator"]
    _set(nav, "@get:userAgent", profile.user_agent)
    _set(nav, "@get:appVersion", profile.app_version)
    _set(nav, "@get:hardwareConcurrency", profile.hardware_concurrency)
    _set(nav, "@get:deviceMemory", profile.device_memory)

    w, h = profile.viewport_width, profile.viewport_height

    scr = fp["screen_1"]["@proto:Screen"]
    for k in ("@get:height", "@get:availHeight"):
        _set(scr, k, h)
    for k in ("@get:width", "@get:availWidth"):
        _set(scr, k, w)

    s2 = fp["screen_2"]
    _set(s2, "tiWidth", w)
    _set(s2, "tiHeight", h)
    _set(s2, "toWidth", profile.outer_width)
    _set(s2, "toHeight", profile.outer_height)
    _set(s2, "scw", w)
    _set(s2, "sch", h)
    dbcr = s2["dbcr"]
    _set(dbcr, "width", w)
    _set(dbcr, "height", h)
    _set(dbcr, "right", w)
    _set(dbcr, "bottom", h)

    vv = fp["screen_3"]["@val:wv"]["@proto:VisualViewport"]
    _set(vv, "@get:width", w)
    _set(vv, "@get:height", h)

    wg = fp["webgl"]
    _set(wg, "unmasked_vendor", profile.unmasked_vendor)
    _set(wg, "unmasked_renderer", profile.unmasked_renderer)


def _build_performance(timeline: dict, memory: dict) -> dict:
    """
    performance 对象。结构照搬真实抓包：挑战页是客户端跳转过来的，
    所以没有重定向记录；连接复用，DNS/TCP 各阶段与 fetchStart 重合。
    """
    t = timeline["timing"]
    return {
        "@proto:Performance": {
            "@proto:EventTarget": {},
            "@get:interactionCount": 0,
            "@get:eventCounts": {"@proto:EventCounts": {"@get:size": 36}},
            "@get:memory": {
                "@proto:Object": {
                    "@get:jsHeapSizeLimit": memory["limit"],
                    "@get:usedJSHeapSize": memory["used"],
                    "@get:totalJSHeapSize": memory["total"],
                }
            },
            "@get:navigation": {
                "@proto:PerformanceNavigation": {
                    "@val:TYPE_RESERVED": 255, "@val:TYPE_BACK_FORWARD": 2,
                    "@val:TYPE_RELOAD": 1, "@val:TYPE_NAVIGATE": 0,
                    "@get:redirectCount": 0, "@get:type": 0,
                }
            },
            "@get:timing": {
                "@proto:PerformanceTiming": {
                    "@get:loadEventEnd": t["loadEventEnd"],
                    "@get:loadEventStart": t["loadEventStart"],
                    "@get:domComplete": t["domComplete"],
                    "@get:domContentLoadedEventEnd": t["domContentLoadedEventEnd"],
                    "@get:domContentLoadedEventStart": t["domContentLoadedEventStart"],
                    "@get:domInteractive": t["domInteractive"],
                    "@get:domLoading": t["domLoading"],
                    "@get:responseEnd": t["responseEnd"],
                    "@get:responseStart": t["responseStart"],
                    "@get:requestStart": t["requestStart"],
                    "@get:secureConnectionStart": t["secureConnectionStart"],
                    "@get:connectEnd": t["connectEnd"],
                    "@get:connectStart": t["connectStart"],
                    "@get:domainLookupEnd": t["domainLookupEnd"],
                    "@get:domainLookupStart": t["domainLookupStart"],
                    "@get:fetchStart": t["fetchStart"],
                    "@get:redirectEnd": t["redirectEnd"],
                    "@get:redirectStart": t["redirectStart"],
                    "@get:unloadEventEnd": t["unloadEventEnd"],
                    "@get:unloadEventStart": t["unloadEventStart"],
                    "@get:navigationStart": t["navigationStart"],
                }
            },
            "@get:onresourcetimingbufferfull": "_n_",
            "@get:timeOrigin": timeline["timeOrigin"],
        }
    }


_FN1_EXC = "TypeError: Function.prototype.toString requires that 'this' be a Function"


def _build_stack(href: str, line: int, cols: list[int]) -> str:
    """伪造 fn_1 的 V8 调用栈，列号来自混淆脚本里 5 个特征代码块的位置"""
    def at(i: int) -> str:
        return f"({href}:{line}:{cols[i]})"

    return (
        f"{_FN1_EXC}\n"
        "    at Object.toString (<anonymous>)\n"
        f"    at Object.aQ [as fnCall1] {at(0)}\n"
        f"    at S.g.<computed>.<computed> {at(1)}\n"
        f"    at S.runFuncAt {at(2)}\n"
        f"    at {href}:{line}:{cols[3]}\n"
        f"    at async bE {at(4)}"
    )


def _post_timings(timeline: dict) -> dict:
    """POST body 里的 timings —— 必须和 fp.performance.timing 同源"""
    t = timeline["timing"]
    keys = ["connectStart", "secureConnectionStart", "unloadEventEnd", "domainLookupStart",
            "domainLookupEnd", "responseStart", "connectEnd", "responseEnd", "requestStart",
            "domLoading", "redirectStart", "loadEventEnd", "domComplete", "navigationStart",
            "loadEventStart", "domContentLoadedEventEnd", "unloadEventStart", "redirectEnd",
            "domInteractive", "fetchStart", "domContentLoadedEventStart"]
    out = {k: t[k] for k in keys}
    out["jobStart"] = timeline["jobStart"]
    out["jobEnd"] = timeline["jobEnd"]
    return out


def build_fp(pow_result: PowResult, profile: UaProfile, href: str,
             dyn: dict | None = None, *, rng: random.Random | None = None,
             random_key: float | None = None, salt: bytes | None = None) -> dict:
    """
    组装并加密 fp。

    random_key / salt 只在测试里注入，用于和 JS 参考实现逐字节比对；
    生产路径下两者都取随机值。
    """
    rng = rng or random
    if dyn is None:
        dyn = build_dynamic(pow_result.pow_ms, rng=rng)

    challenge_data = parse_challenge(pow_result.challenge)
    if random_key is None:
        random_key = rng.random()
    random_key_md5 = md5_hex(js_number_to_string(random_key))
    key = derive_kdf_key(challenge_data, random_key_md5)

    origin = _ORIGIN_RE.sub(r"\1", href)
    browser_2 = build_browser_2(pow_result.template, profile.user_agent, pow_result.version)

    fp = load_fp_base()
    apply_profile(fp, profile)

    _set(fp, "challenge", {
        "id": pow_result.id,
        "version": pow_result.version,
        "checkStr": random_key_md5[:10],
    })
    _set(fp, "location", {"@val:referrer": href, "@val:ploc": origin, "@val:loc": origin})
    _set(fp, "performance", _build_performance(dyn["timeline"], dyn["memory"]))
    _set(fp, "fn_1", {
        "exc": _FN1_EXC,
        "stack": _build_stack(href, pow_result.script_line, pow_result.cols),
    })
    _set(fp, "ts", dyn["ts"])
    _set(fp, "nonce", md5_hex(str(dyn["ts"]))[-7:])
    _set(fp, "pzs", pow_result.pzs)
    _set(fp, "pzc", pow_result.pzc)
    _set(fp, "browser_2", browser_2)
    _set(fp, "timings", dyn["timings"])
    _set(fp, "ctm", dyn["ctm"])

    conn = fp["navigator"]["@proto:Navigator"]["@get:connection"]["@proto:NetworkInformation"]
    _set(conn, "@get:downlink", dyn["connection"]["downlink"])
    _set(conn, "@get:rtt", dyn["connection"]["rtt"])
    _set(conn, "@get:effectiveType", dyn["connection"]["effectiveType"])

    ordered = {k: fp[k] for k in FP_KEY_ORDER}
    fp_json = js_json_dumps(ordered)

    encrypted = kdf_encrypt(xor_with_token(fp_json, pow_result.token), key, salt=salt)
    fp_final = insert_marker(encrypted, random_key_md5[:4])

    return {
        "fp": fp_final,
        "token": pow_result.token,
        "browser_2": browser_2,
        "timings": _post_timings(dyn["timeline"]),
    }
