"""
每次请求都要重新编的动态值：采集耗时、导航时间线、网络质量、内存。

这些数字之间必须自洽——服务端会拿 fp 里的时间线和 POST body 里的 timings
对照，也会看各项耗时的量级是否像真实浏览器。区间取自真实抓包。
"""

import math
import random
import time

__all__ = ["TIMING_RANGES", "perf_ms", "build_dynamic"]

# 各采集项的耗时区间（毫秒）。顺序就是浏览器的采集顺序，不能调整。
# pow 由实测填入。
TIMING_RANGES: list[tuple[str, float | None, float | None]] = [
    ('challenge', 0.4, 0.7), ('user_agent', 0.2, 0.4), ('browser', 0.4, 0.7),
    ('props', 2.2, 4.6), ('screen_1', 1.3, 1.7), ('screen_2', 0.4, 0.6),
    ('screen_3', 0.6, 0.9), ('touch', 0.0, 0.2), ('battery', 0.2, 0.4),
    ('location', 0.2, 0.4), ('context', 0.4, 0.7), ('storage', 0.0, 0.2),
    ('hev', 0.2, 0.4), ('media_devices', 0.2, 0.4), ('navigator', 7.5, 9.5),
    ('performance', 1.2, 1.6), ('video', 0.2, 0.4), ('webgl', 15.0, 30.0),
    ('canvas', 25.0, 40.0), ('fn_1', 0.8, 1.2), ('fn_2', 0.2, 0.4),
    ('fn_3', 0.8, 1.2), ('tsnonce', 0.05, 0.15), ('pow', None, None),
    ('css', 1.0, 1.4), ('rtc', 400.0, 700.0), ('fonts', 80.0, 110.0),
    ('browser_2', 0.4, 0.6),
]

# Chrome 的 performance.now() 差值：按 0.1ms 量化，并带极小的浮点残差
PERF_EPS = 4.76837158203125e-8


def _js_round(x: float) -> int:
    """JS 的 Math.round 是 .5 向上（朝 +∞），和 Python 的银行家舍入不同"""
    return math.floor(x + 0.5)


def perf_ms(ms: float, rng: random.Random) -> float:
    return _js_round(ms * 10) / 10 + rng.randint(-4, 2) * PERF_EPS


def _build_timings(pow_ms: float, rng: random.Random) -> dict[str, float]:
    return {
        k: perf_ms(pow_ms if k == 'pow' else rng.uniform(lo, hi), rng)
        for k, lo, hi in TIMING_RANGES
    }


def _build_timeline(ts: int, collect_start: int, ctm: float, rng: random.Random) -> dict:
    """
    一整条自洽的导航时间线。形状照搬真实抓包：挑战页是客户端跳转过来的，
    performance 里没有重定向记录；连接复用，所以 DNS/TCP 各阶段与 fetchStart
    重合、secureConnectionStart 为 0。
    """
    nav = ts - rng.randint(1450, 2050)
    fetch_start = nav + rng.randint(2, 8)
    request_start = fetch_start + rng.randint(2, 6)
    response_start = request_start + rng.randint(520, 900)      # TTFB
    response_end = response_start + rng.randint(120, 320)
    dom_loading = response_start + rng.randint(2, 10)           # 收到头就开始解析
    unload_event = dom_loading - rng.randint(0, 2)
    dom_interactive = response_end + rng.randint(1, 6)
    dom_complete = dom_interactive + rng.randint(300, 500)

    return {
        'timeOrigin': nav + rng.randint(1, 9) / 10,
        'jobStart': dom_loading + rng.randint(1, 4),            # 内联脚本 mark('jobStart')
        'jobEnd': collect_start + _js_round(ctm) - rng.randint(150, 250),
        'timing': {
            'navigationStart': nav, 'redirectStart': 0, 'redirectEnd': 0,
            'fetchStart': fetch_start, 'domainLookupStart': fetch_start,
            'domainLookupEnd': fetch_start, 'connectStart': fetch_start,
            'connectEnd': fetch_start, 'secureConnectionStart': 0,
            'requestStart': request_start, 'responseStart': response_start,
            'responseEnd': response_end, 'unloadEventStart': unload_event,
            'unloadEventEnd': unload_event, 'domLoading': dom_loading,
            'domInteractive': dom_interactive,
            'domContentLoadedEventStart': dom_interactive,
            'domContentLoadedEventEnd': dom_interactive,
            'domComplete': dom_complete, 'loadEventStart': dom_complete,
            'loadEventEnd': dom_complete + rng.randint(1, 5),
        },
    }


def _build_connection(rng: random.Random) -> dict:
    """Chrome 把实测网络质量量化后才暴露：rtt 取 25ms 整数倍，downlink 取 0.05Mbps 整数倍"""
    rtt = rng.randint(11, 32) * 25
    downlink = round(_js_round(rng.uniform(0.7, 1.7) / 0.05) * 0.05, 2)
    effective = ('slow-2g' if rtt >= 2000 else '2g' if rtt >= 1400
                 else '3g' if rtt >= 270 else '4g')
    return {'rtt': rtt, 'downlink': downlink, 'effectiveType': effective}


def build_dynamic(pow_ms: float, collect_start: int | None = None,
                  rng: random.Random | None = None) -> dict:
    """
    组装一次请求所需的全部动态值。

    collect_start 是采集起点（PoW 之前的毫秒时间戳），之后所有时间线以它为锚。
    rng 可注入以便测试复现。
    """
    rng = rng or random
    if collect_start is None:
        collect_start = int(time.time() * 1000)

    timings = _build_timings(pow_ms, rng)
    ctm = perf_ms(sum(timings.values()) + rng.uniform(150, 250), rng)

    # ts 在 tsnonce 那一步取，偏移量 = 该步及之前所有项耗时之和
    offset = 0.0
    for key, _, _ in TIMING_RANGES:
        offset += timings[key]
        if key == 'tsnonce':
            break
    ts = collect_start + _js_round(offset)

    used = rng.randint(4_500_000, 8_000_000)
    return {
        'ts': ts,
        'timings': timings,
        'ctm': ctm,
        'timeline': _build_timeline(ts, collect_start, ctm, rng),
        'connection': _build_connection(rng),
        'memory': {
            'limit': 4395630592,
            'used': used,
            'total': used + rng.randint(3_000_000, 7_000_000),
        },
    }
