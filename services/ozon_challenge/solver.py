"""
对外入口：挑战页 HTML -> 提交 /abt/result 所需的 token / fp / timings。

    页面解析 -> 工作量证明 -> 生成动态值 -> 组装并加密 fp

采集起点必须取在 PoW **之前**：之后的整条时间线都以它为锚，
PoW 的真实耗时也要落在 timings 里，两者对不上会被识破。
"""

import random
import time
from dataclasses import dataclass

from loguru import logger

from services.ozon_challenge.dynamic import build_dynamic
from services.ozon_challenge.fingerprint import build_fp
from services.ozon_challenge.page import parse_page
from services.ozon_challenge.profile import UaProfile, build_profile
from services.ozon_challenge.proof import solve_pow

__all__ = ["ChallengeResult", "solve_challenge", "is_js_challenge"]


@dataclass
class ChallengeResult:
    token: str
    fp: str
    browser_2: str
    timings: dict
    pow_ms: int
    difficulty_nonce: int

    def result_payload(self) -> dict:
        """POST https://www.ozon.ru/abt/result 的请求体"""
        return {
            "token": self.token,
            "fp": self.fp,
            "info": '{"cookie_enabled":"true"}',
            "error": "",
            "timings": self.timings,
        }


def is_js_challenge(html: str) -> bool:
    """区分 JS 挑战页与滑块验证码页——两者的解法完全不同"""
    return 'id="challenge" type="hidden" value' in html


def solve_challenge(html: str, page_url: str, profile: UaProfile | None = None,
                    rng: random.Random | None = None) -> ChallengeResult:
    """
    解出一次 403 JS challenge。

    profile 必须和实际发请求用的 UA / sec-ch-ua 完全一致，
    否则 browser_2 的 CRC32 对不上。
    """
    rng = rng or random
    profile = profile or build_profile(rng=rng)

    page = parse_page(html)
    if not page.challenge:
        raise ValueError("挑战页里没有 challenge 字段")
    if not page.template:
        raise ValueError("页面字节码里没找到 browser_2 模板（指令表可能已变）")
    if -1 in page.cols:
        missing = [i for i, c in enumerate(page.cols) if c == -1]
        logger.warning(f"[challenge] 有 {len(missing)} 个栈帧特征没匹配到（下标 {missing}），"
                       f"混淆脚本形状可能已变，fn_1 的调用栈会不准")

    # 采集起点：PoW 之前。之后所有时间线都以它为锚
    collect_start = int(time.time() * 1000)
    pow_result = solve_pow(page)
    logger.debug(f"[challenge] version={pow_result.version} pow={pow_result.pow_ms}ms "
                 f"pzc={pow_result.pzc} template={pow_result.template!r}")

    dyn = build_dynamic(pow_result.pow_ms, collect_start, rng=rng)
    params = build_fp(pow_result, profile, page_url, dyn, rng=rng)

    logger.debug(f"[challenge] browser_2={params['browser_2']} fp_len={len(params['fp'])}")
    return ChallengeResult(
        token=params["token"],
        fp=params["fp"],
        browser_2=params["browser_2"],
        timings=params["timings"],
        pow_ms=pow_result.pow_ms,
        difficulty_nonce=pow_result.pzc,
    )
