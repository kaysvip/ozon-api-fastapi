"""
Ozon 403 JS challenge 本地求解。

原本这一步是 POST 到外部 gin 服务（OZON_CHALLENGE_HOST）换 token/fp，
本包把整条链路搬到本地：解析挑战页字节码、跑工作量证明、编造自洽的
浏览器指纹与时间线，最后按原站算法加密。

    from services.ozon_challenge import solve_challenge, build_profile

    profile = build_profile()           # 随机但自洽的指纹档案
    result = solve_challenge(html, page_url, profile)
    session.post("https://www.ozon.ru/abt/result", json=result.result_payload())
"""

from services.ozon_challenge.profile import UaProfile, build_profile
from services.ozon_challenge.solver import ChallengeResult, is_js_challenge, solve_challenge

__all__ = [
    "UaProfile",
    "build_profile",
    "ChallengeResult",
    "solve_challenge",
    "is_js_challenge",
]
