"""
指纹档案的自洽性。

随机化只有在**内部一致**时才有意义：UA 说自己是 Edge 143，
sec-ch-ua 和 hev.brands 就必须也是 143，否则比固定一套指纹更容易被识破。
"""

import random

import pytest

from services.ozon_challenge.fingerprint import apply_profile, load_fp_base
from services.ozon_challenge.profile import BASELINE_PROFILE, ProfilePool, build_profile
from services.ozon_client import OzonClient


@pytest.fixture(scope="module")
def profiles():
    rng = random.Random(2026)
    # use_remote=False：不打外部指纹服务，测试必须离线可跑
    return [build_profile(rng=rng, use_remote=False) for _ in range(200)]


def test_ua_matches_brands_and_headers(profiles):
    for p in profiles:
        assert f"Chrome/{p.major}.0.0.0" in p.user_agent
        assert f"Edg/{p.major}.0.0.0" in p.user_agent
        assert p.app_version == p.user_agent[len("Mozilla/"):]

        # sec-ch-ua 头必须逐项对应 hev.brands
        assert len(p.brands) == 3
        for b in p.brands:
            assert f'"{b["brand"]}";v="{b["version"]}"' in p.sec_ch_ua
        assert p.brands[1] == {"brand": "Microsoft Edge", "version": str(p.major)}
        assert p.brands[2] == {"brand": "Chromium", "version": str(p.major)}

        # 完整版本号也要和主版本对齐
        assert p.edge_full.startswith(f"{p.major}.")
        assert p.chromium_full.startswith(f"{p.major}.")
        assert p.full_version_list[1]["version"] == p.edge_full
        assert p.full_version_list[2]["version"] == p.chromium_full


def test_screen_geometry_consistent(profiles):
    for p in profiles:
        assert p.outer_width == p.viewport_width + 16
        assert p.outer_height == p.viewport_height + 88
        assert p.viewport_width > 0 and p.viewport_height > 0


def test_impersonate_is_supported_by_curl_cffi(profiles):
    """impersonate 目标必须是 curl_cffi 真支持的，否则建 Session 就会抛"""
    import typing

    from curl_cffi.requests.impersonate import BrowserTypeLiteral

    supported = set(typing.get_args(BrowserTypeLiteral))
    for p in profiles:
        assert p.impersonate in supported, f"{p.impersonate} 不被当前 curl_cffi 支持"


def test_profiles_are_diverse(profiles):
    """核心诉求：不能全进程共用一套指纹"""
    assert len({p.unmasked_renderer for p in profiles}) > 1
    assert len({(p.viewport_width, p.viewport_height) for p in profiles}) > 1
    assert len({p.major for p in profiles}) > 1
    # hev 里的完整版本号带随机 build 号，几乎每份档案都不同
    assert len({(p.edge_full, p.chromium_full) for p in profiles}) > len(profiles) // 2


def test_profile_lands_in_fp(profiles):
    p = profiles[0]
    fp = load_fp_base()
    apply_profile(fp, p)

    assert fp["user_agent"] == p.user_agent
    assert fp["navigator"]["@proto:Navigator"]["@get:userAgent"] == p.user_agent
    assert fp["navigator"]["@proto:Navigator"]["@get:appVersion"] == p.app_version
    assert fp["hev"]["brands"] == p.brands
    assert fp["hev"]["uaFullVersion"] == p.edge_full
    assert fp["webgl"]["unmasked_renderer"] == p.unmasked_renderer
    assert fp["screen_1"]["@proto:Screen"]["@get:width"] == p.viewport_width
    assert fp["screen_2"]["toWidth"] == p.outer_width
    assert fp["screen_3"]["@val:wv"]["@proto:VisualViewport"]["@get:height"] == p.viewport_height


def test_apply_profile_rejects_unknown_keys():
    """底板结构变了要立刻炸，而不是悄悄多塞字段"""
    fp = load_fp_base()
    del fp["hev"]["brands"]
    with pytest.raises(KeyError):
        apply_profile(fp, BASELINE_PROFILE)


def test_client_headers_follow_profile(profiles):
    p = profiles[1]
    c = OzonClient(profile=p)
    for headers in (c._ozon_headers, c._seller_headers):
        assert headers["user-agent"] == p.user_agent
        assert headers["sec-ch-ua"] == p.sec_ch_ua
    # 业务头不能被指纹覆盖掉
    assert c._ozon_headers["x-o3-app-name"] == "dweb_client"
    assert c._seller_headers["x-o3-app-name"] == "seller-ui"


def test_pool_reuses_profiles():
    pool = ProfilePool(size=3)
    rng = random.Random(7)
    got = [pool.get(rng) for _ in range(40)]
    assert len({id(g) for g in got}) <= 3
