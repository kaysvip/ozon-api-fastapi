"""
指纹档案：一次挑战里所有「和这台机器有关」的值。

设计要点 —— 哪些能随机、哪些不能：

* 能随机：版本号、平台版本、CPU 架构、屏幕尺寸、WebGL 显卡、核心数、
  内存、语言。这些字段之间只要自洽，服务端无从分辨。
* 不能随机：**浏览器家族**。browser_2 的浏览器名取自页面字节码模板
  （实测是 "ChromiumEdge"），参考实现是按 Edge 验证通过的；换成 Chrome
  这个名字大概率要跟着变，而这一点离线无法验证。所以家族锁在 Edge/Windows。
* 无法随机：canvas / webgl 的 hash、fonts 位图、props。它们是真实渲染
  结果，没有浏览器算不出来，只能沿用底板（见 fp_base.json）。

user_agent 必须和请求头里的一字不差 —— browser_2 的 CRC32 就是拿它算的。
sec-ch-ua 也必须和 hev.brands 对得上，所以两者都由本模块统一产出。
"""

import random
import re
import threading
from dataclasses import dataclass, field

from loguru import logger

from utils.random_tools import extract_chrome_version, rand_get_user_agent, random_fingerprint

__all__ = ["UaProfile", "build_profile", "BASELINE_PROFILE", "ProfilePool", "get_profile"]

# 与 fp_base.json 完全对应的底板：真实 Edge 151 / Windows 抓包，已通过 /abt/result 校验。
# 指纹服务不可用时回退到它。
_BASELINE = dict(
    major=151,
    edge_full="151.0.4129.59",
    chromium_full="151.0.7922.72",
    platform_version="19.0.0",
    architecture="x86",
    bitness="64",
    viewport_width=1912,
    viewport_height=914,
    unmasked_vendor="Google Inc. (NVIDIA)",
    unmasked_renderer=("ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Ti SUPER (0x00002705) "
                       "Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    hardware_concurrency=24,
    device_memory=32,
)

# Chrome/Edge 的 GREASE 品牌串按版本变化，没有公开算法。
# 这里只用真实抓包见过的组合，避免自造出不存在的值。
_GREASE = [("Not=A?Brand", "99"), ("Not;A=Brand", "99"), ("Not_A Brand", "8"),
           ("Not)A;Brand", "8"), ("Not-A.Brand", "99")]

# 真实存在的独显 / 集显组合，用于指纹服务不可用时兜底
_GPUS = [
    ("Google Inc. (NVIDIA)",
     "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Ti SUPER (0x00002705) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)",
     "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)",
     "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER (0x000021C4) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)",
     "ANGLE (AMD, AMD Radeon RX 6600 (0x000073FF) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)",
     "ANGLE (Intel, Intel(R) UHD Graphics 770 (0x00004680) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)",
     "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
]

# 常见桌面分辨率（含 DPR 缩放后的逻辑分辨率）。
# 底板里 1920x1080 的机器对应视口 1912x914，即宽 -8、高 -166（浏览器 chrome + 任务栏），
# 这里沿用同一换算，避免造出不自洽的组合。
_SCREENS = [(1920, 1080), (2560, 1440), (1920, 1200), (1680, 1050),
            (1600, 900), (3840, 2160), (1440, 900), (1536, 864), (1366, 768)]
_VIEWPORT_INSET_W = 8
_VIEWPORT_INSET_H = 166

_WIN_PLATFORM_VERSIONS = ["19.0.0", "15.0.0", "10.0.0", "14.0.0", "13.0.0"]

_UA_TEMPLATE = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36 Edg/{major}.0.0.0")


@dataclass
class UaProfile:
    user_agent: str
    impersonate: str
    major: int
    edge_full: str
    chromium_full: str
    platform_version: str
    architecture: str
    bitness: str
    viewport_width: int
    viewport_height: int
    unmasked_vendor: str
    unmasked_renderer: str
    hardware_concurrency: int
    device_memory: int
    grease: tuple[str, str] = field(default=("Not=A?Brand", "99"))

    # ── 派生值 ──

    @property
    def brands(self) -> list[dict]:
        """hev.brands —— 顺序必须和 sec-ch-ua 头一致"""
        g, gv = self.grease
        return [
            {"brand": g, "version": gv},
            {"brand": "Microsoft Edge", "version": str(self.major)},
            {"brand": "Chromium", "version": str(self.major)},
        ]

    @property
    def full_version_list(self) -> list[dict]:
        g, gv = self.grease
        return [
            {"brand": g, "version": f"{gv}.0.0.0"},
            {"brand": "Microsoft Edge", "version": self.edge_full},
            {"brand": "Chromium", "version": self.chromium_full},
        ]

    @property
    def sec_ch_ua(self) -> str:
        return ", ".join(f'"{b["brand"]}";v="{b["version"]}"' for b in self.brands)

    @property
    def outer_width(self) -> int:
        """底板里 outerWidth = 视口宽 + 16（窗口边框）"""
        return self.viewport_width + 16

    @property
    def outer_height(self) -> int:
        """底板里 outerHeight = 视口高 + 88（标签栏 + 地址栏）"""
        return self.viewport_height + 88

    @property
    def app_version(self) -> str:
        """navigator.appVersion 就是 UA 去掉开头的 'Mozilla/'"""
        return self.user_agent[len("Mozilla/"):]

    def nav_headers(self) -> dict:
        """导航请求头里所有和指纹绑定的字段"""
        return {
            "user-agent": self.user_agent,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }


_BASELINE_UA = _UA_TEMPLATE.format(major=_BASELINE["major"])

BASELINE_PROFILE = UaProfile(
    user_agent=_BASELINE_UA,
    # impersonate 的版本映射统一走 utils.random_tools，避免两处维护支持列表
    impersonate=extract_chrome_version(_BASELINE_UA),
    **_BASELINE,
)


def _parse_two_ints(s: str) -> tuple[int, int] | None:
    nums = re.findall(r"\d+", s or "")
    if len(nums) >= 2:
        return int(nums[0]), int(nums[1])
    return None


def build_profile(rng: random.Random | None = None, use_remote: bool = True) -> UaProfile:
    """
    生成一份自洽的指纹档案。

    优先用 rand_get_user_agent / random_fingerprint 取真实分布的随机值；
    服务不可用时退回本地随机（仍然每次都不同），最差退回底板。
    """
    rng = rng or random

    major = None
    edge_full = chromium_full = None
    platform_version = architecture = bitness = None
    screen = None
    vendor = renderer = None

    if use_remote:
        ua_model = rand_get_user_agent(version="140,141,142,143,144")
        if ua_model:
            m = re.search(r"Chrome/(\d+)", ua_model.ua)
            if m:
                major = int(m.group(1))
            ch = ua_model.clientHints
            platform_version = ch.platformVersion or None
            architecture = ch.architecture or None
            bitness = ch.bitness or None
            if ch.uaFullVersion:
                chromium_full = ch.uaFullVersion
            screen = _parse_two_ints(ua_model.screenResolution) or \
                _parse_two_ints(ua_model.sysResolution)
            try:
                import json as _json
                hints_json = _json.dumps(ua_model.clientHints.model_dump(by_alias=True))
                fp_model = random_fingerprint(ua_model.ua, hints_json)
                if fp_model:
                    vendor = fp_model.webglConfig.unmaskedVendor or None
                    renderer = fp_model.webglConfig.unmaskedRenderer or None
            except Exception as exc:
                logger.debug(f"[profile] random_fingerprint 异常: {exc}")
        else:
            logger.debug("[profile] 指纹服务不可用, 使用本地随机")

    # ── 缺什么补什么，保证每一项都有值且彼此自洽 ──
    if major is None:
        major = rng.choice([140, 141, 142, 143, 144, 151])
    if chromium_full is None or not re.fullmatch(r"\d+(\.\d+){3}", chromium_full or ""):
        chromium_full = f"{major}.0.{rng.randint(6000, 7999)}.{rng.randint(30, 190)}"
    else:
        # 服务给的完整版本要和主版本对齐，否则 hev 内部自相矛盾
        chromium_full = re.sub(r"^\d+", str(major), chromium_full)
    edge_full = f"{major}.0.{rng.randint(3000, 4300)}.{rng.randint(30, 120)}"

    if platform_version is None:
        platform_version = rng.choice(_WIN_PLATFORM_VERSIONS)
    if architecture is None:
        architecture = "x86"
    if bitness is None:
        bitness = "64"
    if screen is None:
        screen = rng.choice(_SCREENS)
    if not vendor or not renderer:
        vendor, renderer = rng.choice(_GPUS)

    sw, sh = screen
    viewport_w = sw - _VIEWPORT_INSET_W
    viewport_h = sh - _VIEWPORT_INSET_H

    ua = _UA_TEMPLATE.format(major=major)

    return UaProfile(
        user_agent=ua,
        impersonate=extract_chrome_version(ua),
        major=major,
        edge_full=edge_full,
        chromium_full=chromium_full,
        platform_version=platform_version,
        architecture=architecture,
        bitness=bitness,
        viewport_width=viewport_w,
        viewport_height=viewport_h,
        unmasked_vendor=vendor,
        unmasked_renderer=renderer,
        hardware_concurrency=rng.choice([4, 6, 8, 12, 16, 20, 24, 32]),
        device_memory=rng.choice([4, 8, 8, 16, 16, 32]),
        grease=rng.choice(_GREASE),
    )


# ============================================================
# 档案池
# ============================================================

class ProfilePool:
    """
    一批预生成的指纹档案，每次请求随机取一份。

    为什么是池而不是每次现造：build_profile 会调远程指纹服务，
    每个请求都调一次既慢又是在给自己刷特征。池子既保证了多样性
    （不再是全进程共用一套 UA），又把远程调用摊薄到 pool_size 次。
    """

    def __init__(self, size: int = 8):
        self._size = max(1, size)
        self._profiles: list[UaProfile] = []
        self._lock = threading.Lock()

    def get(self, rng: random.Random | None = None) -> UaProfile:
        rng = rng or random
        if len(self._profiles) < self._size:
            with self._lock:
                if len(self._profiles) < self._size:
                    try:
                        self._profiles.append(build_profile(rng=rng))
                    except Exception as exc:
                        logger.warning(f"[profile] 生成档案失败, 回退到底板: {exc}")
                        self._profiles.append(BASELINE_PROFILE)
        return rng.choice(self._profiles)

    def reset(self) -> None:
        """丢弃现有档案（例如察觉到被大面积封锁时）"""
        with self._lock:
            self._profiles = []


_DEFAULT_POOL: ProfilePool | None = None
_DEFAULT_POOL_LOCK = threading.Lock()


def get_profile(pool_size: int = 8, rng: random.Random | None = None) -> UaProfile:
    """从进程级默认档案池里取一份档案"""
    global _DEFAULT_POOL
    if _DEFAULT_POOL is None:
        with _DEFAULT_POOL_LOCK:
            if _DEFAULT_POOL is None:
                _DEFAULT_POOL = ProfilePool(pool_size)
    return _DEFAULT_POOL.get(rng)
