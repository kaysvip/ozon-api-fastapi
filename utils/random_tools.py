import re

import requests
from pydantic import BaseModel, Field

# 指纹服务 API 地址
FINGERPRINT_HOST = "https://orz.a0bc.com"


class ClientHintsModel(BaseModel):
    model: str = Field(default="", alias="model")
    wow64: str = Field(default="", alias="wow64")
    mobile: str = Field(default="", alias="mobile")
    bitness: str = Field(default="", alias="bitness")
    platform: str = Field(default="", alias="platform")
    architecture: str = Field(default="", alias="architecture")
    uaFullVersion: str = Field(default="", alias="ua_full_version")
    platformVersion: str = Field(default="", alias="platform_version")


class WebgpuModel(BaseModel):
    webgpuSwitch: str = Field(default="1", alias="webgpu_switch")
    gpuAdapterinfoVendor: str = Field(default="", alias="gpu_adapterinfo_vendor")
    gpuAdapterinfoArchitecture: str = Field(default="", alias="gpu_adapterinfo_architecture")


class WebglConfigModel(BaseModel):
    unmaskedRenderer: str = Field(default="", alias="unmasked_renderer")
    unmaskedVendor: str = Field(default="", alias="unmasked_vendor")
    webgpu: WebgpuModel = Field(default_factory=WebgpuModel, alias="webgpu")
    system: str = Field(default="", alias="system")


class RandUserAgentModel(BaseModel):
    ua: str
    clientHints: ClientHintsModel = Field(..., alias="client_hints")
    dpr: str
    sysResolution: str = Field(..., alias="sys_resolution")
    sysDpr: str = Field(..., alias="sys_dpr")
    screenResolution: str = Field(..., alias="screen_resolution")
    kernelVersion: str = Field(..., alias="kernel_version")


class RandFingerprintModel(BaseModel):
    webglConfig: WebglConfigModel = Field(..., alias="webgl")
    macAddress: str = Field(default="", alias="mac_address")
    kernelVersion: str = Field(..., alias="kernel_version")
    deviceName: str = Field(..., alias="device_name")


def rand_get_user_agent(system_version="Windows", version="136", browser="chrome") -> RandUserAgentModel | None:
    """获取随机 User-Agent"""
    uri = FINGERPRINT_HOST + "/adspower/rand-get-user-agent"
    json_data = {
        "system_version": system_version,
        "version": version,
        "browser": browser,
        "system": "",
        "ua": ""
    }
    try:
        res = requests.post(uri, json=json_data, timeout=5)
        return RandUserAgentModel(**res.json())
    except Exception:
        return None


def random_fingerprint(ua: str, client_hints: str) -> RandFingerprintModel | None:
    """获取随机浏览器指纹（WebGL 等）"""
    uri = FINGERPRINT_HOST + "/adspower/random-fingerprint"
    json_data = {
        "ua": ua,
        "client_hints": client_hints,
        "fingerprint_list": "kernel_version,webgl,mac_address,device_name",
        "webgl_config": ""
    }
    try:
        res = requests.post(uri, json=json_data, timeout=5)
        return RandFingerprintModel(**res.json())
    except Exception:
        return None


# curl_cffi 实际支持的 impersonate 版本（按降序排列）
_SUPPORTED_IMPERSONATE = [142, 136, 131]


def extract_chrome_version(ua: str) -> str:
    """从 UA 字符串中提取 Chrome 主版本号，映射到 curl_cffi 支持的最近版本"""
    match = re.search(r'Chrome/(\d+)', ua)
    if match:
        ver = int(match.group(1))
        for supported in _SUPPORTED_IMPERSONATE:
            if ver >= supported:
                return f"chrome{supported}"
    return "chrome136"
