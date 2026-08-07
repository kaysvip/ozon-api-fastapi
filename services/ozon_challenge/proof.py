"""
工作量证明与 browser_2。

PoW：找出使 md5(pzs + n) 的二进制前 dis 位全为 0 的最小 n。
难度 dis 藏在 token 第 4 段（冒号分隔）的 base64 JSON 里。
"""

import hashlib
import json
import time
from dataclasses import dataclass

from services.ozon_challenge.page import ParsedPage, lenient_b64decode
from services.ozon_crypto import parse_challenge

__all__ = ["PowResult", "solve_pow", "crc32", "build_browser_2", "challenge_difficulty"]


@dataclass
class PowResult:
    challenge: str
    version: str
    id: str
    token: str
    template: str
    script_line: int
    cols: list[int]
    pzs: str
    pzc: int
    pow_ms: int


def challenge_difficulty(token: str) -> int:
    """token 第 4 段 base64 解出的 JSON 里的 pz 就是要求的前导 0 比特数"""
    return int(json.loads(lenient_b64decode(token.split(":")[3]).decode("latin-1"))["pz"])


def _leading_zero_bits_ok(digest: bytes, dis: int) -> bool:
    """digest 的前 dis 个比特是否全为 0"""
    if dis <= 0:
        return True
    whole, rem = divmod(dis, 8)
    if any(digest[:whole]):
        return False
    if rem and digest[whole] >> (8 - rem):
        return False
    return True


def find_nonce(pzs: str, dis: int) -> int:
    """
    等价于 JS 的 hash(str, dis)：从 0 开始试，返回第一个满足条件的 n。
    JS 逐比特拼字符串再 startsWith，这里直接按位判断，结果相同但快得多。
    """
    prefix = pzs.encode("utf-8")
    n = 0
    while True:
        if _leading_zero_bits_ok(hashlib.md5(prefix + str(n).encode("ascii")).digest(), dis):
            return n
        n += 1


def solve_pow(page: ParsedPage) -> PowResult:
    """解析结果 -> 完成工作量证明。单独一步，调用方才能拿到真实耗时去编时间线。"""
    if not page.challenge:
        raise ValueError("挑战页里没有 challenge")
    if not page.template:
        raise ValueError("页面字节码里没找到 browser_2 模板")

    challenge_data = parse_challenge(page.challenge)
    token = challenge_data[2]
    dis = challenge_difficulty(token)

    pzs = token[:20]
    begin = time.time()
    pzc = find_nonce(pzs, dis)
    pow_ms = int((time.time() - begin) * 1000)

    return PowResult(
        challenge=page.challenge,
        version=challenge_data[0],
        id=challenge_data[1],
        token=token,
        template=page.template,
        script_line=page.script_line,
        cols=page.cols,
        pzs=pzs,
        pzc=pzc,
        pow_ms=pow_ms,
    )


# ============================================================
# browser_2
# ============================================================

_CRC_TABLE: list[int] | None = None


def crc32(s: str) -> int:
    """
    与 JS 版逐字符 charCodeAt & 255 的实现对齐。
    不能直接用 zlib.crc32(s.encode())：非 ASCII 时取字节的方式不同。
    """
    global _CRC_TABLE
    if _CRC_TABLE is None:
        table = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
            table.append(c & 0xFFFFFFFF)
        _CRC_TABLE = table

    c = 0xFFFFFFFF
    for ch in s:
        c = (c >> 8) ^ _CRC_TABLE[(c ^ ord(ch)) & 0xFF]
    return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF


def build_browser_2(template: str, user_agent: str, challenge_version: str) -> str:
    """
    browser_2 = 浏览器名 + " v" + CRC32(user_agent + challenge版本号) 的三个指定字节。
    名字和字节下标都写在页面字节码的模板串里，服务端会逐字符校验，
    所以 user_agent 必须和请求头里的一字不差。
    """
    parts = [p for p in str(template).split("*") if p]
    idx = (parts[1] if len(parts) > 1 else "012")
    d = crc32(user_agent + challenge_version)
    octets = [(d >> 24) & 255, (d >> 16) & 255, (d >> 8) & 255, d & 255]
    return f"{parts[0]} v{octets[int(idx[0])]}.{octets[int(idx[1])]}.{octets[int(idx[2])]}"
