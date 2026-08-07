"""
Ozon challenge / captcha 共用的加密与序列化原语（纯 Python，无 Node 依赖）。

原站两条链路（403 JS challenge 与滑块 captcha）用的是同一套加密：
    md5 链派生 key -> fp JSON 与 token 逐字符 XOR
    -> CryptoJS OpenSSL KDF (EVP_BytesToKey + AES-256-CBC) -> 密文正中插标记

加密结果对输入字节完全敏感，所以 fp 的 JSON 必须和浏览器里
`JSON.stringify` 的输出**逐字节一致**——这正是 `js_json_dumps` 存在的原因。
"""

import base64
import hashlib
import json
import os
from decimal import Decimal

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

__all__ = [
    "js_number_to_string",
    "js_json_dumps",
    "md5_hex",
    "parse_challenge",
    "derive_kdf_key",
    "kdf_encrypt",
    "xor_with_token",
    "insert_marker",
]


# ============================================================
# ECMAScript Number::toString —— 与 JSON.stringify 的数字格式对齐
# ============================================================

def js_number_to_string(x: float | int) -> str:
    """
    按 ECMA-262 Number::toString 把数字转成字符串。

    不能直接用 Python 的 repr/json：两者在指数记法的**阈值**和**指数位数**上都不同，
        1e-5   JS "0.00001"        Python "1e-05"
        1e18   JS "1000000000000000000"  Python "1e+18"
        4.7e-8 JS "4.7e-8"         Python "4.7e-08"
    fp 里的 timings 恰好会落在这些边界上（perf_ms 可能产出 ~1e-7 量级的值）。
    """
    if isinstance(x, bool):  # bool 是 int 的子类，必须先挡掉
        raise TypeError("bool is not a number here")
    if isinstance(x, int):
        return str(x)

    if x != x:
        return "NaN"
    if x == float("inf"):
        return "Infinity"
    if x == float("-inf"):
        return "-Infinity"
    if x == 0:
        return "0"  # JS 里 -0 在 JSON.stringify 下也是 "0"

    sign = "-" if x < 0 else ""
    # repr 已是最短往返表示，Decimal 由它取出精确的有效数字与指数
    d = Decimal(repr(abs(x))).normalize()
    digits_tuple = d.as_tuple()
    s = "".join(str(i) for i in digits_tuple.digits)
    k = len(s)
    # value = 0.s * 10**n  （规范里的 n）
    n = k + digits_tuple.exponent

    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    # 指数记法：JS 不补零、正指数带 '+'
    e = n - 1
    mantissa = s[0] if k == 1 else s[0] + "." + s[1:]
    return f"{sign}{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"


def js_json_dumps(obj) -> str:
    """等价于 JSON.stringify(obj)（无缩进、无空格）。"""
    out: list[str] = []
    _write(obj, out)
    return "".join(out)


def _write(v, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, (int, float)):
        out.append(js_number_to_string(v))
    elif isinstance(v, str):
        # 转义规则与 JSON.stringify 一致：只转义 " \ 和控制字符，不转义非 ASCII
        out.append(json.dumps(v, ensure_ascii=False))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        first = True
        for k, item in v.items():
            if not first:
                out.append(",")
            first = False
            out.append(json.dumps(str(k), ensure_ascii=False))
            out.append(":")
            _write(item, out)
        out.append("}")
    else:
        raise TypeError(f"不支持的类型: {type(v)!r}")


# ============================================================
# challenge 解析与 key 派生
# ============================================================

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def parse_challenge(challenge: str) -> list[str]:
    """
    challenge -> [version, id, token]

    去掉前 3 个字符后 base64 解码。必须用 latin-1 解码以复刻 JS `atob()`
    的行为（atob 产出的是逐字节码位，不是 UTF-8 文本）。
    """
    return base64.b64decode(challenge[3:]).decode("latin-1").split(",")


def derive_kdf_key(challenge_data: list[str], random_key_md5: str) -> str:
    """
    复刻 JS getConfig() 的 key 派生：
        key = md5(md5(random_key_md5[:4]) + token)
        再按 challenge_id 的字符和 % 4 迭代 md5
    """
    key = md5_hex(md5_hex(random_key_md5[:4]) + challenge_data[2])
    md5_num = sum(ord(c) for c in challenge_data[1]) % 4
    for _ in range(md5_num):
        key = md5_hex(key)
    return key


# ============================================================
# CryptoJS OpenSSL KDF + AES-256-CBC
# ============================================================

def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
    """OpenSSL EVP_BytesToKey (MD5)，与 CryptoJs.kdf.OpenSSL.execute 一致"""
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len:key_len + iv_len]


def kdf_encrypt(text: str, key: str, key_length: int = 8, iv_length: int = 4,
                salt: bytes | None = None) -> str:
    """
    复刻 CryptoJS OpenSSL KDF 加密：
      - 随机 8 字节 salt（测试时可外部注入以便和 JS 逐字节比对）
      - EVP_BytesToKey 派生 key/iv
      - AES-256-CBC + PKCS7
      - 输出 OpenSSL 格式: base64("Salted__" + salt + ciphertext)

    key_length / iv_length 单位是 CryptoJS 的 word（4 字节）。
    """
    key_bytes = key_length * 4   # 8 words = 32 bytes = AES-256
    iv_bytes = iv_length * 4     # 4 words = 16 bytes

    if salt is None:
        salt = os.urandom(8)
    derived_key, iv = _evp_bytes_to_key(key.encode("utf-8"), salt, key_bytes, iv_bytes)

    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode()


def xor_with_token(text: str, token: str) -> str:
    """fp JSON 的每个码位与 token 循环异或（JS 侧是 charCodeAt/fromCharCode）"""
    ns = [ord(c) for c in token]
    return "".join(chr(ns[i % len(ns)] ^ ord(c)) for i, c in enumerate(text))


def insert_marker(cipher: str, marker: str) -> str:
    """在密文正中插入标记（random_key_md5 的前 4 位）"""
    mid = len(cipher) // 2
    return cipher[:mid] + marker + cipher[mid:]
