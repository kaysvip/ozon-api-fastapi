"""
Ozon 滑块验证码计算模块 (纯 Python，不依赖 Node.js)
  1. 解析 captcha_input -> 提取 captcha_info (含背景图 / 滑块图 URL)
  2. 识别滑块 x 偏移
  3. 生成鼠标轨迹 + 纯 Python 加密
  4. 返回提交到 /abt/captcha/result 所需的 token 和 fp
"""
from loguru import logger
import base64
import hashlib
import json
import os as _os
import random
import struct
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from services.ozon_captcha.slider_recognize import find_slider_offset, load_image_from_url


# ─────────────────── 工具函数 ───────────────────

def extract_image_urls(captcha_info: dict) -> tuple:
    CDN_BASE = "https://cdn2.ozone.ru/s3/abt-challenge/cpt/"

    bg_keys = ["is", "backgroundImage", "bg", "bgUrl", "background", "backImage", "back"]
    piece_keys = ["ps", "captchaImage", "piece", "pieceUrl", "puzzle", "slider", "front", "frontImage"]

    def _find_url(info, keys):
        for k in keys:
            if k in info:
                val = info[k]
                if isinstance(val, str):
                    if val.startswith("http"):
                        return val
                    else:
                        return CDN_BASE + val
        return None

    bg_url = _find_url(captcha_info, bg_keys)
    piece_url = _find_url(captcha_info, piece_keys)

    if not bg_url or not piece_url:
        urls_found = []
        for v in captcha_info.values():
            if isinstance(v, str) and (".png" in v or ".jpg" in v or ".webp" in v):
                if not v.startswith("http"):
                    v = CDN_BASE + v
                urls_found.append(v)
        if len(urls_found) >= 2 and not bg_url:
            bg_url = urls_found[0]
        if len(urls_found) >= 2 and not piece_url:
            piece_url = urls_found[1]

    return bg_url, piece_url


# ─────────────────── 轨迹数据生成 ───────────────────

def float64_to_base64(arr):
    buf = struct.pack(f'<{len(arr)}d', *arr)
    return base64.b64encode(buf).decode()


def cubic_bezier(t, cb0, cb1):
    u = 1.0 - t
    return 3.0 * u * u * t * cb0 + 3.0 * u * t * t * cb1 + t * t * t


def inverse_bezier(target_val, cb0, cb1, tol=1e-12):
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        val = cubic_bezier(mid, cb0, cb1)
        if abs(val - target_val) < tol:
            return mid
        if val < target_val:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def _snap_half(v):
    return round(v * 2) / 2


def generate_captcha_data(target_x, captcha_info):
    pp_config = captcha_info['pp']
    cb = captcha_info['cb']

    fixed_y  = int(pp_config[0])
    x_start  = float(pp_config[1])
    x_end    = float(pp_config[2])
    x_range  = x_end - x_start

    TRACK_WIDTH = 440.0

    bezier_target = (target_x - x_start) / x_range
    bezier_target = max(0.0, min(1.0, bezier_target))
    target_t  = inverse_bezier(bezier_target, cb[0], cb[1])
    target_dx = target_t * TRACK_WIDTH

    sp = target_t * 100

    anchor_x = _snap_half(random.uniform(700, 900))
    anchor_y = _snap_half(random.uniform(680, 720))

    pre_count = random.randint(5, 9)
    start_x = anchor_x + random.uniform(-80, 180)
    start_y = anchor_y + random.uniform(100, 350)

    mps_data = []
    for i in range(pre_count):
        prog = (i + 1) / pre_count
        ease = 1 - (1 - prog) ** 2
        mx = start_x + (anchor_x - start_x) * ease + random.gauss(0, 4)
        my = start_y + (anchor_y - start_y) * ease + random.gauss(0, 4)
        mps_data.extend([_snap_half(mx), _snap_half(my)])

    mps_data[-2] = _snap_half(anchor_x + random.uniform(-3, 3))
    mps_data[-1] = _snap_half(anchor_y + random.uniform(-3, 3))

    n_drag = random.randint(15, 30)

    base_ts = int(time.time() * 1000)
    timestamps = [base_ts]
    for _ in range(1, n_drag):
        timestamps.append(timestamps[-1] + random.randint(15, 28))

    pps_data = []
    for i in range(n_drag):
        t_frac = (i + 1) / n_drag

        if t_frac < 0.5:
            ease = 4.0 * t_frac * t_frac * t_frac
        else:
            ease = 1.0 - (-2.0 * t_frac + 2.0) ** 3 / 2.0

        noise = random.gauss(0, 1.2) if i < n_drag - 2 else 0.0
        current_dx = target_dx * ease + noise
        current_dx = max(0.0, min(TRACK_WIDTH, current_dx))
        current_t = current_dx / TRACK_WIDTH

        bval = cubic_bezier(current_t, cb[0], cb[1])
        slider_x = bval * x_range + x_start

        pps_data.extend([fixed_y, slider_x, timestamps[i]])

    final_bval = cubic_bezier(target_t, cb[0], cb[1])
    final_x = final_bval * x_range + x_start
    pps_data[-3] = fixed_y
    pps_data[-2] = final_x

    pps_b64 = float64_to_base64(pps_data)
    mps_b64 = float64_to_base64(mps_data)

    pp_result = [fixed_y, final_x]
    drag_duration = timestamps[-1] - timestamps[0]

    st = random.uniform(400, 1500)
    et = st + drag_duration + random.uniform(100, 600)

    return {
        'pp':  pp_result,
        'pps': pps_b64,
        'mps': mps_b64,
        'sp':  sp,
        'st':  st,
        'et':  et,
    }


# ─────────────────── 纯 Python 加密 ───────────────────

def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int) -> tuple:
    """OpenSSL EVP_BytesToKey (MD5), 与 CryptoJS.kdf.OpenSSL.execute 一致"""
    derived = b''
    block = b''
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len:key_len + iv_len]


def _kdf_encrypt(text: str, key: str, key_length: int = 8, iv_length: int = 4) -> str:
    """
    复刻 CryptoJS OpenSSL KDF 加密:
      - 随机 8 字节 salt
      - EVP_BytesToKey 派生 key/iv
      - AES-256-CBC + PKCS7 padding
      - 输出 OpenSSL 格式: base64("Salted__" + salt + ciphertext)
    """
    password = key.encode('utf-8')
    key_bytes = key_length * 4   # 8 words = 32 bytes = AES-256
    iv_bytes = iv_length * 4     # 4 words = 16 bytes

    salt = _os.urandom(8)
    derived_key, iv = _evp_bytes_to_key(password, salt, key_bytes, iv_bytes)

    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    plaintext = text.encode('utf-8')
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    openssl_data = b'Salted__' + salt + ciphertext
    return base64.b64encode(openssl_data).decode()


def _to_js_compat(obj):
    """
    递归转换 Python 值，使 json.dumps 输出与 JS JSON.stringify 完全一致。
    核心差异: Python json.dumps(1.0) -> "1.0", JS JSON.stringify(1.0) -> "1"
    """
    if isinstance(obj, float):
        if obj != obj:       # NaN
            return None
        if obj.is_integer():
            return int(obj)  # 1.0 -> 1, 让 json.dumps 输出 "1" 而非 "1.0"
        return obj
    if isinstance(obj, dict):
        return {k: _to_js_compat(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_js_compat(v) for v in obj]
    return obj


def get_params(captcha_input: str, user_agent: str, captcha_data: dict) -> dict:
    """
    纯 Python 实现, 等价于 ozon_result.js 的 get_params()。
    返回 {'fp': str, 'token': str}
    """
    # ── getConfig: 用 latin-1 解码以匹配 JS atob() 行为 ──
    decoded = base64.b64decode(captcha_input[3:]).decode('latin-1')
    challenge_data = decoded.split(',')

    random_key = str(random.random())
    random_key_md5 = _md5_hex(random_key)
    random_key_md5_1 = _md5_hex(random_key_md5[:4])
    key = _md5_hex(random_key_md5_1 + challenge_data[2])

    md5_num = sum(ord(c) for c in challenge_data[1]) % 4
    for _ in range(md5_num):
        key = _md5_hex(key)

    # ── 构建 fp JSON (key 顺序与 JS 对象字面量一致) ──
    fp_obj = {
        "captcha": {
            "id": challenge_data[1],
            "version": challenge_data[0],
        },
        "st": captcha_data['st'],
        "et": captcha_data['et'],
        "pp": captcha_data['pp'],
        "pps": captcha_data['pps'],
        "sp": captcha_data['sp'],
        "mps": captcha_data['mps'],
        "ua": user_agent,
    }

    # 转换浮点数格式以匹配 JS JSON.stringify
    fp_obj = _to_js_compat(fp_obj)
    fp_json = json.dumps(fp_obj, separators=(',', ':'), ensure_ascii=False)

    # ── XOR: fp_json 每个字符与 token 循环异或 ──
    fp_codes = [ord(c) for c in fp_json]
    ns_arr = [ord(c) for c in challenge_data[2]]
    encry_str = ''.join(chr(ns_arr[i % len(ns_arr)] ^ fp_codes[i]) for i in range(len(fp_codes)))

    # ── KDF 加密 ──
    fp_encrypted = _kdf_encrypt(encry_str, key)

    # ── 在密文中间插入 random_key_md5[:4] ──
    mid = len(fp_encrypted) // 2
    fp_final = fp_encrypted[:mid] + random_key_md5[:4] + fp_encrypted[mid:]

    return {'fp': fp_final, 'token': challenge_data[2]}


DEFAULT_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'


# ─────────────────── captcha_input -> token + fp ───────────────────

def build_captcha_result(captcha_input: str, user_agent: str = None):
    """
    解析 captcha_input，识别滑块位置，生成提交到 /abt/captcha/result 的 token 和 fp。
    """
    if user_agent is None:
        user_agent = DEFAULT_UA

    # 1. 解析 captcha_info
    logger.info("[1/4] 解析 captcha_info...")
    captcha_data_raw = base64.b64decode(captcha_input[3:]).decode('latin-1')
    info = captcha_data_raw.split(':')[-1]
    info += ('=' * (len(info) % 4))
    captcha_info = json.loads(base64.b64decode(info).decode())
    logger.info(f"      captcha_info 字段: {list(captcha_info.keys())}")

    # 2. 提取图片 URL 并识别滑块位置
    logger.info("[2/4] 识别滑块位置...")
    bg_url, piece_url = extract_image_urls(captcha_info)

    if not bg_url or not piece_url:
        raise ValueError("无法从 captcha_info 提取图片 URL")

    logger.info(f"      背景图: {bg_url}")
    logger.info(f"      滑块图: {piece_url}")

    bg_img = load_image_from_url(bg_url)
    piece_img = load_image_from_url(piece_url)

    pp = captcha_info.get("pp", None)
    best_x, best_y, candidates = find_slider_offset(bg_img, piece_img, pp=pp, top_k=5, debug=False)
    logger.info(f"      最佳偏移: x={best_x}, y={best_y}")

    # 3. 生成轨迹数据
    logger.info("[3/4] 生成轨迹数据...")
    captcha_data = generate_captcha_data(best_x, captcha_info)
    logger.info(f"      sp={captcha_data['sp']:.2f}, pp={captcha_data['pp']}")

    # 4. 纯 Python 加密
    logger.info("[4/4] 加密指纹...")
    result = get_params(captcha_input, user_agent, captcha_data)
    fp = result['fp']
    token = result['token']
    logger.info(f"      fp 长度: {len(fp)}")

    return {
        'token': token,
        'fp': fp,
        'slider_x': best_x,
        'slider_y': best_y,
    }
