"""
构造差分测试用的合成挑战页与随机字节码流。

Node 参考实现和 Python 移植读同一份输入，输出必须逐字节一致。
"""

import base64
import json
import random

# 与 page.py 中 OPERAND_WIDTH 同源；这里只用定长指令来造流
FIXED_OPS = {
    2: 2, 3: 9, 4: 5, 10: 3, 12: 2, 15: 2, 16: 0,
    17: 5, 18: 4, 19: 5, 21: 3, 22: 9, 23: 1,
    50: 3, 51: 3, 52: 3, 53: 3, 54: 3, 55: 3, 56: 3, 57: 3,
    100: 3, 101: 3, 102: 3, 103: 3,
}
# 变长指令 -> 变长段之前的固定字节数
VAR_OPS = {13: 5, 5: 1, 11: 3, 14: 1, 20: 5}

FRAME_SNIPPETS = [
    'try{return window[b[0x1a]][b[0x2b]+b[0x3c]][b[0x4d]]}catch',
    'e,f,l;g(e=a[b[0x11]+b[0x22]](),f=a[b[0x33]+b[0x44]]()',
    'var f;g(this[b[0x55]+b[0x66]][b[0x77]]([this[',
    '0x88]+b[0x99]+b[0xaa]+b[0xbb]](),a[b[0xcc]](d,function()',
    ']()();if(q!==void b[0xdd]){p=[][b[0xee]](bA(p),bA(q))',
]

TEMPLATE = "ChromiumEdge************312"
PZ_BITS = 10          # 难度，控制 PoW 耗时


def _emit_fixed(r, out):
    op = r.choice(sorted(FIXED_OPS))
    out.append(op)
    out.extend(r.randrange(256) for _ in range(FIXED_OPS[op]))


def _emit_var(r, out):
    op = r.choice(sorted(VAR_OPS))
    out.append(op)
    out.extend(r.randrange(256) for _ in range(VAR_OPS[op]))
    n = r.randrange(0, 12)
    out.append(n)
    out.extend(r.randrange(256) for _ in range(n))


def _emit_loadstr(r, out, s):
    """LOADSTR: op=1, 目标寄存器, 长度 (hi<<8)||lo —— 短串走 hi=0 分支"""
    out.append(1)
    out.append(r.randrange(256))
    out.append(0)
    out.append(len(s))
    out.extend(ord(c) for c in s)


def build_bytecode(r: random.Random, template: str | None, n_prefix: int = 12) -> list[int]:
    out: list[int] = []
    for _ in range(n_prefix):
        (_emit_var if r.random() < 0.4 else _emit_fixed)(r, out)
        if r.random() < 0.25:
            _emit_loadstr(r, out, "".join(r.choice("abcdefghij")
                                          for _ in range(r.randrange(1, 20))))
    if template is not None:
        _emit_loadstr(r, out, template)
    # 补足长度，让 base64 字面量超过 800 字符（extract_bytecode 的门槛）
    while len(out) < 700:
        _emit_fixed(r, out)
    return out


def wrap_script(bytecode: list[int], with_frames: bool = True) -> str:
    b64 = base64.b64encode(bytes(bytecode)).decode()
    body = "<script>(function(){var b=[];"
    if with_frames:
        for i, f in enumerate(FRAME_SNIPPETS):
            body += f"/*f{i}*/{f};"
    body += f'var z="{b64}";'
    return body + "})()</script>"


def make_challenge(pz_bits: int = PZ_BITS) -> tuple[str, str]:
    """返回 (challenge 串, token)"""
    pz_part = base64.b64encode(json.dumps({"pz": pz_bits}).encode()).decode()
    token = f"abcdef0123:9876543210:zzz:{pz_part}:tail"
    plain = f"3,challenge-id-42,{token}"
    return "xyz" + base64.b64encode(plain.encode("latin-1")).decode(), token


def build_page(seed: int = 20260807) -> dict:
    """合成一张 JS 挑战页。用 \\r\\n 换行，专门压一压列号计算。"""
    r = random.Random(seed)
    challenge, token = make_challenge()
    script = wrap_script(build_bytecode(r, TEMPLATE))
    html = (
        "<!doctype html>\r\n"
        "<html><head><title>x</title></head>\r\n"
        "<body>\r\n"
        f'<input id="challenge" type="hidden" value="{challenge}">\r\n'
        f"{script}\r\n"
        "</body></html>\r\n"
    )
    return {"html": html, "challenge": challenge, "token": token, "template": TEMPLATE}


def build_bytecode_cases(count: int = 300) -> list[dict]:
    """一批随机字节码流，专测 VM 指令流走位（含无模板的用例）"""
    cases = []
    for i in range(count):
        r = random.Random(50000 + i)
        tmpl = None if i % 3 == 0 else (
            f"Br{i % 7}Name{'*' * (1 + i % 14)}"
            f"{r.randrange(3)}{r.randrange(3)}{r.randrange(3)}"
        )
        bc = build_bytecode(r, tmpl, n_prefix=r.randrange(0, 30))
        cases.append({"script": wrap_script(bc, with_frames=False),
                      "has_template": tmpl is not None})
    return cases
