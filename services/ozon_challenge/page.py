"""
挑战页解析：从下发的 HTML 里取出后续都要用到的东西。

难点在 browser_2 的模板串——它不在明文里，而是编在页面混淆脚本的
虚拟机字节码中。这里按指令流逐条前进取第一条含 '*' 的 LOADSTR，
而不是扫可打印字符，否则会误命中。
"""

import base64
import re
from dataclasses import dataclass, field

__all__ = ["ParsedPage", "parse_page", "extract_bytecode", "read_browser2_template",
           "lenient_b64decode"]


# fn_1 调用栈里的 5 个栈帧。脚本每次重新混淆，b[0x..] 的下标都会变，
# 所以把十六进制下标通配掉，靠代码形状定位。
FRAME_PATTERNS = [
    re.compile(r'try\{return window\[b\[0x[\da-f]+\]\]\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\[b\[0x[\da-f]+\]\]\}catch'),
    re.compile(r'e,f,l;g\(e=a\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\(\),f=a\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\(\)'),
    re.compile(r'var f;g\(this\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\[b\[0x[\da-f]+\]\]\(\[this\['),
    re.compile(r'0x[\da-f]+\]\+b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\(\),a\[b\[0x[\da-f]+\]\]\(d,function\(\)'),
    re.compile(r'\]\(\)\(\);if\(q!==void b\[0x[\da-f]+\]\)\{p=\[\]\[b\[0x[\da-f]+\]\]\(bA\(p\),bA\(q\)\)'),
]

# 字节码指令的操作数宽度，用来在指令流里正确前进。
# -1 表示变长，需要单独处理。
OPERAND_WIDTH = {
    2: 2, 3: 9, 4: 5, 10: 3, 11: -1, 12: 2, 14: -1, 15: 2, 16: 0,
    17: 5, 18: 4, 19: 5, 20: -1, 21: 3, 22: 9, 23: 1,
    50: 3, 51: 3, 52: 3, 53: 3, 54: 3, 55: 3, 56: 3, 57: 3,
    100: 3, 101: 3, 102: 3, 103: 3,
}

_B64_LITERAL = re.compile(r'"[A-Za-z0-9+/=]{800,}"')


@dataclass
class ParsedPage:
    challenge: str | None = None
    script_line: int = -1
    cols: list[int] = field(default_factory=list)
    template: str | None = None


def lenient_b64decode(b64: str) -> bytes:
    """
    复刻 Node `Buffer.from(b64, 'base64')` / 浏览器 `atob()` 的宽松解码：
    '=' 之后停止；末尾落单的 1 个字符直接丢弃。
    Python 的 b64decode 对补位更严格，不预处理会直接抛错。
    """
    s = b64.split("=")[0]
    r = len(s) % 4
    if r == 1:
        s = s[:-1]
    elif r:
        s += "=" * (4 - r)
    return base64.b64decode(s)


def extract_bytecode(script: str) -> list[int] | None:
    """页面脚本里最长的那个 base64 字面量就是虚拟机字节码"""
    lits = _B64_LITERAL.findall(script)
    if not lits:
        return None
    # 取最长；JS 侧是稳定降序排序后取首个，等价于取第一个最长的
    b64 = max((x[1:-1] for x in lits), key=len)
    # JS 侧解码后还有一步「码位 >255 就拆成两字节」，那是为浏览器 atob 写的；
    # 按字节解码时每个值天然 <=255，该分支不可达。
    return list(lenient_b64decode(b64))


class _Cursor:
    """
    模拟 JS 里越界读出 undefined 的行为：
    越界取字节得到 None，pc 一旦被 NaN 污染（None 参与算术）即视为终止。
    """

    __slots__ = ("bc", "pc", "dead")

    def __init__(self, bc: list[int]):
        self.bc = bc
        self.pc = 0
        self.dead = False

    def byte(self) -> int | None:
        if self.dead:
            return None
        v = self.bc[self.pc] if 0 <= self.pc < len(self.bc) else None
        self.pc += 1
        return v

    def peek(self) -> int | None:
        if self.dead:
            return None
        return self.bc[self.pc] if 0 <= self.pc < len(self.bc) else None

    def skip_var(self, fixed: int) -> None:
        """pc += fixed; pc += 1 + bc[pc]  —— bc[pc] 越界时 JS 会得到 NaN 并终止循环"""
        self.pc += fixed
        n = self.peek()
        if n is None:
            self.dead = True
            return
        self.pc += 1 + n


def read_browser2_template(script: str) -> str | None:
    """
    解析出 browser_2 的模板串，形如 "ChromiumEdge************312"。
    '*' 之前是浏览器名，之后的数字是取 CRC32 字节的下标。
    """
    bc = extract_bytecode(script)
    if not bc:
        return None

    cur = _Cursor(bc)

    def read_str() -> str:
        # 虚拟机原样写法是 (getByte() << 8) || getByte()，短路语义要照抄：
        # 高位非 0 时**不会**再读低位字节。
        hi = cur.byte()
        n = ((hi or 0) << 8) or cur.byte()
        if not n:
            return ""
        out = []
        for _ in range(n):
            b = cur.byte()
            out.append(chr(b) if b is not None else "\x00")
        return "".join(out)

    while not cur.dead and cur.pc < len(bc) and cur.pc < 4096:
        op = cur.byte()
        if op is None:
            break
        if op == 1:                      # LOADSTR
            cur.byte()                   # 目标寄存器
            s = read_str()
            if "*" in s:
                return s
            continue
        if op == 13:                     # FRAME
            cur.skip_var(5)
            continue
        if op == 5:                      # LOADARR
            cur.byte()
            cur.skip_var(0)
            continue
        w = OPERAND_WIDTH.get(op)
        if w is None:                    # 指令表变了，交给上层报错
            return None
        if w >= 0:
            cur.pc += w
            continue
        if op == 11:                     # CALL
            cur.skip_var(3)
        elif op == 14:                   # RET
            cur.byte()
            cur.skip_var(0)
        elif op == 20:                   # MKFUNC
            cur.skip_var(5)
        else:
            return None
    return None


_CHALLENGE_RE = re.compile(r'id="challenge" type="hidden" value="(.*?)"')


def parse_page(html: str) -> ParsedPage:
    """从挑战页 HTML 里取出 challenge、混淆脚本位置、browser_2 模板"""
    m = _CHALLENGE_RE.search(html)
    challenge = m.group(1) if m else None

    # 必须用 split('\n') 而非 splitlines()：后者会吃掉 '\r'，
    # 导致栈帧列号偏移，与浏览器实际报的列号对不上。
    lines = html.split("\n")
    line = -1
    script = ""
    for i, ln in enumerate(lines):
        if "<script>(function()" in ln:
            line = i + 1
            script = ln
            break

    cols = []
    for pat in FRAME_PATTERNS:
        mm = pat.search(script)
        cols.append(mm.start() + 1 if mm else -1)   # V8 的列号从 1 开始

    return ParsedPage(
        challenge=challenge,
        script_line=line,
        cols=cols,
        template=read_browser2_template(script) if script else None,
    )
