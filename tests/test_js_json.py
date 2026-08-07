"""
数字序列化必须和浏览器的 JSON.stringify 完全一致。

fp 序列化后直接参与加密，差一个字符结果就废。而 Python 的 repr/json
在指数记法的阈值和指数位数上都和 JS 不同，所以有了 js_number_to_string。
"""

import json
import struct
import subprocess

import pytest

from services.ozon_crypto import js_json_dumps, js_number_to_string
from tests.conftest import REFERENCE_DIR, requires_node


def test_matches_golden_table(golden_numbers):
    """黄金表由 Node 的 JSON.stringify 产出，提交在仓库里，跑测试不需要 Node"""
    bad = []
    for row in golden_numbers:
        v = struct.unpack("<d", bytes.fromhex(row["hex"]))[0]
        got = js_number_to_string(v)
        if got != row["js"]:
            bad.append((row["hex"], row["js"], got))
    assert not bad, f"{len(bad)} 个不一致，前 5 个: {bad[:5]}"


@pytest.mark.parametrize("value,expected", [
    # Python repr 会写成 1e-05 / 1e+18 / 4.7e-08，JS 不是
    (1e-5, "0.00001"),
    (1e18, "1000000000000000000"),
    (4.76837158203125e-08, "4.76837158203125e-8"),
    (-1.9073486328125e-07, "-1.9073486328125e-7"),
    (1e21, "1e+21"),
    (1e-7, "1e-7"),
    # 整数值浮点在 JS 里没有小数点
    (1.0, "1"),
    (0.0, "0"),
    (-0.0, "0"),
    (100.0, "100"),
    (0.1, "0.1"),
])
def test_known_edge_cases(value, expected):
    assert js_number_to_string(value) == expected


def test_dumps_shape():
    obj = {"a": 1, "b": [1.0, 2.5, None, True, False], "c": "x\"y", "d": {"e": 0.0}}
    assert js_json_dumps(obj) == '{"a":1,"b":[1,2.5,null,true,false],"c":"x\\"y","d":{"e":0}}'


def test_non_ascii_not_escaped():
    """JSON.stringify 不转义非 ASCII，Python 的 ensure_ascii 默认会转"""
    assert js_json_dumps({"k": "Доступ"}) == '{"k":"Доступ"}'


@requires_node
def test_live_against_node(golden_numbers):
    """有 Node 时直接现场比一次，防止黄金表本身过期"""
    hexes = [r["hex"] for r in golden_numbers]
    script = ("const hs=JSON.parse(process.argv[1]);"
              "console.log(JSON.stringify(hs.map(h=>JSON.stringify("
              "Buffer.from(h,'hex').readDoubleLE(0)))));")
    out = subprocess.run(["node", "-e", script, json.dumps(hexes)],
                         cwd=REFERENCE_DIR, capture_output=True, text=True, check=True)
    live = json.loads(out.stdout)
    for row, js in zip(golden_numbers, live):
        v = struct.unpack("<d", bytes.fromhex(row["hex"]))[0]
        assert js_number_to_string(v) == js
