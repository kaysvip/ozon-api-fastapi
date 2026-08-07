# 测试

```bash
uv sync --group dev
uv run pytest
```

## 差分测试

`test_challenge_port.py` 把 Python 移植和原站算法的 JS 参考实现
（`reference/ozon_result.js`）喂同一份输入，比对**逐字节**产物：
挑战页解析、字节码走位、工作量证明、CRC32/browser_2、直到最终 fp 密文。

这条链路对输入字节完全敏感，改动后不跑这个测试很难发现问题，
所以任何改到 `services/ozon_challenge/` 或 `services/ozon_crypto.py`
的地方都应该重跑一遍。

跑参考实现需要 Node 和 crypto-js：

```bash
cd tests/reference && npm install
```

没装的话相关用例会自动 skip，纯 Python 的不变量测试仍然会跑。

## 数字序列化

`data/js_numbers.json` 是由 Node 的 `JSON.stringify` 产出的黄金表，
提交在仓库里，所以 `test_js_json.py` 不需要 Node 也能跑。
装了 Node 时会额外现场比一次，防止黄金表过期。
