# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Ozon（俄罗斯电商）数据采集 FastAPI 后端。核心难点不是业务逻辑，而是**绕过 Ozon 的反爬**：TLS 指纹伪装（curl_cffi impersonate）、403 JS challenge 本地求解（含工作量证明与浏览器指纹伪造）、滑块验证码识别与轨迹加密。

## 常用命令

依赖用 `uv` 管理（`uv.lock` 已提交，Python >= 3.12）。`requirements.txt` 是 UTF-16 编码的导出快照，不是依赖来源——改依赖请改 `pyproject.toml`。

```bash
uv sync                          # 安装/同步依赖
uv run python main.py            # 启动服务（默认 0.0.0.0:62002，reload 开启）

uv sync --group dev              # 装测试依赖
uv run pytest                    # 跑全部测试
uv run pytest tests/test_challenge_port.py -v    # 只跑差分测试
cd tests/reference && npm install               # 差分测试需要的 Node 侧依赖
```

- Swagger: `http://localhost:62002/Ozon-docs`，ReDoc: `/Ozon-redoc`
- 无 lint/format 配置。

## 配置

`app/config.py` 用 pydantic-settings，**env 前缀为 `OZON_`**：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `OZON_PORT` | 62002 | 服务端口 |
| `OZON_LOCAL_CHALLENGE` | true | 本地求解 403 JS challenge |
| `OZON_CHALLENGE_REMOTE_FALLBACK` | true | 本地失败时回退到外部服务 |
| `OZON_CHALLENGE_HOST` | `https://ozon-crawl-gin.a0bc.com` | 回退用的外部 gin 服务 |
| `OZON_PROFILE_POOL_SIZE` | 8 | 指纹档案池大小 |

另有一个硬编码在 `utils/random_tools.py` 的指纹服务 `FINGERPRINT_HOST = https://orz.a0bc.com`（AdsPower 风格的随机 UA / WebGL 指纹）。它不可用时 `build_profile` 会退到本地随机，不影响功能。

## 架构

请求链路：`main.py` → `app/__init__.py:creat_app()`（注意拼写是 `creat_app`）→ `app/view/ozon_view.py` 的 `ozon_router`（prefix `/api/v1`）。

`creat_app()` 在**函数内**导入路由：`app.view` → `services.ozon_client` → `app.config` 会绕回 `app/__init__.py`，放到模块顶层会形成循环导入。

- **`app/view/ozon_view.py`** — 所有路由。每个 handler 都是同一个模式：构造 `OzonClient(req.cookies, req.proxy)` → 调一个方法 → 结果为空则回 `ApiResponse(code=500, message=..client.last_error)`。**HTTP 状态码永远是 200**，错误通过 body 里的 `code` 字段表达。
- **`services/ozon_client.py`** — 反爬核心，见下。
- **`services/ozon_challenge/`** — 403 JS challenge 本地求解，见下。
- **`services/ozon_captcha/`** — 滑块验证码，见下。
- **`services/ozon_crypto.py`** — 两条关卡链路共用的加密与序列化原语。
- **`app/schemas/ozon_schemas.py`** — 所有请求/响应模型。数据类接口统一带 `cookies: str`（分号分隔的原始 cookie 串）和 `proxy: str`（`host:port`，内部拼成 `socks5://`）。

### 反爬机制（`services/ozon_client.py`）

1. **指纹档案池** — 每个 `OzonClient` 从进程级 `ProfilePool` 取一份 `UaProfile`（默认 8 份）。请求头的 `user-agent` / `sec-ch-ua` 由档案改写，且**必须和 fp 里的值完全一致**：`browser_2` 的 CRC32 是拿 user-agent 算的，`hev.brands` 又要和 `sec-ch-ua` 逐项对上。
2. **impersonate 映射** — UA 里的 Chrome 版本经 `utils/random_tools.py:extract_chrome_version()` 向下映射到 curl_cffi 支持的版本（`_SUPPORTED_IMPERSONATE = [142, 136, 131]`）。**升级 curl_cffi 后要同步更新这个列表**；`tests/test_profile.py` 里有一条测试会校验映射结果确实被当前 curl_cffi 支持。
3. **403 关卡分流** — `_handle_challenge()` 按页面内容分三种情况：JS 挑战页走本地求解（失败可回退外部服务）提交 `/abt/result`；滑块页走本地滑块求解提交 `/abt/captcha/result`；都不是就是直接封禁页，放弃。
4. **封锁重置** — `_is_access_blocked()` 检测俄文 `Доступ ограничен`（但先排除 challenge/captcha 页面）。命中后 `_reset_session()` 重建 Session 并预热首页。

每个数据方法都重复同一套 retry 骨架（3 次，`get_shop_page` 是 5 次）：非 200/403 → 记 `last_error` 重试；blocked → reset 重试；challenge → 处理后重试。HTML 类接口（`search` / `get_shop_page`）额外处理 `location.replace(...)` 跳转。**新增数据接口时照抄这套骨架**，不要只写 happy path。

`get_seller_data` 是例外：打的是 `seller.ozon.ru` 后台 API，用 `_SELLER_HEADERS`，需要 `x-o3-company-id`，且 cookie 走 header 字符串而非 session cookie jar。

### 403 JS challenge（`services/ozon_challenge/`）

入口 `solve_challenge(html, page_url, profile)`，四步：

1. **`page.py`** — 从挑战页取出 challenge 串、混淆脚本行号、5 个栈帧的列号，以及 `browser_2` 模板。模板不在明文里，编在页面**虚拟机字节码**中（脚本里最长的 base64 字面量），要按 `OPERAND_WIDTH` 指令表逐条走指令流才能取到。
2. **`proof.py`** — 工作量证明：找出使 `md5(token[:20] + n)` 二进制前 `dis` 位全 0 的最小 n，`dis` 藏在 token 第 4 段的 base64 JSON 里。另有 CRC32 与 `browser_2` 组装。
3. **`dynamic.py`** — 编一整套自洽的时间线：28 项采集耗时（顺序即采集顺序，不能调）、导航时间线、量化后的网络质量与内存。`performance.now()` 按 0.1ms 量化并带 `4.768e-8` 量级的浮点残差。
4. **`fingerprint.py`** — 静态底板 `fp_base.json`（真实 Edge 151/Windows 抓包）+ 档案 + 动态值，按 `FP_KEY_ORDER` 定序，XOR 后走 CryptoJS OpenSSL KDF 加密。

改这块的三个陷阱：

- **序列化必须逐字节等于 `JSON.stringify`。** Python 的 `repr`/`json` 和 JS 在指数记法的阈值与指数位数上都不同（`1e-5` → JS `0.00001`、Python `1e-05`；`4.7e-8` → JS `4.7e-8`、Python `4.7e-08`），而 timings 恰好会产出这种极小值。所以一律用 `services/ozon_crypto.py:js_json_dumps()`，不要用 `json.dumps`。
- **`FP_KEY_ORDER` 的顺序不能动**，序列化结果直接参与加密。
- **浏览器家族锁在 Edge。** `browser_2` 的浏览器名取自页面字节码模板（实测 `"ChromiumEdge"`），参考实现是按 Edge 验证通过的；换成 Chrome 这个名字大概率要跟着变，而这一点离线无法验证。`profile.py` 里只随机化版本、平台版本、屏幕、显卡、核心数、内存等**能保证自洽**的维度。
- `canvas.hash` / `webgl.hash` / `fonts` / `props` 是真实渲染结果，没有浏览器算不出来，只能沿用底板——这几项在所有档案间是相同的。

### 滑块验证码（`services/ozon_captcha/`）

`build_captcha_result(captcha_input, user_agent)` 四步：解析 `captcha_info`（`captcha_input[3:]` base64，**用 latin-1 解码以匹配 JS `atob()`**）→ `slider_recognize.find_slider_offset()` 用 OpenCV 模板匹配求 x 偏移（滑块图按 alpha 裁剪，匹配结果要**减去 crop_x**）→ 生成拟人轨迹（贝塞尔反解 + 高斯噪声，打包成 float64 小端 base64）→ 加密。

加密与 challenge 共用 `services/ozon_crypto.py`。

## 测试

`tests/test_challenge_port.py` 把 Python 移植和原站算法的 JS 参考实现（`tests/reference/ozon_result.js`）喂同一份输入，比对逐字节产物，一路到最终 fp 密文。**改动 `services/ozon_challenge/` 或 `services/ozon_crypto.py` 后必须重跑**，否则很难发现问题。没装 Node/crypto-js 时这些用例会 skip，纯 Python 的不变量测试仍会跑。

`test_baseline_profile_is_identity_on_fp_base` 是一条关键不变量：底板档案套用到 `fp_base.json` 必须是恒等变换——它守住了「档案改写的字段」和「底板实际结构」不会悄悄错位。

## 约定

- 注释和日志用中文。
- 日志混用两套：`services/ozon_client.py` 用标准库 `logging`，其余用 `loguru`。
- `services/` 和 `utils/` 是顶层包，不在 `app/` 下——导入写 `from services.ozon_client import ...`，运行时的 cwd 必须是项目根。
