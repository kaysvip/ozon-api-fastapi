# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Ozon（俄罗斯电商）数据采集 FastAPI 后端。核心难点不是业务逻辑，而是**绕过 Ozon 的反爬**：TLS 指纹伪装（curl_cffi impersonate）、403 challenge 自动求解、滑块验证码识别与轨迹加密。

## 常用命令

依赖用 `uv` 管理（`uv.lock` 已提交，Python >= 3.12）。`requirements.txt` 是 UTF-16 编码的导出快照，不是依赖来源——改依赖请改 `pyproject.toml`。

```bash
uv sync                          # 安装/同步依赖
uv run python main.py            # 启动服务（默认 127.0.0.1:62002，reload 开启）
```

- Swagger: `http://localhost:62002/Ozon-docs`，ReDoc: `/Ozon-redoc`
- 无测试套件、无 lint/format 配置。验证改动的常规做法是启服务后打 Swagger，或 `uv run python -c "from main import app"` 确认能导入。

## 配置

`app/config.py` 用 pydantic-settings，**env 前缀为 `OZON_`**：

- `OZON_PORT`（默认 62002）
- `OZON_CHALLENGE_HOST` — 外部 gin 服务，负责把 challenge 串换成 token/fp（默认 `https://ozon-crawl-gin.a0bc.com`）

另有一个硬编码在 `utils/random_tools.py` 的指纹服务 `FINGERPRINT_HOST = https://orz.a0bc.com`（AdsPower 风格的随机 UA / WebGL 指纹）。两个外部服务都不可用时，客户端会退化到内置默认 UA 并且 403 无法自解。

## 架构

请求链路：`main.py` → `app/__init__.py:creat_app()`（注意拼写是 `creat_app`）→ `app/view/ozon_view.py` 的 `ozon_router`（prefix `/api/v1`）。

三层结构，职责边界清晰：

- **`app/view/ozon_view.py`** — 所有路由。每个 handler 都是同一个模式：构造 `OzonClient(req.cookies, req.proxy)` → 调一个方法 → 结果为空则回 `ApiResponse(code=500, message=..client.last_error)`。**HTTP 状态码永远是 200**，错误通过 body 里的 `code` 字段表达。
- **`services/ozon_client.py`** — 反爬核心，见下。
- **`services/ozon_captcha/`** — 滑块验证码，见下。
- **`app/schemas/ozon_schemas.py`** — 所有请求/响应模型。数据类接口统一带 `cookies: str`（分号分隔的原始 cookie 串）和 `proxy: str`（`host:port`，内部拼成 `socks5://`）。

### 反爬机制（`services/ozon_client.py`）

理解这个文件是理解整个项目的关键。四个互相咬合的机制：

1. **指纹缓存** — `_generate_fingerprint_config()` 是**进程级单例**（模块全局 + 双检锁）。首次调用去 `orz.a0bc.com` 取随机 UA + WebGL vendor/renderer，之后所有 `OzonClient` 实例共享同一套指纹和 headers。改成 per-request 随机会破坏这个设计意图。
2. **impersonate 映射** — UA 里的 Chrome 版本（如 143）经 `extract_chrome_version()` 向下映射到 curl_cffi 实际支持的版本（`_SUPPORTED_IMPERSONATE = [142, 136, 131]`）。**升级 curl_cffi 后要同步更新这个列表**，否则会一直退到旧版本指纹。
3. **403 challenge 自愈** — `_handle_challenge()` 从 403 页面正则提取 `id="challenge"` 或 `id="captcha-input"` 的 hidden value，送到 `OZON_CHALLENGE_HOST` 换回 token/fp，POST 到 `https://www.ozon.ru/abt/result`，把返回的 cookie 并入自身 cookie 池。返回 `True` 表示"已处理，调用方应重试"。
4. **封锁重置** — `_is_access_blocked()` 检测俄文 `Доступ ограничен`（但先排除 challenge/captcha 页面，那两种不算封锁）。命中后 `_reset_session()` 重建 curl_cffi Session 并预热首页。

每个数据方法都重复同一套 retry 骨架（3 次，`get_shop_page` 是 5 次）：非 200/403 → 记 `last_error` 重试；blocked → reset 重试；challenge → 处理后重试；否则返回。HTML 类接口（`search` / `get_shop_page`）额外处理 `location.replace(...)` 跳转。**新增数据接口时照抄这套骨架**，不要只写 happy path。

`get_seller_data` 是例外：打的是 `seller.ozon.ru` 后台 API，用 `_SELLER_HEADERS`，需要 `x-o3-company-id`，且 cookie 走 header 字符串而非 session cookie jar。

### 滑块验证码（`services/ozon_captcha/`）

`build_captcha_result(captcha_input, user_agent)` 是唯一入口，四步：

1. `captcha_input[3:]` base64 解码（**用 latin-1 解码以匹配 JS `atob()` 行为**），取 `:` 后段再 base64 解出 `captcha_info` JSON。
2. `slider_recognize.find_slider_offset()` — OpenCV 模板匹配求 x 偏移（y 固定为 `pp[0]`）。滑块图按 alpha 通道裁剪，匹配结果要**减去 crop_x** 才是元素定位坐标。
3. `generate_captcha_data()` — 生成拟人鼠标轨迹：贝塞尔曲线（`captcha_info['cb']`）反解目标 t，加高斯噪声、随机时间戳间隔，坐标 snap 到 0.5 倍数，打包成 float64 小端 base64（`pps` 拖拽轨迹 / `mps` 前置移动）。
4. `get_params()` — **纯 Python 复刻原站 JS 加密**：随机数 → MD5 链派生 key（迭代次数由 challenge id 字符和决定）→ fp JSON 与 token 逐字符循环 XOR → CryptoJS OpenSSL KDF（EVP_BytesToKey + AES-256-CBC）→ 密文正中插入 `random_key_md5[:4]`。

改这块时的两个陷阱：`_to_js_compat()` 存在是因为 Python `json.dumps(1.0)` 出 `"1.0"` 而 JS 出 `"1"`，差一个字符加密结果就废；`fp_obj` 的 **key 顺序必须与原站 JS 对象字面量一致**，因为序列化后直接参与加密。

## 约定

- 注释和日志用中文。
- 日志混用两套：`services/ozon_client.py` 用标准库 `logging`，其余用 `loguru`。
- `services/` 和 `utils/` 是顶层包，不在 `app/` 下——导入写 `from services.ozon_client import ...`，运行时的 cwd 必须是项目根。
