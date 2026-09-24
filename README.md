# MiMo Relay — MiMo Desktop 订阅 → 本地 OpenAI / Anthropic 双协议中继

把本机已登录的 **Xiaomi MiMo Desktop** 订阅额度,转成标准 OpenAI 与 Anthropic API,供 Claude Code、Cursor、各类脚本直接调用。**零配置**:凭据从 MiMo Desktop 本地数据目录自动提取(DPAPI 链),无需手工导出 cookie。

## 要求

- Windows 10/11,已安装并**登录** MiMo Desktop
- Node.js ≥ 22.5(内置 `node:sqlite`,实测 v24 可用)

## 快速开始

```
node mimo-relay.cjs
```

首次运行:**先完全退出一次 MiMo Desktop**(右下角托盘图标 → 退出)。原因:App 运行期间其 Cookies 数据库为独占锁,无法读取;退出后 relay 完成一次凭据提取,并立即用 DPAPI(仅当前 Windows 用户可解)加密缓存到 `%APPDATA%\mimo-relay\creds.dat`——**之后 App 开不开都无所谓**,启动直接走缓存。

验证:

```
curl http://127.0.0.1:8317/health
# {"ok":true,"credentialSource":"auto-dpapi"|"cache"|"file",...}
```

## 客户端配置

| 客户端 | 配置 |
|---|---|
| OpenAI 兼容工具 | `base_url=http://127.0.0.1:8317/v1`,`api_key` 任意非空 |
| Claude Code | `ANTHROPIC_BASE_URL=http://127.0.0.1:8317`,`ANTHROPIC_AUTH_TOKEN` 任意非空 |
| Codex CLI(新版,已移除 `wire_api="chat"`) | `~/.codex/config.toml` 加 provider:见下 |

Codex 配置示例(`wire_api` 必须为 `responses`,relay 已实现该转换):

```toml
model = "mimo-pro"
model_provider = "mimo"

[model_providers.mimo]
name = "MiMo"
base_url = "http://127.0.0.1:8317/v1"
wire_api = "responses"
env_key = "MIMO_API_KEY"   # 任意非空值,如 set MIMO_API_KEY=mimo
```

模型名填 `mimo-pro`(默认,推理主力)或 `mimo-flash`(快速版);云端实际执行为 mimo-v2.6-pro / mimo-v2.6-flash。填其他名字不会报错,自动回落到 `mimo-pro`。

## 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/models` | 模型列表(别名) |
| POST | `/v1/chat/completions` | OpenAI 聊天,流式/非流式,tools 透传 |
| POST | `/v1/responses` | OpenAI Responses API(Codex 新版),流式/非流式,function_call 完整支持 |
| POST | `/v1/images/generations` | OpenAI 图像 API(Doubao-Seedream-5.0-pro 文生图) |
| POST | `/v1/messages` | Anthropic Messages,流式 SSE/非流式,完整 tool_use 支持 |
| POST | `/v1/messages/count_tokens` | 粗略 token 估算 |
| GET | `/health` | 状态(含凭据来源) |

## 图像生成(文生图)

`POST /v1/images/generations` 走 MiMo 云端独立的图像端点(与聊天同一套订阅鉴权),模型固定 `Doubao-Seedream-5.0-pro`,`model` 字段任意填(名单外自动回落,填 `dall-e-3` 也能出图):

```
curl http://127.0.0.1:8317/v1/images/generations \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"Doubao-Seedream-5.0-pro\",\"prompt\":\"一只橘猫在键盘上睡觉,像素风\"}"
# -> {"model":"doubao-seedream-5-0-pro-...","created":...,"data":[{"url":"https://...TOS 签名直链..."}],"usage":{...}}
```

- 出图耗时实测 **~40 秒**,客户端超时请放宽到 ≥120s
- 响应为标准 OpenAI images 结构,`data[0]` 含 `url`(火山 TOS 签名直链,需二次下载)或 `b64_json`
- `size`/`n` 等其余字段原样透传上游

## Claude Code 适配细节

`/v1/messages` 面向 Claude Code 全量对齐(在上游能力范围内):

- **工具调用**:`tools`/`tool_choice` 双向映射,`tool_use`/`tool_result` 历史还原为 OpenAI `tool_calls`/`role:tool`;流式 `input_json_delta` 增量下发
- **思考链**:上游 `reasoning_content` → `thinking` 块(带 signature);流式 `thinking_delta` + `signature_delta`;请求侧 `thinking.budget_tokens` → `reasoning_effort`
- **多模态**:`image` 块(base64/url)→ OpenAI `image_url` parts(mimo-pro 实测可识图)
- **用量**:`prompt_tokens_details.cached_tokens` → `cache_read_input_tokens`/`cache_creation_input_tokens`
- **健壮性**:SSE 周期 `ping` + 150s 空闲看门狗;上游非 2xx 与中途异常翻译为 Anthropic `error` 事件/`{type:'error'}` 响应
- **不支持的块**:服务端工具(web_search 等)丢弃,`document` 块降级为占位文本

## 自动维护

- 上游 401/403 → 自动重刷会话并重试一次
- 每 30 分钟定时重刷
- 重刷失败且为非文件模式 → 自动重新提取凭据(MiMo Desktop 重新登录后自愈)
- 凭据来源优先级:`MIMO_COOKIES` 文件 > 实时提取(App 未运行) > DPAPI 缓存

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `MIMO_RELAY_PORT` | `8317` | 监听端口(仅 127.0.0.1) |
| `MIMO_COOKIES` | 空 | 显式指定 cookies JSON 文件(绕过自动提取,自动监视变更) |
| `MIMO_RELAY_LOG` | 空 | 日志追加写入路径(自启模式自动设置) |

## 开机自启

```
powershell -ExecutionPolicy Bypass -File install-autostart.ps1    # 安装并立即启动
powershell -ExecutionPolicy Bypass -File uninstall-autostart.ps1  # 卸载并停止
```

写入当前用户注册表 Run 键 `MimoRelay`(登录时启动,无需管理员),经 wscript 隐藏窗口运行,日志在 `%APPDATA%\mimo-relay\relay.log`。

## 安全说明

- 凭据只存内存 + DPAPI(CurrentUser)加密缓存,**不明文落盘**
- 服务仅监听 `127.0.0.1`,不暴露局域网
- 本工具提取的是**当前机器当前用户自己登录的** MiMo 凭据,仅供本人使用;分发工具不会泄露任何人的凭据(每台机器各取各的)
- 调用消耗的是本人 MiMo 订阅额度,请留意 `/health` 上游状态与云端用量
