# pql-proxy

把 PromptQL Playground 包装成 OpenAI 兼容 API 的反代。

## 状态

2026-10-06 PromptQL 以"free credits 被滥用"为由收回了本账号的 Playground 免费额度，旧号暂时不可用。**新注册账号仍可获得免费额度**，换号后本项目继续可用。

## 功能

- `GET /v1/models` — 模型列表（GPT-6.1 Sol / GPT-6 Astra / Claude Fable 5.1 / Claude Opus 5.5）
- `POST /v1/chat/completions` — 聊天（流式、tools/tool_calls、图片）
- OAuth 自动续签（refresh token → access token → luxJWT → Playground JWT，约 24h 有效）

## 运行

```bash
python3 pql_proxy.py  # 监听 127.0.0.1:8000
```

需要 `auth.json`（`{"refresh_token": "..."}`）：用 PromptQL 的 OAuth（PKCE S256，client_id 见源码）换 refresh token 后填入，之后自动续签。

**注意：auth.json 是登录凭证，绝不提交到仓库。**
