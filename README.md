# pql-proxy（已归档）

把 PromptQL Playground 包装成 OpenAI 兼容 API 的反代。

## 状态

**项目已停止。** 2026-10-06 PromptQL 以"free credits 被滥用"为由，收回了账号的 Playground 免费额度。没有额度后所有 API 调用都会失败，本项目不再可用，仅作代码归档。

## 曾实现的功能

- `GET /v1/models` — 模型列表（GPT-6.1 Sol / GPT-6 Astra / Claude Fable 5.1 / Claude Opus 5.5）
- `POST /v1/chat/completions` — 聊天（流式、tools/tool_calls、图片）
- OAuth 自动续签（refresh token → access token → luxJWT → Playground JWT，约 24h 有效）

## 运行（历史记录，不再可用）

```bash
python3 pql_proxy.py  # 监听 127.0.0.1:8000
```

需要 `auth.json`（`{"refresh_token": "..."}`），**绝不提交到仓库**。
