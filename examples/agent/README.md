# Agent runner demo

Local fake LLM + fake MCP for `erebus agent run` without cloud keys.

```bash
bash examples/agent/demo.sh
```

Honest boundary (stderr, every run): the signed receipt proves execution,
request/response bytes, and tool calls — **not** that the task succeeded.

| File | Role |
|------|------|
| `fake_llm.py` | OpenAI-compat HTTP; tool call then text; SSE when `stream: true` |
| `fake_mcp.py` | MCP stdio: `tools/list` + `get_weather` |
| `demo.sh` | keygen → agent run (`--mcp-stdio --allow-mcp --stream`) → verify-attest |
