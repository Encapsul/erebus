# Agent runner demo

Local fake LLM + fake MCP for `erebus agent run` without cloud keys.

```bash
bash examples/agent/demo.sh
```

Honest boundary (stderr, every run): the signed receipt proves execution,
request/response bytes, and tool calls — **not** that the task succeeded.

**Tool trail (automatic):** each tool execution appends an in-process receipt
beside the agent trail (`run.attest.d` → `run.tools.attest.d`, or
`--tool-trail DIR`). Same digests as `erebus attest-tool` (no subprocess per
call). After a run:

```bash
erebus verify-attest --chain run.attest.d --tool-trail run.tools.attest.d \
  --require-tool-execution
```

Flags: `--tool-trail`, `--tool-attest-key` (default: reuse `--attest-key`),
`--no-tool-attest`, `--require-tool-execution` (post-run verify).

| File | Role |
|------|------|
| `fake_llm.py` | OpenAI-compat HTTP; tool call then text; SSE when `stream: true` |
| `fake_mcp.py` | MCP stdio: `tools/list` + `get_weather` |
| `demo.sh` | keygen → agent run (`--mcp-stdio --allow-mcp --stream --require-tool-execution`) → verify chain + tool trail |
