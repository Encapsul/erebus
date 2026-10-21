#!/usr/bin/env python3
"""Minimal MCP stdio server: tools/list + get_weather (for agent demos/e2e)."""
from __future__ import annotations

import json
import os
import sys


def respond(msg_id, result):
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n"
    )
    sys.stdout.flush()


def main() -> int:
    weather = os.environ.get("WEATHER", "18C, sunny")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if "id" not in msg:
            continue
        method = msg.get("method")
        mid = msg["id"]
        if method == "initialize":
            respond(
                mid,
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-mcp", "version": "0.1"},
                },
            )
        elif method == "tools/list":
            respond(
                mid,
                {
                    "tools": [
                        {
                            "name": "get_weather",
                            "description": "Weather for a city (demo)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"city": {"type": "string"}},
                                "required": ["city"],
                            },
                        }
                    ]
                },
            )
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            if name != "get_weather":
                respond(
                    mid,
                    {
                        "content": [{"type": "text", "text": f"unknown tool {name}"}],
                        "isError": True,
                    },
                )
            else:
                city = (params.get("arguments") or {}).get("city", "?")
                respond(
                    mid,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": f"{city}: {weather}",
                            }
                        ],
                        "isError": False,
                    },
                )
        else:
            respond(mid, {})
    return 0


if __name__ == "__main__":
    sys.exit(main())
