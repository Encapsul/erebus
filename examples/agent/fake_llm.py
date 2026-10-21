#!/usr/bin/env python3
"""Fake OpenAI-compatible LLM for `erebus agent` demos and e2e.

First turn with tools → call get_weather (or echo). After a tool result → text.
Supports non-stream JSON and `stream: true` SSE.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        req = json.loads(body or b"{}")
        msgs = req.get("messages") or []
        answered = bool(msgs) and msgs[-1].get("role") == "tool"
        stream = bool(req.get("stream"))
        tool_names = {
            (t.get("function") or {}).get("name")
            for t in (req.get("tools") or [])
            if isinstance(t, dict)
        }
        if req.get("tools") and not answered:
            name = "get_weather" if "get_weather" in tool_names else "echo"
            args = (
                '{"city":"Paris"}'
                if name == "get_weather"
                else '{"text":"pong"}'
            )
            reply = {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {"name": name, "arguments": args},
                                }
                            ],
                        }
                    }
                ]
            }
        else:
            reply = {
                "choices": [
                    {"message": {"role": "assistant", "content": "weather-ok"}}
                ]
            }
        if stream:
            self._sse(reply)
        else:
            raw = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    def _sse(self, reply):
        msg = reply["choices"][0]["message"]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if msg.get("tool_calls"):
            tc = msg["tool_calls"][0]
            chunks = [
                {"choices": [{"delta": {"role": "assistant"}, "index": 0}]},
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": tc["id"],
                                        "type": "function",
                                        "function": {
                                            "name": tc["function"]["name"],
                                            "arguments": "",
                                        },
                                    }
                                ]
                            },
                            "index": 0,
                        }
                    ]
                },
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {
                                            "arguments": tc["function"]["arguments"]
                                        },
                                    }
                                ]
                            },
                            "index": 0,
                        }
                    ]
                },
            ]
        else:
            text = msg.get("content") or ""
            chunks = [
                {"choices": [{"delta": {"role": "assistant"}, "index": 0}]},
                {"choices": [{"delta": {"content": text}, "index": 0}]},
            ]
        for c in chunks:
            self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        # Close so keep-alive clients do not wait forever for EOF.
        try:
            self.connection.shutdown(1)
        except OSError:
            pass


def main() -> int:
    httpd = HTTPServer(("127.0.0.1", 0), H)
    print(httpd.server_address[1], flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
