# Execution attestation — spec 2.0 / 2.1

This page is the normative description of the receipts produced by
`erebus attest`, the launcher stub and the attesting proxy
(`erebus serve --attest-key`). It is also the document the predicate URI
`https://erebus.dev/attestation/execution/v2` points at. Spec 2.1 is 2.0
plus the signed tool calls of a served call (§3.2) and the tool context of
its request, linked across the trail (§3.3); stop receipts (§3.5) and human
approvals (§3.6); it keeps the v2 predicate URI.

A receipt answers one question with cryptographic evidence: **which bytes ran,
where, when, with which inputs and outputs, and who vouches for it.**

## 1. Layers of evidence

| Layer | What it proves | Signed by | Verified by |
|---|---|---|---|
| Statement (in-toto v1) | bundle/payload digests, provenance, execution facts | — (payload) | `verify-attest` |
| DSSE envelope | the statement was produced by the **operator key** | operator Ed25519 key | `verify-attest`, `cosign`, in-toto |
| Machine co-signature | the receipt was produced **on an enrolled host** | machine Ed25519 key (`erebus enroll`) | `verify-attest --strict` |
| Machine certificate | the machine key belongs to `<owner>` | registry key | `verify-attest --strict --registry-key` |
| Transparency-log proof | the receipt was published at position *i* of a signed tree | registry log key (+ RFC 3161 TSA) | `verify-attest --proof` |
| Local trail | receipts form an append-only hash chain | operator key (prev hash inside the statement) | `verify-attest --chain` |

Every claim printed by a verifier is read from the **signed statement**, never
from the unsigned display copies.

## 2. Receipt document (`*.erebus.attest`)

Pretty-printed JSON (2-space indent). The exact bytes on disk are the
transparency-log leaf preimage and the local-trail hash input, so **do not
reformat** a receipt.

```json
{
  "spec_version": "2.0",
  "attestation_type": "erebus-execution",
  "artifact":   { "...": "display copy, see §4" },
  "provenance": { "...": "display copy, see §4" },
  "execution":  { "...": "display copy, see §4" },
  "statement":  { "...": "decoded in-toto statement, see §3" },
  "signature": {
    "algorithm": "ed25519",
    "key_fingerprint": "sha256:<hex(sha256(operator pubkey))>",
    "signature_hex": "<hex of the operator's DSSE signature>"
  },
  "envelope": {
    "payloadType": "application/vnd.in-toto+json",
    "payload": "<base64(JCS(statement))>",
    "signatures": [
      { "keyid": "sha256:<operator fingerprint>", "sig": "<base64>" },
      { "keyid": "sha256:<machine_id>",           "sig": "<base64>" }
    ]
  },
  "machine": {
    "machine_id": "sha256:<hex(sha256(machine pubkey))>",
    "public_key_hex": "<64 hex>",
    "certificate": {
      "machine_id": "sha256:…",
      "public_key_hex": "<64 hex>",
      "owner": "alice",
      "registry": "https://registry.example",
      "issued_at": "2026-09-17T10:00:00+00:00",
      "registry_key_id": "sha256:…",
      "registry_key_hex": "<64 hex>",
      "signature_hex": "<128 hex>"
    }
  }
}
```

- `envelope` and `machine` are absent on spec 1.x receipts. `machine` is
  absent on 2.0 receipts produced by a host that never ran `erebus enroll`.
- `signature` mirrors the operator entry of the envelope so 1.x consumers keep
  working. Verifiers **must** check that the mirror matches the envelope.

### 2.1 Canonical payload — JCS (RFC 8785)

`payload = base64(JCS(statement))`. JCS is applied to the JSON value of
`statement`: object keys sorted by UTF-16 code units, no insignificant
whitespace, strings serialized per RFC 8259, integers verbatim. Receipts
contain no floating-point numbers (a float is a hard error at signing time).

### 2.2 Pre-Authentication Encoding — DSSE v1

Each signature covers

```
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

with `payload` the **decoded** bytes and `LEN` the decimal byte length —
exactly the [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).
Signature algorithm: Ed25519 (RFC 8032, `ed25519-dalek` strict verification).

### 2.3 Operator verification (`verify-attest`)

1. `envelope.payloadType == application/vnd.in-toto+json`.
2. `base64decode(envelope.payload) == JCS(statement)` — otherwise `TAMPERED`.
3. Pick the trusted key whose fingerprint equals `signature.key_fingerprint`;
   the envelope must carry a valid signature by that key under `keyid ==
   fingerprint`. Looking the key up by fingerprint (instead of "any trusted
   key signed something") keeps a trusted *machine* key from satisfying the
   operator check.
4. `signature.signature_hex == hex(base64decode(sig))` of that entry.
5. Re-derive the statement from `artifact`/`provenance`/`execution` with the
   statement's own `predicate_type` (v1 or v2) and compare (§4).

### 2.4 Machine verification (`verify-attest --strict`)

1. `machine` and `envelope` present (1.x receipts fail `--strict`).
2. `statement.predicate.execution.machine_id == machine.machine_id` — the
   machine identity is part of the **signed** statement, so a machine block
   cannot be grafted onto another receipt.
3. `machine.machine_id == "sha256:" + hex(sha256(machine.public_key_hex))`.
4. The envelope carries a valid signature by the machine key.
5. `machine.certificate` present, for the same key, and its signature verifies
   under a trusted registry key (`--registry-key HEX` or a `.pub` file in the
   trusted dir).

Certificate canonical bytes (signed by the registry key):

```
erebus-machine-cert/v1\n{machine_id}\n{public_key_hex}\n{owner}\n{registry}\n{issued_at}\n
```

The registry key that signs certificates is the transparency-log key
(`GET /log/key`), so an auditor trusts exactly one registry key.

## 3. in-toto statement

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "bundle",  "digest": { "sha256": "<hex>" } },
    { "name": "payload", "digest": { "sha256": "<hex>" } }
  ],
  "predicateType": "https://erebus.dev/attestation/execution/v2",
  "predicate": { "…": "see §3.1" }
}
```

`bundle` is the SHA-256 of the whole `.erebus` file — this is what
`cosign verify-blob-attestation … <bundle>` checks with `--check-claims`.

> erebus 1.x wrote `predicate_type`; parsers accept both spellings and the
> 1.x signature bytes are rebuilt in the legacy form, so old receipts keep
> verifying. New receipts always use the in-toto key `predicateType`.

### 3.1 Predicate v2 — JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://erebus.dev/attestation/execution/v2",
  "title": "erebus execution attestation predicate",
  "type": "object",
  "required": ["builder", "layers", "execution", "artifact"],
  "additionalProperties": false,
  "properties": {
    "builder":  { "type": "string", "description": "erebus-cli version that built the bundle" },
    "author":   { "type": ["string", "null"] },
    "license":  { "type": ["string", "null"] },
    "layers": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "kind", "sha256"],
        "properties": {
          "name":   { "type": "string" },
          "kind":   { "type": "string", "enum": ["runtime", "app", "model", "engine", "layer"] },
          "sha256": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" }
        }
      }
    },
    "execution": {
      "type": "object",
      "required": ["attested_at", "machine_id_hash", "os", "arch"],
      "additionalProperties": false,
      "properties": {
        "attested_at":           { "type": "string", "format": "date-time" },
        "machine_id_hash":       { "type": "string", "description": "sha256(hostname‖os‖arch) — legacy, weak" },
        "machine_id":            { "type": ["string", "null"], "pattern": "^sha256:[0-9a-f]{64}$",
                                   "description": "fingerprint of the enrolled machine key that co-signed the envelope" },
        "os":                    { "type": "string" },
        "arch":                  { "type": "string" },
        "input_hash":            { "type": ["string", "null"], "description": "served call: sha256 of the proxied request body; batch run: sha256 of the launch vector (entrypoint then argv, NUL-joined); stdin is `stdin_hash`" },
        "output_hash":           { "type": ["string", "null"], "description": "served call: sha256 of the proxied response body; batch run: sha256(stdout digest \":\" stderr digest), captured on Linux isolation ≥ 2 and on macOS when ERE_ATTEST_KEY is set, else null" },
        "stdin_hash":            { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "description": "spec 2.1, batch run — sha256 of every byte relayed to a non-terminal stdin; omitted when stdin was a terminal, when the payload exited before stdin reached EOF (or stopped reading), or when not captured" },
        "egress": {
          "type": "object",
          "description": "spec 2.1, batch run — outbound policy the launcher enforced (ERE_EGRESS); omitted when the payload ran unconfined",
          "required": ["tcp_ports", "scope"],
          "properties": {
            "tcp_ports": { "type": "array", "items": { "type": "integer", "minimum": 1, "maximum": 65535 }, "description": "sorted; empty = no egress" },
            "scope":     { "enum": ["loopback", "any_address"], "description": "loopback: macOS Seatbelt, localhost:<port> only; any_address: Linux Landlock, the port on any host" }
          }
        },
        "exit_code":             { "type": ["integer", "null"] },
        "prev_attestation_hash": { "type": ["string", "null"], "description": "sha256 of the previous receipt bytes in the local trail" },
        "stop": {
          "type": "object",
          "description": "spec 2.1, §3.5 — omitted when this receipt is not a stop",
          "required": ["requested_at", "reaped_at", "signal"],
          "properties": {
            "requested_at": { "type": "string", "format": "date-time" },
            "reaped_at":    { "type": "string", "format": "date-time" },
            "signal":       { "type": "string", "enum": ["SIGTERM", "SIGINT"] },
            "kill_timeout": { "const": true, "description": "omitted when false — supervisor called kill()" }
          }
        },
        "approval": {
          "type": "object",
          "description": "spec 2.1, §3.6 — omitted when no human approval is attached",
          "required": ["decision", "subject_digest", "decided_at", "key_fingerprint", "signature_hex"],
          "properties": {
            "decision":        { "enum": ["allow", "deny"] },
            "subject_digest":  { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
            "decided_at":      { "type": "string", "format": "date-time" },
            "key_fingerprint": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
            "signature_hex":   { "type": "string", "pattern": "^[0-9a-f]{128}$" }
          }
        },
        "request": {
          "type": ["object", "null"],
          "required": ["method", "path"],
          "properties": {
            "method": { "type": "string" },
            "path":   { "type": "string" },
            "status": { "type": ["integer", "null"] },
            "tool_calls": {
              "type": "array", "minItems": 1,
              "description": "spec 2.1, §3.2 — omitted when the response carried none",
              "items": {
                "type": "object",
                "required": ["choice", "name", "arguments_hash"],
                "properties": {
                  "choice":         { "type": "integer", "minimum": 0 },
                  "id":             { "type": ["string", "null"] },
                  "name":           { "type": "string", "minLength": 1 },
                  "arguments_hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" }
                }
              }
            },
            "tool_calls_incomplete": { "const": true, "description": "spec 2.1 — omitted when false" },
            "tools_offered": {
              "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 },
              "description": "spec 2.1, §3.3 — function tool names the request offered"
            },
            "tool_history": {
              "type": "array", "minItems": 1,
              "description": "spec 2.1, §3.3 — calls the request replayed as history; items as tool_calls, choice 0"
            },
            "tool_results": {
              "type": "array", "minItems": 1,
              "description": "spec 2.1, §3.3 — results the request fed back",
              "items": {
                "type": "object",
                "required": ["id", "content_hash"],
                "properties": {
                  "id":           { "type": "string", "minLength": 1 },
                  "content_hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" }
                }
              }
            },
            "request_tools_incomplete": { "const": true, "description": "spec 2.1 — omitted when false" }
          }
        },
        "rootfs_root":           { "type": ["string", "null"], "description": "Merkle root of the extracted rootfs (rootfs.merkle)" }
      }
    },
    "artifact": {
      "type": "object",
      "required": ["metadata_hash", "format_version", "flags"],
      "properties": {
        "metadata_hash":  { "type": "string" },
        "format_version": { "type": "integer" },
        "flags":          { "type": "array", "items": { "type": "string" } }
      }
    }
  }
}
```

**Batch stdin (spec 2.1).** With capture on, a non-terminal stdin is relayed
by the launcher supervisor through a pipe and hashed. The digest is signed
only when stdin reached EOF and every byte was delivered before the payload
exited (500 ms grace), so `stdin_hash` always equals `sha256` of the whole
input an auditor holds: `printf 'job' | ./agent.erebus` signs
`sha256("job")`. Its absence is not evidence of empty input. A terminal is
left attached and never hashed.

**Egress confinement (spec 2.1).** `ERE_EGRESS=PORT[,PORT…]` (or `none`)
in the launcher's environment limits the payload's outbound TCP to those
ports; the intended value is the port of an `erebus attest-tool http`
boundary, so the agent can reach its tools only through it. The launcher
enforces it before exec and signs `execution.egress`; an unparsable value or
a kernel that cannot enforce it stops the launch (exit 126 under capture),
never an unconfined run.

| Platform | Mechanism | Enforced |
|---|---|---|
| macOS | Seatbelt `network-outbound` | TCP and UDP only to `localhost:<port>` (`scope: loopback`) |
| Linux ≥ 6.7 | Landlock `CONNECT_TCP` (ABI ≥ 4) + seccomp | TCP `connect` only to the ports, on any address (`scope: any_address`); UDP/raw/packet sockets, TCP Fast Open, `io_uring`, x32 and foreign ABIs refused (EACCES) |
| Linux < 6.7 | — | launch refused |

Unix-domain sockets (local IPC) are not confined, and neither are child
processes the payload spawns over stdio (an MCP stdio server started by the
agent itself is outside the boundary).

Differences from v1 (`…/execution/v1`): `execution.machine_id` added.
Everything else is byte-identical, which is why a single `build_statement`
serves both predicate types.

### 3.2 Tool calls of a served call (spec 2.1)

A receipt from the attesting proxy records *what the agent was told to do*,
not only what the model said: every tool call the engine returned is signed
into `execution.request.tool_calls`, ordered by `(choice, index)`.

| Field | Value |
|---|---|
| `choice` | `choices[].index` of a chat completion; `0` for the Responses API |
| `id` | engine call id (`call_…`; Responses API `call_id`), links the call to the `tool` message that answers it; `null` for a legacy `function_call` |
| `name` | function name, **in clear**: an auditor must read which action ran |
| `arguments_hash` | `sha256` of the exact `arguments` string (stream fragments concatenated); JCS bytes when an engine sends an object |
| `arguments_jcs_hash` | optional: `sha256` of the JCS form of the parsed arguments; absent, `null` or blank arguments count as `{}`; omitted when the arguments are not JSON or contain a float (JCS number formatting is not pinned across implementations). This is what a tool receipt is matched on (§3.4) |

Recognised: chat completions `message.tool_calls`, streamed
`delta.tool_calls`, legacy `function_call`, Responses API `function_call`
output items (`output[]`, `response.output_item.done`, `response.completed`
deduplicated by index and id). The format is decided **from the bytes
alone** — first non-whitespace byte `{` is one JSON document, anything else
is read as SSE `data:` events — never from headers, so the list is a pure
function of the body `output_hash` covers.

`tool_calls_incomplete: true` means the list may miss entries: compressed
body (`Content-Encoding` other than `identity`), malformed JSON or event,
body over 16 MiB (JSON) or event over 4 MiB (SSE), more than 256 calls, a
name or id over 1 KiB, a call without a name. The extractor never guesses:
**an absent call is evidence of absence only when the flag is absent.**

Both fields are omitted — not `null` — when unused, so a receipt without
tool calls is byte-identical to 2.0 and says `"spec_version": "2.0"`; a
receipt carrying either field says `"2.1"`.

**Auditor check** (`verify-attest <receipt> --response-body FILE`), from
signed data only:

1. `sha256(FILE) == execution.output_hash`, else `TAMPERED: response body
   mismatch`.
2. Re-extract the tool calls of `FILE`. Without the incomplete flag the result
   must equal the signed list and be complete; with it, every signed call must
   appear in the result. Otherwise `TAMPERED: tool_calls mismatch` — the
   launcher signed a list its own body contradicts.

Plaintext arguments are never in the receipt: the operator keeps them and
`arguments_hash` proves they were not altered.

### 3.3 Tool context of the request, linked across the trail (spec 2.1)

An agent closes the loop in its *next* request: it replays the model's calls
as history and feeds each result back under the call id. The proxy indexes
that request body — the one `input_hash` covers — into three signed lists:

| Field | Source (chat completions / Responses API) |
|---|---|
| `tools_offered` | `tools[].function.name`, legacy `functions[].name` / `tools[].name` of `type: function`; built-in tools without a name are skipped |
| `tool_history` | `messages[role=assistant].tool_calls` and `function_call` / `input[type=function_call]`, digested exactly like `tool_calls` |
| `tool_results` | `messages[role=tool]` → `{id: tool_call_id, content_hash}` / `input[type=function_call_output]` → `{id: call_id, content_hash: sha256(output)}`; content hashed as its string bytes, JCS otherwise |

Only a body whose first non-whitespace byte is `{` is read; other bodies
carry no tool context. `request_tools_incomplete: true` flags a compressed
request, malformed JSON, a body over 16 MiB, a result without a call id
(including legacy `role: "function"` results), a float in structured
content, more than 256 entries or a label over 1 KiB. Same omission rule as
§3.2: a request without tool context keeps the 2.0 bytes.

**Auditor check** (`verify-attest <receipt> --request-body FILE`):
`sha256("METHOD path\n" ‖ FILE) == execution.input_hash`, else `TAMPERED:
request body mismatch`; re-indexing `FILE` must give the signed lists (a
superset when flagged incomplete), else `TAMPERED: request tool fields
mismatch`.

**Linkage** (`verify-attest --chain DIR`, from signed data only, after every
receipt verified). Walking the trail in order, each request is matched
against the calls the engine issued in *earlier* receipts:

| Finding | Meaning |
|---|---|
| `result_without_call` | a result was fed back for a call id the engine never issued in this trail — an injected result |
| `history_without_call` | history replays a call id the engine never issued |
| `history_altered` | history replays an issued id with another name or `arguments_hash` — a rewritten conversation |
| `result_rewritten` | a second, different `content_hash` for an id issued once |
| `unoffered_tool` | the engine called a tool absent from the request's `tools_offered` |

Each finding is reported once, at its first receipt. Issued calls are
reported `answered` or `pending`. Two rules keep the report honest: an id
the engine issued several times (some engines reuse `call_0`) never yields
`result_rewritten`, and a missing-call finding after any response signed
`tool_calls_incomplete` is counted `unverifiable`, not accused. A trail that
starts mid-conversation shows its first replayed history as
`history_without_call`. Findings are warnings; `--require-tool-linkage`
turns them into a verification failure (exit 2).

### 3.4 Attested tool boundary (spec 2.1)

`erebus attest-tool` puts the tool itself behind a signing boundary and
writes its own trail, one receipt per execution:

- `attest-tool http --listen A --upstream B`: reverse proxy in front of a
  plain HTTP tool or an MCP server over Streamable HTTP (JSON or SSE
  answers). Every request is recorded.
- `attest-tool stdio … -- CMD ARGS`: wraps an MCP server spawned over
  stdio. Newline-delimited JSON-RPC is relayed byte for byte. Each
  `tools/call` request with its response (matched by JSON-RPC `id`) is one
  receipt, with `input_hash` / `output_hash` the `sha256` of the two
  messages without their newline, method `STDIO` and path `tools/call`.

The receipt names the tool (`artifact.flags: ["tool"]`). Its digests are
those of the program file it runs, or of the JCS descriptor of the
boundary (`{kind, transport, upstream|command}`), or of the exact bundle
with `--bundle`. `execution.request.tool_invocation` is signed:

| Field | Value |
|---|---|
| `protocol` | `mcp` (JSON-RPC request) or `http` |
| `name` | MCP `params.name`; absent for plain HTTP (bind it with `--tool-trail NAME=DIR`) |
| `arguments_jcs_hash` | same canonical digest as §3.2: MCP `params.arguments`, or the HTTP request body (blank → `{}`) |
| `result_hashes` | every form the result can be relayed in. MCP: JCS of `result`, of `content`, of `structuredContent`, and the raw `sha256` of the text blocks joined by `\n` when `content` is all text. HTTP: raw `sha256` of the body, plus its JCS digest when JSON |
| `is_error` | JSON-RPC `error`, MCP `isError: true`, HTTP status ≥ 400 or no response |
| `incomplete` | the response was not observed (connection lost, compressed or oversized body) |
| `call_id` | optional: the engine's tool call id the caller declared, from MCP `params._meta["dev.erebus/call_id"]` or the HTTP request header `Erebus-Call-Id` (`_meta` wins); trimmed, 1–256 bytes, otherwise absent |

**Execution matching** (`verify-attest --chain AGENT --tool-trail
[NAME=]DIR …`). Every tool trail is verified as a chain first: with the
agent's trusted keys by default (`tool_trust: "shared"`, and the human
output warns that one key can forge both trails), or with
`--tool-trusted-dir DIR` only against the keys in `DIR`
(`tool_trust: "separate"`). That directory must not hold any key the agent
trail is trusted with; an overlap is refused, so the tool trail and the
agent trail are provably signed by different keys. Then each call the engine issued is matched one-to-one,
in chain order, to an unused tool execution:

1. **Bound**: the execution whose `call_id` equals the call's id. The
   tool must have run exactly that call (same name, same
   `arguments_jcs_hash`), otherwise the finding is `execution_altered`. A
   bound execution is never matched to any other call.
2. **Unbound**: otherwise, an execution without `call_id` with the same
   `arguments_jcs_hash` and the same name (a nameless execution matches on
   arguments only).

Binding makes two identical calls distinguishable: without it, executions
of identical calls that ran in another order are paired in chain order
and can yield a spurious `result_not_from_tool`. A missing or non-existent
directory is an error, never "nothing executed".

| Finding | Meaning |
|---|---|
| `result_without_execution` | a result was fed back for an issued call that no attested tool executed |
| `result_not_from_tool` | the fed-back `content_hash` is not one of the matched execution's `result_hashes` |
| `execution_without_call` | a tool execution no issued call accounts for (including one bound to an id the engine never issued), reported at its tool receipt |
| `execution_altered` | the execution bound to this call ran another name or other arguments than the engine issued |

The report counts `executed`, `not_executed`, `verbatim`, `unverifiable`,
`bound` (matched by `call_id`) and `altered`. A call without
`arguments_jcs_hash` (even when bound), an execution without
`arguments_jcs_hash` or `call_id`, and an unmatched execution after a response signed
`tool_calls_incomplete` are `unverifiable`, never accused. Findings carry
the agent receipt that issued the call and the tool receipt. They are
warnings; `--require-tool-execution` turns them into a failure (exit 2),
independently of `--require-tool-linkage`.

### 3.5 Stop receipts (spec 2.1)

When `erebus serve --attest-key` receives SIGTERM or SIGINT *after* the
engine is healthy, it appends one final receipt whose signed predicate
carries only `execution.stop`:

| Field | Meaning |
|---|---|
| `requested_at` | ISO 8601 UTC when the stop was first observed |
| `reaped_at` | ISO 8601 UTC when the engine child was reaped |
| `signal` | `SIGTERM` or `SIGINT` |
| `kill_timeout` | `true` when the supervisor called `kill()` (omitted when false) |

A signal during startup (`wait_healthy`) aborts without a stop receipt.
`reaped_at` is always ≥ `requested_at`. Spec version is `2.1`.

The stub capture supervisor (`ERE_ATTEST_KEY` + pivot/macOS capture path)
latches the same fields into the **completion** receipt when SIGTERM/SIGINT
arrives during the run (`kill_timeout: true`, same semantics as serve).

### 3.6 Human approval (spec 2.1)

Optional oversight evidence (EU AI Act Art. 14). `erebus approve` signs:

```
erebus-approval/v1\n{decision}\n{subject_digest}\n{decided_at}\n
```

with an Ed25519 approver key (`decision` is `allow` or `deny`). The
resulting JSON is attached with `erebus attest --approval FILE` into
`execution.approval`. `verify-attest --approver-key <hex|.pub>` checks the
signature and prints the approver fingerprint; a forged signature is
`TAMPERED` (exit 2). Spec version is `2.1` when present.

### 3.7 Local witness checkpoint (R1 / DDIL)

While offline, a second Ed25519 **witness** key co-signs the local trail
head. Design (trail head only — not a full Merkle tree offline):

| Field | Meaning |
|---|---|
| `origin` | Absolute path of the trail directory |
| `size` | Number of receipt files covered |
| `root` | `sha256:` of the **head receipt file bytes** (same digest as `HEAD`) |
| `witnessed_at` | ISO 8601 UTC when the witness signed |
| `witness_id` | Fingerprint of the witness verifying key |
| `signature_hex` | Ed25519 over the canonical bytes below |

Canonical message:

```
erebus-witness-checkpoint/v1\n{origin}\n{size}\n{root_hex}\n{witnessed_at}\n{witness_id}\n
```

Stored as `<trail>/HEAD.witness.json`. CLI:

```sh
erebus witness keygen [--dir DIR]          # ~/.local/share/erebus/witness/witness.key
erebus witness seal --trail agent.attest.d
erebus verify-attest --chain DIR --witness-key <hex|.pub> [--require-witness]
erebus verify-attest receipt.attest --proof --witness-key …
```

`--require-witness` refuses a trail that grew past the sealed `size` /
`root` (insertion during an outage). Without it, a historical seal still
verifies and prints `witnessed at T1`; with `--proof`, also `anchored at T2`,
requiring `witnessed_at ≤ checkpoint.timestamp`. A failed `--push` leaves
the receipt in the trail and seals the head (store-and-forward).

## 4. Display copies and consistency

`artifact`, `provenance` and `execution` at the top level are convenience
copies for humans and `jq`. They are **not signed**. A verifier rebuilds the
statement from them and compares it to the signed `statement`; any
difference is reported as `TAMPERED: <block> mismatch`. Keys absent from an
older receipt (e.g. `machine_id` on 1.2) are treated as `null`, so 1.x
receipts stay consistent.

## 5. Bare envelope (`erebus attest --envelope FILE`)

The `envelope` object alone, compact JSON. This is the interchange form:

```sh
erebus keygen --key-dir keys            # also writes <fp>.pem (SPKI)
erebus attest agent.erebus --key keys/<fp>.key --envelope agent.dsse.json
cosign verify-blob-attestation \
  --key keys/<fp>.pem \
  --signature agent.dsse.json \
  --type https://erebus.dev/attestation/execution/v2 \
  --insecure-ignore-tlog agent.erebus
# Verified OK
```

`--insecure-ignore-tlog` only means "this envelope was not uploaded to
Rekor"; erebus receipts are anchored in the erebus transparency log instead
(`verify-attest --proof`). Rekor upload is planned (P1). cosign refuses
blobs over 128 MiB unless `COSIGN_MAX_ATTACHMENT_SIZE` is raised (e.g.
`16GiB`); bundles with embedded weights usually need it.

## 6. Compatibility matrix

| Receipt | `verify-attest` | `--strict` | `--proof` | cosign |
|---|---|---|---|---|
| 1.0 – 1.2 (pretty-JSON signature) | ✅ legacy path | ❌ `STRICT: spec 1.x` | ✅ if pushed | ❌ |
| 2.0, host not enrolled | ✅ | ❌ `STRICT: … not enrolled` | ✅ | ✅ |
| 2.0, enrolled host | ✅ | ✅ with registry key | ✅ | ✅ |
| 2.1 (tool fields, `stdin_hash`/`egress`, `stop`, or `approval`) | ✅ erebus after 0.6.1; ❌ `TAMPERED` on 0.6.1 and older, which rebuild the statement without the new fields | as 2.0 | ✅ | ✅ (same v2 predicate URI) |

## 7. Files and locations

| Path | Purpose | Mode |
|---|---|---|
| `~/.local/share/erebus/machine/machine.key` (or `$ERE_MACHINE_DIR`) | machine seed, never rotated implicitly | 0600 |
| `…/machine/machine.cert.json` | registry certificate | 0644 |
| `~/.local/share/erebus/witness/witness.key` (or `$ERE_WITNESS_KEY` / `$ERE_WITNESS_DIR`) | local trail witness seed (R1) | 0600 |
| `<trail>/HEAD.witness.json` | signed trail-head checkpoint while offline | 0644 |
| `<bundle>.erebus.attest` | latest receipt | 0644 |
| `<bundle>.erebus.attest.d/` | hash-chained trail | 0644 |
| `<receipt>.proof.json` | transparency-log proof (`erebus-log-proof/v1`) | 0644 |

## 8. Threat notes

- A **stolen operator key** produces receipts that verify — but not
  `--strict` ones (no machine key) and not with a log proof predating the
  theft. Rotate the operator key; enrolled machines are unaffected.
- A **stolen machine key** only helps an attacker who also holds an operator
  key; the registry certificate names the owner, and `GET /machines` lists
  every enrolled key so it can be revoked (revocation lists: P1).
- The machine key is a **software** key. A TPM2-backed quote is on the
  roadmap (P1, optional, Linux only) and will be an extra field, never a
  requirement.
- **What tool linkage proves, and what it does not.** It proves, per call
  id, what the engine asked for and what the agent *reported back* to it,
  and it exposes results nobody asked for, rewritten history and changed
  results (§3.3). Alone it does not prove the tool ran. With the tool behind
  `attest-tool` (§3.4) it also proves that every issued call reached a tool
  with exactly those arguments, that the result relayed to the model is the
  one the tool returned, and that the tool ran nothing the model did not
  ask for. Limits that remain: the boundary proves what crossed it, not the
  tool's effect on the outside world (an HTTP tool that answers `queued`
  without sending the mail is not caught); a tool the agent calls *around*
  the boundary is not observed (`execution_without_call` cannot see it,
  `result_without_execution` can) unless the run is confined with
  `ERE_EGRESS` to the boundary's port and the receipt shows `egress` — on
  Linux the port is enforced but not the address, and Unix sockets and
  stdio subprocesses stay open; two identical calls are told apart only
  when the caller declares the engine's call id (`call_id`), and a declared
  id is the caller's claim — it binds the execution to that call, it does
  not prove which process sent it; and both trails
  are signed by keys the verifier must trust. With the default shared trust
  a single compromised operator key forges both sides; with
  `--tool-trusted-dir` forging both needs two keys, which only helps if the
  tool operator's key is actually held by someone else (another team, the
  tool vendor, another host). Separation proves different keys, not
  different owners.
