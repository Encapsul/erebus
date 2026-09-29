# Execution attestation — spec 2.0

This page is the normative description of the receipts produced by
`erebus attest`, the launcher stub and the attesting proxy
(`erebus serve --attest-key`). It is also the document the predicate URI
`https://erebus.dev/attestation/execution/v2` points at.

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
        "input_hash":            { "type": ["string", "null"], "description": "served call: sha256 of the proxied request body; batch run: sha256 of the launch vector (entrypoint then argv, NUL-joined) — stdin is not hashed" },
        "output_hash":           { "type": ["string", "null"], "description": "served call: sha256 of the proxied response body; batch run: sha256(stdout digest \":\" stderr digest), Linux isolation ≥ 2 only, else null" },
        "exit_code":             { "type": ["integer", "null"] },
        "prev_attestation_hash": { "type": ["string", "null"], "description": "sha256 of the previous receipt bytes in the local trail" },
        "request": {
          "type": ["object", "null"],
          "required": ["method", "path"],
          "properties": {
            "method": { "type": "string" },
            "path":   { "type": "string" },
            "status": { "type": ["integer", "null"] }
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

Differences from v1 (`…/execution/v1`): `execution.machine_id` added.
Everything else is byte-identical, which is why a single `build_statement`
serves both predicate types.

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

## 7. Files and locations

| Path | Purpose | Mode |
|---|---|---|
| `~/.local/share/erebus/machine/machine.key` (or `$ERE_MACHINE_DIR`) | machine seed, never rotated implicitly | 0600 |
| `…/machine/machine.cert.json` | registry certificate | 0644 |
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
