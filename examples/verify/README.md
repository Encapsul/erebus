# Verify this receipt offline

Public files only. This directory has no private key.

`operator.pem` is the operator public key. `agent.dsse.json` is the DSSE
envelope from `erebus attest --envelope`. `agent.erebus` is the bundle those
bytes sign (built on macOS; cosign checks the file, it does not run it).

## Cosign (operator signature only)

```bash
cosign verify-blob-attestation \
  --key operator.pem \
  --signature agent.dsse.json \
  --type https://erebus.dev/attestation/execution/v2 \
  --insecure-ignore-tlog agent.erebus
#  Verified OK
```

That line means the operator key signed this bundle. It does not mean a model
computed an answer. `scripts/yc_demo.sh` emits the same kind of envelope on a
Linux host, and also checks tamper refusal, the offline transparency-log
proof, and the machine co-signature. This sample is the operator signature
only: the host was not enrolled.

## One-command pack (`offline.sh`)

Point at a receipt (and optional `.proof.json` beside it), or a directory that
holds receipt + proof + `.pub` keys:

```bash
# Receipt + sibling keys / proof
./offline.sh /path/to/000022-….json --log-key "$REG_HEX" --strict

# Or a staging directory
mkdir -p /tmp/erebus-pack && cp receipt.json receipt.json.proof.json *.pub /tmp/erebus-pack/
./offline.sh --pack /tmp/erebus-pack --log-key "$REG_HEX" --strict --bundle agent.erebus
```

Equivalent bare CLI (what the script wraps):

```bash
erebus verify-attest receipt.json \
  --trusted-dir ./keys \
  --proof --proof-file receipt.json.proof.json \
  --log-key "$REG_HEX" \
  --strict
```

Auditor zip path (full trail): `erebus evidence export …` then
`erebus verify-evidence evidence.zip --bundle agent.erebus`.

## Request / response body binding (`body.sh`)

A served-call receipt plus the plaintext bodies an auditor was handed.
`verify-attest --request-body` / `--response-body` re-hash those bytes and
re-derive the signed tool fields. Forged bodies exit 2 (`TAMPERED`). This
does not prove the model computed the answer — only that these bytes match
the receipt.

```bash
./body.sh
# fixtures: body/call.attest + request.json + response.json + operator.pub
```

## Golden output digest

For a deterministic tool, pin the expected result hash:

```bash
erebus verify-attest tool.attest --expected-output-hash sha256:<hex>
# mismatch → exit 2, TAMPERED: output_hash mismatch
```

`erebus attest-tool … --expected-output-hash` refuses to write a receipt when
the live response differs. Same bound: bytes, not judgment.
