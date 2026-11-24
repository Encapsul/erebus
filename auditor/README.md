# Auditor kit

This directory is the hand-off surface for a third party who must verify an
erebus trail, typically inside an on-prem or air-gapped perimeter where no
vendor call-home is allowed. It contains no private key, no account setup and
no network calls: `verify_pack.py` runs `erebus verify-evidence` with **pinned
keys**, then checks the pack's DSSE envelope with stock `cosign` and,
optionally, its RFC 3161 token with stock `openssl`.

The operator hands over **one zip**:

```bash
erebus evidence export agent.erebus --trail agent.erebus.attest.d \
  --log-key <registry /log/key hex> -o evidence.zip [--include-bundle]
```

The auditor also receives the bundle (unless `--include-bundle` was used) and
two values **out of band** — a contract annex, signed email or call, never the
zip itself:

| Input | Source | Form |
|---|---|---|
| Operator public key | the operator (`erebus keygen` output) | 64 hex, or `sha256:<fingerprint>` |
| Log key | the registry, `GET /log/key` | 64 hex |

## One command

```bash
python3 auditor/verify_pack.py evidence.zip \
  --bundle agent.erebus \
  --operator-key <operator hex or sha256:fingerprint> \
  --log-key <log key hex>
# ...
# EVIDENCE PACK OK — confirm the pinned keys out of band
```

The script refuses to continue unless `verify-evidence` reports `verified`,
both keys pinned, at least one receipt, an inclusion proof for **every**
receipt, and the bundle file checked against the signed digest. It exits 1
with `AUDIT FAILED` on any mismatch. `--json` returns the same result for the
auditor's own tooling; `--erebus /path/to/erebus` selects the binary.

Optional, still offline:

```bash
python3 auditor/verify_pack.py evidence.zip --bundle agent.erebus \
  --operator-key <operator> --log-key <log> \
  --tsa-ca cacert.pem        # CA chain obtained from the TSA out of band
```

`cosign` and `openssl` are optional: the script prints `SKIP` with the reason
when either is missing. With `cosign` present it verifies the first DSSE
envelope against every operator PEM in the pack (`--insecure-ignore-tlog`
only skips Sigstore's Rekor; the erebus log is checked by `verify-evidence`).
`--tsa-ca` verifies each `.tsr` against the exact checkpoint bytes the pack
carries.

## What the auditor can conclude

For each receipt: this exact bundle ran under this operator key on the named
machine at the signed time, with these input/output digests, and the record
was anchored in the transparency log before the TSA time. The hash chain
proves no receipt was reordered or removed before the head. The auditor must
still check the pinned keys came from the expected parties.

The kit does **not** prove the output was correct, reveal prompt/response
plaintext, or prove that every execution was captured. Coverage is derived
from receipts: traffic that never produced one is invisible. The current log
checkpoint must be compared out of band to catch deletion of the newest
receipts. See [what erebus proves](../docs/src/concepts/proof.md) and the
[audit guide](../docs/src/guides/audit.md).

## Status

This kit ships with an automated offline proof in CI (`evidence_e2e.rs`), but
**T4 is not complete**: no auditor or consultancy has yet provided the written
confirmation that the pack is sufficient for their engagement. Do not present
this directory as third-party validation. The ready-to-send brief and blank
answer form are in [T4-request.md](T4-request.md). The request checklist is:
one ICP agent, 14 days of receipts, the pinned keys out of band, this script's
output, and the auditor's own written conclusion.
