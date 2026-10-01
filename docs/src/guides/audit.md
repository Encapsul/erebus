# Auditing an erebus trail

This guide is for the person who **receives** evidence: an auditor, a
compliance officer, a customer's security team. You do not need an erebus
account, network access, or any trust in the operator who ran the agent.

You get one file, `evidence.zip`, produced on the operator's side by:

```bash
erebus evidence export agent.erebus --log-key $REG -o evidence.zip [--include-bundle]
```

Export refuses to package a trail that does not verify, but you must not rely
on that: everything below is re-checked on your machine.

## 1. Get the two keys through another channel

The pack carries the public keys that signed it. On their own they prove
nothing — anyone can generate keys and sign a fabricated trail. Before
opening the pack, obtain:

| Key | Who gives it to you | What it looks like |
|---|---|---|
| Operator public key | the operator (contract annex, signed email, call) — the value `erebus keygen` printed | 64 hex, or its `sha256:` fingerprint |
| Transparency-log key | the registry, at `GET /log/key` → `public_key_hex` | 64 hex |

These two values are your only trust inputs. Write down where they came from.

## 2. Verify the pack

```bash
erebus verify-evidence evidence.zip \
  --bundle agent.erebus \
  --operator-key <operator public key hex> \
  --log-key <registry log key hex>
```

```text
OK: evidence pack verified (erebus-evidence/1)
  bundle:     agent.erebus sha256:7ca8bb55… (file checked)
  receipts:   42, hash-chained, head sha256:360dcb37…
  signatures: 42/42 operator, 42/42 machine co-signed (enrolled)
  log:        42/42 inclusion proofs under signed checkpoints, 42 RFC 3161 anchor(s)
  files:      320 hashed — none missing, none extra
  operator    sha256:d830f417… (pinned)
              public key 5f1c02e9…
  registry    sha256:9d3a805b… (pinned)
```

`--json` prints the same report for your own tooling. Any failure exits
with code 2 and names the file and the check that failed (`TAMPERED: …`).

What each line established, and how:

| Line | Check |
|---|---|
| `bundle` | SHA-256 of the file you hold equals the digest inside every signed receipt. Without `--bundle` (and without `--include-bundle` at export) only the digest is reported. |
| `receipts` | Each receipt names the SHA-256 of the previous one inside its signed statement: nothing was reordered, inserted or removed inside the trail. |
| `signatures` | DSSE signature by a pinned operator key; machine co-signature by a host key whose certificate is signed by the pinned registry key (`--strict`). |
| `log` | Each receipt is a leaf of the registry's Merkle transparency log: inclusion proof up to a checkpoint signed by the pinned log key. |
| `files` | Every file listed in `MANIFEST.json` is present with its hash, and nothing else is in the zip. The manifest is only an index: editing a receipt and re-hashing the manifest is still refused by the receipt's own signature and log leaf. |
| `operator` / `registry` | Every key in the pack is one you pinned. `NOT PINNED` means you skipped step 1: the report is then only self-consistent. |

## 3. Check the timestamps without erebus

Each anchored receipt comes with the registry checkpoint it was logged under
and the RFC 3161 response of an independent timestamping authority (TSA)
over that checkpoint. erebus checks the token structurally; the TSA's CMS
signature is checked with stock OpenSSL and the TSA's published CA chain:

```bash
unzip evidence.zip -d ev && cd ev
curl -sSO https://freetsa.org/files/cacert.pem        # the TSA named in the token
for t in anchors/*.tsr; do
  openssl ts -verify -in "$t" -data "${t%.tsr}.checkpoint" -CAfile cacert.pem
done
# Verification: OK
openssl ts -reply -in anchors/<receipt>.tsr -text | grep 'Time stamp'
```

`anchors/<receipt>.checkpoint` is byte-for-byte what the TSA hashed
(`erebus-log-checkpoint/v1`, log origin, tree size, root); `verify-evidence`
already refused the pack if it differs from the checkpoint signed in the
proof. The TSA time is an upper bound: the receipt existed, in a log of that
size, no later than that instant.

## 4. Check the signatures without erebus (optional)

Receipts are standard DSSE envelopes over in-toto statements, so Sigstore's
`cosign` verifies them against the bundle:

```bash
COSIGN_MAX_ATTACHMENT_SIZE=16GiB cosign verify-blob-attestation \
  --key ev/keys/operator/<fp>.pem \
  --signature ev/dsse/<receipt>.dsse.json \
  --type https://erebus.dev/attestation/execution/v2 \
  --insecure-ignore-tlog agent.erebus
# Verified OK
```

cosign refuses blobs over 128 MiB by default; bundles with embedded weights
are larger, hence `COSIGN_MAX_ATTACHMENT_SIZE`. `--insecure-ignore-tlog` only
means "not Sigstore's Rekor log": the erebus transparency log is checked in
step 2. Key files are named after the first 16 hex digits of the
fingerprint.

## 5. What you can and cannot conclude

With steps 1–3 green you can state, for each receipt: **this exact bundle
ran on this enrolled machine, for this operator, with these input and output
digests and exit code, and the record existed unmodified no later than the
TSA time.** For a served model, each receipt is one inference call with the
request and response digests.

You cannot conclude, from the pack alone:

- that the output is *correct* or the agent behaved well — see
  [What erebus proves](../concepts/proof.md);
- what the inputs and outputs *were* — receipts hold digests. For a served
  call, `input_hash` / `output_hash` are the SHA-256 of the request and
  response bodies: ask the operator for them and hash them yourself. For a
  batch run, `input_hash` covers the launch arguments, `stdin_hash` (when
  present) the whole piped stdin, and `output_hash` combines the stdout
  and stderr digests;
- that **no later** execution was left out. The chain proves nothing was
  removed *before* the head; runs after the head are only visible in the
  transparency log. To close that gap, ask the registry for the current
  checkpoint (`GET /log/checkpoint`) and the operator's records
  (`erebus attest-history`) for the period you audit, and compare counts;
- that the host was not root-compromised while running (the machine key is
  a software key; see the boundary page).

## Reference

- Pack layout: `trail/` (receipts, proofs, `HEAD`), `anchors/` (`.tsr`,
  `.checkpoint`), `dsse/`, `keys/operator/`, `keys/registry/`,
  `MANIFEST.json`, `README.txt`, optional `bundle/`.
- Receipt format: [Execution attestation — spec 2.0](../spec/attestation.md).
- Per-receipt verification: `erebus verify-attest <receipt> --strict --proof
  --log-key <hex> --bundle <file>`.
