# Self-hosted trust center (MVP)

This is the **self-hosted** trust center: a thin product surface on the existing
stdlib registry. It is not a hosted SaaS, and the hosted trust center remains
unshipped and paid. There is no control mapping and no retention policy engine
yet. The registry already owns users, orgs, tokens, the Merkle transparency log,
signed checkpoints, inclusion proofs, the audit trail and admin backup/restore;
the trust center adds projects, API keys, receipt intake, status, search, share
links and evidence export on top of those primitives.

Start it with a pinned log origin and an out-of-band admin account:

```bash
mkdir -p /var/lib/erebus-registry
ERE_ADMIN_USERS=admin python3 scripts/registry_server.py \
  --dir /var/lib/erebus-registry --host 0.0.0.0 --port 8787 \
  --log-origin my-trust-center --tsa-url https://freetsa.org/tsr
```

Use `--tls-cert` / `--tls-key` or terminate TLS in front of it. Pin
`--log-origin` and the public key from `GET /log/key`: a verifier must trust the
log key out of band, not read it from the same server it is verifying.

## Flow

1. Register a user and create a project with one or more **operator public
   keys** (32-byte Ed25519 hex). Only DSSE/JCS spec 2.x receipts signed under
   those keys are accepted.

   ```bash
   curl -sS -X POST http://localhost:8787/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"a-long-password"}'
   # -> {"username":"alice","token":"..."}

   curl -sS -X POST http://localhost:8787/trust/projects \
     -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
     -d '{"org":"alice","name":"pilot","trusted_keys":["<operator public key hex>"]}'
   # -> {"id":"alice/pilot","project":{...},"origin":"my-trust-center"}
   ```

2. Create a project API key for the agent that posts receipts. The token is
   shown once; store it as `Bearer tc:<token>`.

   ```bash
   curl -sS -X POST http://localhost:8787/trust/projects/alice/pilot/keys \
     -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
     -d '{"label":"agent"}'
   # -> {"key_id":"...","token":"..."}
   ```

3. Post the **exact receipt bytes**. The trust center checks the DSSE signature
   under a pinned key, that the signed statement's execution/artifact fields
   match the receipt, that `prev_attestation_hash` equals the `sha256:<hex>` of
   the previous receipt in this project, then anchors the same bytes in the
   Merkle log. A wrong predecessor or a foreign key is rejected (409 / 400).

   ```bash
   curl -sS -X POST http://localhost:8787/trust/receipts \
     -H 'Authorization: Bearer tc:<api token>' \
     -H 'Content-Type: application/json' --data-binary @receipt.json
   # -> {"id":"...","status":"verified","log":{...},
   #     "verify_url":"http://localhost:8787/verify/<id>"}
   ```

4. Search and inspect. A user token works when `?project=` is supplied; an API
   key is scoped to its project. Filters: `id`, `bundle`, `machine`, `status`,
   `since`, `until`, `limit`, `skip`.

   ```bash
   curl -sS 'http://localhost:8787/trust/receipts?project=alice%2Fpilot&status=verified&limit=20' \
     -H 'Authorization: Bearer <token>'
   curl -sS http://localhost:8787/trust/status   # no account needed
   ```

## Status meaning

| Status | Meaning |
|---|---|
| `verified` | DSSE/JCS signature under a pinned project key, correct project chain link, and Merkle inclusion under a checkpoint signed by the pinned log key all re-check from stored bytes. |
| `missing` | No stored/logged receipt for this id. |
| `failed` | A proof, signature or chain check failed. |

`verified` says **this receipt is authentic and logged**. It does not say every
execution was captured. See
[What erebus proves — and what it does not](../concepts/proof.md).

## Sharing and evidence export

Create a capability link for one receipt. The token is shown once; anyone with
the link can verify without an erebus account.

```bash
curl -sS -X POST http://localhost:8787/trust/receipts/<id>/share \
  -H 'Authorization: Bearer <token>'
# -> {"url":"http://localhost:8787/verify/<id>?token=<secret>"}
```

`GET /verify/<id>?token=<secret>` returns an HTML page; append `&format=json`
for the JSON view with the receipt id, status, log origin, trusted key
fingerprints and log key. Omitting or guessing the token returns 404.

A project export is a zip with `manifest.json`, original `receipts/<id>.json`
and `proofs/<id>.proof.json` files in the shape accepted by
`erebus verify-attest --proof-file` / `erebus verify-evidence`:

```bash
curl -sS 'http://localhost:8787/trust/evidence?project=alice%2Fpilot' \
  -H 'Authorization: Bearer <token>' -o evidence.zip
```

A person holding a receipt share link can download a one-receipt pack from
`/public/evidence/<id>?token=<secret>`. Verify offline with the **pinned** log
public key, not one fetched from the same server:

```bash
erebus verify-attest receipts/<id>.json \
  --proof-file proofs/<id>.proof.json --log-key <log public key hex>
```

## Backup and restore

`GET /admin/backup` (admin token only) returns the registry manifest with a
`trust_center` object: project/key/receipt/share state plus the exact receipt
bytes. `POST /admin/restore` accepts that manifest. Restore re-appends receipts
to the transparency log, so run it on a fresh registry state with the **same
`log.key`** and the same `ERE_ADMIN_USERS`. Keep `log.key` and `users.json`
outside the export; the manifest says so explicitly. Package blobs are backed
up separately by the existing `/admin/backup` flow.

This is an MVP restore path, not a full disaster-recovery or high-availability
story: there is no replication quorum, no retention enforcement, and no hosted
operator on call.

## Limits of the MVP

- Self-hosted only. The hosted trust center is a paid surface and is not shipped.
- No control mapping (EU AI Act, SOC 2, ISO 42001); that remains the compliance
  team's work, fed by the evidence pack.
- No claim of complete capture. Use the attested gateway, signed launch policy,
  heartbeat receipts, `COVERAGE.json` and `erebus monitor` for the separate
  completeness question; even those do not see traffic that never reached the
  gateway.
- The public verification link is a bearer capability: treat it as a secret and
  revoke it by rebuilding share state if it leaks.
- Intake accepts spec 2.x DSSE/JCS receipts only; legacy 1.x receipts stay
  verifiable in the CLI but are not ingested by this endpoint.
