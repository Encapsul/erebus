# Verify this receipt with cosign

Public files only. This directory has no private key.

`operator.pem` is the operator public key. `agent.dsse.json` is the DSSE
envelope from `erebus attest --envelope`. `agent.erebus` is the bundle those
bytes sign (built on macOS; cosign checks the file, it does not run it).

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
