# P3 Frontends

Protocol adapters that translate external registry APIs into erebus registry calls.

All frontends are stdlib-only Python servers. They run alongside (or in front of) the
erebus registry and translate protocol-specific requests to erebus REST calls.

## Frontends

| Script | Protocol | Port | Description |
|---|---|---|---|
| `s3_frontend.py` | S3-compatible | 9000 | List/Get/Put/Head objects via S3 REST API |
| `hf_frontend.py` | HuggingFace Hub | 8081 | Minimal HF Hub API (`/api/models/*`) |
| `oci_frontend.py` | OCI Distribution (Docker) | 5000 | Docker-compatible registry v2 |
| `lfs_frontend.py` | Git LFS | 8082 | Batch download/upload by SHA-256 OID |
| `bazel_frontend.py` | Bazel HTTP remote cache | 8083 | CAS + action cache GET/PUT |

## Usage

```bash
# Start the erebus registry first (on 127.0.0.1:8080)
python3 scripts/registry_server.py --dir /opt/erebus-registry/data --host 127.0.0.1 --port 8080 &

# Start one or more frontends
python3 scripts/frontends/s3_frontend.py --registry http://127.0.0.1:8080 --port 9000 &
python3 scripts/frontends/hf_frontend.py --registry http://127.0.0.1:8080 --port 8081 &
python3 scripts/frontends/oci_frontend.py --registry http://127.0.0.1:8080 --port 5000 &
python3 scripts/frontends/lfs_frontend.py --registry http://127.0.0.1:8080 --port 8082 &
python3 scripts/frontends/bazel_frontend.py --registry http://127.0.0.1:8080 --port 8083 &
```

## Authentication

All frontends forward `Authorization` headers to the erebus registry:

- `Bearer <token>` — erebus bearer token (preferred)
- `AWS <key>:<secret>` — S3-style auth; only the key portion is forwarded

## Notes

- Frontends are MIT, like the rest of erebus.
- They do NOT implement the full spec of each protocol — just enough for
  `huggingface-cli`, `docker`, `git lfs`, `bazel`, and boto3/SDK clients to work.
- Private packages require auth; public packages are readable without a token.
