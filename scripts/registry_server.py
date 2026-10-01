#!/usr/bin/env python3
"""erebus registry v2 — HTTP entry point. stdlib only.

Layout (ROADMAP P1-4):
  erebus_registry/util.py, artifacts.py, auth.py, store.py, http.py
  + proof core (ed25519, merkle, tsa, tlog)
This file wires CLI flags to Store + Handler and starts the server.
"""
import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from erebus_registry import http as http_mod  # noqa: E402
from erebus_registry.artifacts import (  # noqa: E402, F401
    artifact_lifecycle,
    parse_gguf,
    verify_gguf,
    verify_gguf_integrity,
    verify_integrity,
)
from erebus_registry.auth import (  # noqa: E402, F401
    _get_cached_discovery,
    _jwt_verify_id_token,
    _jwt_verify_rs256,
    stripe_api,
    verify_stripe_signature,
)
from erebus_registry.ed25519 import (  # noqa: E402, F401
    _ed25519_public_key,
    _ed25519_sign,
    _ed25519_verify,
)
from erebus_registry.http import Handler  # noqa: E402
from erebus_registry.merkle import (  # noqa: E402, F401
    _MerkleTree,
    _mt_consistency,
    _mt_inclusion,
    _mt_leaf,
    _mt_root,
    _mt_verify_inclusion,
)
from erebus_registry.store import Store  # noqa: E402
from erebus_registry.tlog import TransparencyLog, load_or_create_log_key  # noqa: E402
from erebus_registry.tsa import (  # noqa: E402, F401
    _TSA_SHA256_ALGID,
    _der,
    _der_int,
    tsa_build_request,
    tsa_parse_response,
)
from erebus_registry.util import (  # noqa: E402, F401
    CHUNK,
    EREBUS_MAGIC,
    MONTH_FMT,
    PAID_TIERS,
    REGISTRY_VERSION,
    ROLE_ORDER,
    SAFE_EMAIL,
    SAFE_FILE,
    SAFE_MONTH,
    SAFE_ORG,
    SAFE_PACK,
    SAFE_SIDECAR,
    SAFE_USER,
    SSO_CACHE_TTL,
    TIER_QUOTAS,
    WEEK_FMT,
    atomic_write,
    base64url_decode,
    month_now,
    week_now,
)

LANDING = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>erebus registry</title>
<style>
 body{{font-family:ui-monospace,Menlo,monospace;background:#0b0e14;color:#d7dce6;
      display:flex;flex-direction:column;align-items:center;padding:48px 16px;gap:28px}}
 h1{{color:#7ee0c3;font-size:26px}} .tag{{color:#5b6577}}
 .counters{{display:flex;gap:34px;text-align:center}}
 .num{{font-size:38px;color:#7ee0c3;font-weight:700}} .lbl{{color:#5b6577;font-size:12px}}
 form{{display:flex;gap:8px}} input{{background:#10162a;color:inherit;border:1px solid #1d2433;
      border-radius:8px;padding:11px 13px;font:inherit;width:280px}}
 button{{background:#173229;color:#7ee0c3;border:1px solid #245244;border-radius:8px;
      padding:0 18px;font:inherit;cursor:pointer}}
 code{{background:#10162a;padding:2px 6px;border-radius:4px}}
 a{{color:#7ee0c3}} #msg{{color:#5b6577;min-height:20px}}
</style></head><body>
<h1>erebus registry</h1>
<div class="tag">Your AI agent. One file. Runs anywhere.</div>
<div class="counters">
  <div><div class="num" id="saved">…</div><div class="lbl">GB SAVED BY DELTAS THIS WEEK</div></div>
  <div><div class="num" id="served">…</div><div class="lbl">GB SERVED</div></div>
  <div><div class="num" id="pulls">…</div><div class="lbl">PULLS</div></div>
</div>
<form onsubmit="join(event)"><input id="email" placeholder="you@company.com" autocomplete="email">
<button>Join the waitlist</button></form>
<div id="msg"></div>
<div class="tag">Open source · MIT —
<a href="https://github.com/Tednoob17/erebus">github.com/Tednoob17/erebus</a> ·
<a href="/ui/dashboard">Dashboard</a> · API: <code>/index.json</code> · <code>/packages/&lt;name&gt;</code></div>
<script>
async function refresh(){{
  try{{
    const s = await (await fetch('/stats')).json();
    saved.textContent = (s.bytes_saved/1e9).toFixed(2);
    served.textContent = (s.bytes_served/1e9).toFixed(2);
    pulls.textContent = s.pulls;
  }}catch(e){{}}
}}
function join(e){{
  e.preventDefault();
  fetch('/waitlist',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{email:document.getElementById('email').value}})}})
    .then(r=>r.json()).then(j=>{{msg.textContent=j.message||j.error;refresh();}})
    .catch(()=>msg.textContent='error');
}}
refresh(); setInterval(refresh, 30000);
</script></body></html>"""

DASHBOARD = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>erebus dashboard</title>
<style>
 body{{font-family:ui-monospace,Menlo,monospace;background:#0b0e14;color:#d7dce6;padding:32px}}
 h1{{color:#7ee0c3;font-size:22px;margin-bottom:24px}} a{{color:#7ee0c3}}
 table{{border-collapse:collapse;width:100%;max-width:1200px}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #1d2433}}
 th{{color:#5b6577;font-weight:600;font-size:12px;text-transform:uppercase}}
 tr:hover{{background:#10162a}} .tag{{color:#5b6577;font-size:12px}}
</style></head><body>
<h1>erebus registry — dashboard</h1>
<div class="tag"><a href="/">← landing</a> · <a href="/stats">/stats</a> · <a href="/index.json">/index.json</a></div>
<table>
<thead><tr><th>Name</th><th>Size</th><th>State</th><th>Integrity</th><th>Format</th><th>Private</th></tr></thead>
<tbody id="pkgs"></tbody>
</table>
<script>
async function load(){{
  const idx = await (await fetch('/index.json')).json();
  const tbody = document.getElementById('pkgs');
  tbody.innerHTML = '';
  for (const p of idx.packages) {{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${{p.name}}</td><td>${{(p.size/1024).toFixed(1)}} KB</td><td>${{p.state||'-'}}</td><td>${{p.integrity||'-'}}</td><td>${{p.format||'-'}}</td><td>${{p.private? 'yes' : 'no'}}</td>`;
    tbody.appendChild(tr);
  }}
}}
load(); setInterval(load, 30000);
</script></body></html>"""



# Inject pages into the http module (Handler renders them).
http_mod.LANDING = LANDING
http_mod.DASHBOARD = DASHBOARD

def main() -> None:
    ap = argparse.ArgumentParser(description="erebus registry v2")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--quota-gb", type=float, default=20.0,
                    help="monthly transfer quota for free-tier authenticated pulls")
    ap.add_argument("--upload-cap-gb", type=float, default=70.0,
                    help="hard cap on any single upload")
    ap.add_argument("--require-auth", action="store_true",
                    help="force strict auth: all uploads require a token, "
                         "even with --allow-anon-uploads")
    ap.add_argument("--allow-anon-uploads", action="store_true",
                    help="OPT-IN fail-open: permit anonymous uploads before the "
                         "first user registers. Off by default — the registry is "
                         "fail-closed, so mutations require auth unless this is set")
    ap.add_argument("--verify", action="store_true",
                    help="Run a one-shot integrity scan of all stored blobs and exit")
    ap.add_argument("--tls-cert",
                    help="path to TLS certificate file (PEM)")
    ap.add_argument("--tls-key",
                    help="path to TLS private key file (PEM)")
    ap.add_argument("--stripe-secret-key",
                    default=os.environ.get("STRIPE_SECRET_KEY"),
                    help="Stripe secret key (or STRIPE_SECRET_KEY env)")
    ap.add_argument("--stripe-webhook-secret",
                    default=os.environ.get("STRIPE_WEBHOOK_SECRET"),
                    help="Stripe webhook signing secret (or env)")
    ap.add_argument("--stripe-price-pro",
                    default=os.environ.get("STRIPE_PRICE_PRO"),
                    help="Stripe price ID for the Pro plan")
    ap.add_argument("--stripe-price-team",
                    default=os.environ.get("STRIPE_PRICE_TEAM"),
                    help="Stripe price ID for the Team plan")
    ap.add_argument("--billing-success-url",
                    default="https://registry.erebus.dev/billing/success",
                    help="redirect target after Stripe Checkout payment")
    ap.add_argument("--billing-cancel-url",
                    default="https://registry.erebus.dev/billing/cancelled",
                    help="redirect target after Checkout cancellation")
    # SSO (OIDC) options
    ap.add_argument("--sso-issuer",
                    help="OIDC issuer URL (e.g. https://accounts.google.com)")
    ap.add_argument("--sso-client-id", help="OIDC client ID")
    ap.add_argument("--sso-client-secret",
                    help="OIDC client secret (never logged)")
    ap.add_argument("--sso-provider", default="OIDC",
                    help="Display name for the SSO provider (default: OIDC)")
    ap.add_argument("--sso-base-url",
                    help="Public base URL of this registry (for redirect_uri)")
    # Transparency log (ROADMAP P0-5)
    ap.add_argument("--log-key",
                    help="Ed25519 seed (32 raw bytes, `erebus keygen` format) signing "
                         "log checkpoints; default <dir>/log.key, created 0600 if absent")
    ap.add_argument("--log-origin", default=None,
                    help="checkpoint origin string clients pin (default: erebus-registry)")
    ap.add_argument("--tsa-url",
                    help="RFC 3161 TSA URL used to anchor checkpoints "
                         "(e.g. https://freetsa.org/tsr); unset = no external anchoring")
    ap.add_argument("--anchor-every", type=int, default=10,
                    help="anchor the checkpoint at the TSA every N receipts (0 = manual "
                         "POST /log/anchor only)")
    args = ap.parse_args()

    if bool(args.tls_cert) != bool(args.tls_key):
        ap.error("--tls-cert and --tls-key must be used together")

    Handler.store = Store(
        args.dir, int(args.quota_gb * 1e9), int(args.upload_cap_gb * 1e9),
        require_auth=args.require_auth,
        allow_anon_uploads=args.allow_anon_uploads,
        log_key=args.log_key,
        log_origin=args.log_origin,
        tsa_url=args.tsa_url,
        anchor_every=args.anchor_every,
    )
    Handler.billing = {
        "secret_key": args.stripe_secret_key,
        "webhook_secret": args.stripe_webhook_secret,
        "price_pro": args.stripe_price_pro,
        "price_team": args.stripe_price_team,
        "success_url": args.billing_success_url,
        "cancel_url": args.billing_cancel_url,
    }
    # Initialize SSO config if provided
    if args.sso_issuer and args.sso_client_id and args.sso_client_secret:
        Handler.store.set_sso_config(
            args.sso_issuer,
            args.sso_client_id,
            args.sso_client_secret,
            args.sso_provider,
        )
        # Store base_url for redirect_uri construction
        if args.sso_base_url:
            cfg = Handler.store.get_sso_config()
            cfg["base_url"] = args.sso_base_url
            atomic_write(os.path.join(args.dir, "sso.json"), json.dumps(cfg).encode())
    class Server(ThreadingHTTPServer):
        # Default listen backlog is 5; fleet-style bursts of concurrent
        # pulls/uploads otherwise get connection resets.
        request_queue_size = 128
        daemon_threads = True

    server = Server((args.host, args.port), Handler)

    if args.tls_cert and args.tls_key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    elif args.host != "127.0.0.1":
        print(
            "WARNING: Serving on non-localhost without TLS. Tokens traverse "
            "plaintext. Use --tls-cert/--tls-key or a reverse proxy.",
            flush=True,
        )
        scheme = "http"
    else:
        scheme = "http"

    if args.verify:
        store = Handler.store
        print("Running integrity scan...", flush=True)
        snapshot = store.scan_integrity_locked()
        ok_count = sum(1 for v in snapshot.values() if v.get("ok"))
        bad_count = len(snapshot) - ok_count
        print(f"Scanned {len(snapshot)} blobs: {ok_count} ok, {bad_count} corrupt", flush=True)
        if bad_count > 0:
            print("Corrupt blobs:", flush=True)
            for name, info in snapshot.items():
                if not info.get("ok"):
                    print(f"  {name}: {info.get('detail')}", flush=True)
            raise SystemExit(1)
        raise SystemExit(0)

    bootstrap = Handler.store.bootstrap_open_uploads()
    billing_state = ("on" if Handler.billing.get("secret_key")
                     and Handler.billing.get("webhook_secret") else "off")
    # The bound port, not args.port: with --port 0 the OS picks a free one
    # and this line is how callers (tests, harnesses) learn it race-free.
    port = server.server_address[1]
    print(
        f"erebus registry v2 on {scheme}://{args.host}:{port} dir={args.dir} "
        f"quota={args.quota_gb}GB/month cap={args.upload_cap_gb}GB/upload "
        f"auth={'required (strict, --require-auth)' if args.require_auth else 'OPEN — anonymous uploads (opt-in --allow-anon-uploads)' if bootstrap else 'required (fail-closed by default)'} "
        f"billing={billing_state}",
        flush=True,
    )
    http_mod.START_TS = time.time()
    http_mod.STARTED_AT = datetime.now(timezone.utc).isoformat()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

