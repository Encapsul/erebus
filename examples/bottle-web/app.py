"""App web d'exemple avec une dépendance tierce (bottle).

`bottle` n'est PAS dans la stdlib. Prefer `requirements.txt` (pip at build) or
a vendored `site-packages/` / `.venv` install tree — erebus stages those into
`/app/site-packages` and sets PYTHONPATH.
"""

import os
import sys

from bottle import Bottle, response

app = Bottle()


@app.route("/")
def index():
    response.content_type = "text/html; charset=utf-8"
    return (
        "<!doctype html><html><head><meta charset=utf-8><title>erebus + bottle</title>"
        "</head><body style='font-family:system-ui;max-width:40rem;margin:4rem auto'>"
        "<h1>Hello from bottle, packagé par erebus 🍾</h1>"
        "<p>Ce serveur utilise <code>bottle</code>, une dépendance tierce "
        "embarquée depuis le .venv — pas la stdlib.</p>"
        f"<p>Python {sys.version.split()[0]} — PID {os.getpid()}</p>"
        "</body></html>"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"Server listening on http://127.0.0.1:{port}", flush=True)
    app.run(host="127.0.0.1", port=port, quiet=True)
