import secrets
import uuid
import threading
import time
from urllib.parse import urljoin, urlparse

from flask import Flask, abort, render_template, request

from bot import visit_url

app = Flask(__name__)

BASE_URL = "http://127.0.0.1:5000"
NOTES = {}

def _make_nonce():
    return secrets.token_urlsafe(16)


def _csp_header(nonce):
    return (
        "default-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "img-src 'self' data:; "
        "style-src 'self'; "
        "connect-src *; "
        f"script-src 'nonce-{nonce}' 'strict-dynamic'"
    )


def _normalize_target(input_url):
    if not input_url:
        return None
    if input_url.startswith("/"):
        return urljoin(BASE_URL, input_url)
    try:
        parsed = urlparse(input_url)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    return input_url


def _is_same_origin(target_url):
    parsed = urlparse(target_url)
    if parsed.scheme != "http":
        return False
    if parsed.hostname != "127.0.0.1":
        return False
    return parsed.port == 5000


@app.after_request
def add_csp(response):
    nonce = getattr(request, "csp_nonce", None)
    if nonce:
        response.headers["Content-Security-Policy"] = _csp_header(nonce)
    return response


@app.route("/")
def index():
    notes = sorted(NOTES.values(), key=lambda n: n["created_at"], reverse=True)
    return render_template("index.html", notes=notes)


@app.route("/note/new", methods=["GET", "POST"])
def new_note():
    nonce = _make_nonce()
    request.csp_nonce = nonce
    if request.method == "GET":
        return render_template("new_paste.html", nonce=nonce)

    title = request.form.get("title", "").strip() or "Untitled"
    body = request.form.get("body", "")
    note_id = uuid.uuid4().hex
    NOTES[note_id] = {
        "id": note_id,
        "title": title,
        "body": body,
        "created_at": time.time(),
    }
    return "", 302, {"Location": f"/note/{note_id}"}


@app.route("/note/<note_id>")
def preview(note_id):
    note = NOTES.get(note_id)
    if not note:
        abort(404)
    nonce = _make_nonce()
    request.csp_nonce = nonce
    return render_template("view.html", msg=note["body"], note=note, nonce=nonce)


@app.route("/telemetry/error-reporter.js")
def error_reporter():
    nonce = _make_nonce()
    request.csp_nonce = nonce
    body = (
        "(function(){"
        "var q=window._q=window._q||[];"
        "var d={t:'render_error',ts:Date.now(),p:location.pathname,m:String(window.lastRenderError||'')};"
        "q.push(d);"
        "try{"
        "fetch('/telemetry/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});"
        "}catch(e){}"
        "if(!window.__er){window.__er={v:'1.2.0'};}"
        "})();"
    )
    return app.response_class(body, mimetype="application/javascript")


@app.route("/telemetry/report", methods=["POST"])
def telemetry_report():
    return "", 204


@app.route("/report", methods=["GET", "POST"])
def report():
    nonce = _make_nonce()
    request.csp_nonce = nonce
    if request.method == "GET":
        return render_template("report.html", nonce=nonce)

    url = request.form.get("url", "")
    target = _normalize_target(url)
    if not target:
        abort(400)
    if not _is_same_origin(target):
        abort(400)

    thread = threading.Thread(target=visit_url, args=(target,), daemon=True)
    thread.start()
    return "Queued", 202


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
