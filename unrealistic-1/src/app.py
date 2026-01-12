import os
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import json
import jwt
from flask import (
    Flask,
    abort,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from urllib.parse import unquote_plus

DB_PATH = "/app/db/app.db"
COOKIE_NAME_SESSION = "session"
COOKIE_NAME_MOTD = "motd"

def get_main_origin():
    host = request.host.rsplit(':', 1)[0]
    scheme = request.scheme
    return f"{scheme}://{host}:5000"

def get_motd_origin():
    host = request.host.rsplit(':', 1)[0]
    scheme = request.scheme
    return f"{scheme}://{host}:5001"

def _read_flag_file(name: str) -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        secret = secrets.token_urlsafe(64)
        os.environ["JWT_SECRET"] = secret
    return secret


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_nonce() -> str:
    return secrets.token_urlsafe(18)


def _is_loopback(ip: Optional[str]) -> bool:
    return ip in {"127.0.0.1", "::1"}


def get_db() -> sqlite3.Connection:
    conn = getattr(g, "_db", None)
    if conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g._db = conn
    return conn


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()


def get_user_by_username(username: str):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id: int):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(username: str, password: str) -> int:
    db = get_db()
    password_hash = generate_password_hash(password)
    created_at = int(time.time())
    cur = db.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, created_at),
    )
    db.commit()
    return int(cur.lastrowid)


def create_message(user_id: int, body: str) -> str:
    db = get_db()
    message_id = str(uuid.uuid4())
    created_at = int(time.time())
    db.execute(
        "INSERT INTO messages (id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
        (message_id, user_id, body, created_at),
    )
    db.commit()
    return message_id


def list_messages_for_user(user_id: int):
    db = get_db()
    return db.execute(
        "SELECT id, created_at FROM messages WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()


def get_message_for_user(user_id: int, message_id: str):
    db = get_db()
    return db.execute(
        "SELECT id, body, created_at FROM messages WHERE id = ? AND user_id = ?",
        (message_id, user_id),
    ).fetchone()


def delete_message_for_user(user_id: int, message_id: str) -> bool:
    db = get_db()
    cur = db.execute(
        "DELETE FROM messages WHERE id = ? AND user_id = ?", (message_id, user_id)
    )
    db.commit()
    return cur.rowcount == 1


def issue_session_cookie(response, user_id: int, extra_claims: Optional[Dict[str, Any]] = None):
    now = _utcnow()
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=2)).timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(payload, _jwt_secret(), algorithm="HS256")
    response.set_cookie(
        COOKIE_NAME_SESSION,
        token,
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/",
    )


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        session = _parse_session()
        if not session:
            return redirect(url_for("login", next=request.path))
        g.session = session
        g.user_id = int(session["sub"])
        return fn(*args, **kwargs)

    return wrapper


def _parse_session() -> Optional[Dict[str, Any]]:
    token = request.cookies.get(COOKIE_NAME_SESSION)
    if not token:
        return None
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except Exception:
        return None


def require_api_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        session = _parse_session()
        if not session:
            abort(403)
        g.session = session
        g.user_id = int(session["sub"])
        return fn(*args, **kwargs)

    return wrapper


app = Flask(__name__, template_folder="templates", static_folder="static")
motd_app = Flask("motd_app", template_folder="templates", static_folder="static")


def _inject_common_template_vars():
    session = _parse_session()
    current_username = None
    if session is not None:
        try:
            user = get_user_by_id(int(session.get("sub")))
            if user is not None:
                current_username = user["username"]
        except Exception:
            current_username = None

    return {
        "authenticated": session is not None,
        "session": session,
        "current_username": current_username,
    }


@app.context_processor
def _inject_auth_state():
    return _inject_common_template_vars()


@motd_app.context_processor
def _inject_auth_state_motd():
    return _inject_common_template_vars()

@app.before_request
def _attach_nonce():
    g.csp_nonce = _new_nonce()


@motd_app.before_request
def _attach_nonce_motd():
    g.csp_nonce = _new_nonce()


@app.after_request
def _set_security_headers(resp):
    if not resp.headers.get("Content-Security-Policy"):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "base-uri 'none'; "
            f"script-src 'unsafe-inline';"
            "style-src 'self'; "
        )
    return resp

@app.teardown_appcontext
def _close_db(_exc):
    conn = getattr(g, "_db", None)
    if conn is not None:
        conn.close()


@app.get("/")
def index():
    session = _parse_session()
    user = None
    if session:
        user = get_user_by_id(int(session["sub"]))
    return render_template("index.html", user=user)


@app.get("/register")
def register():
    return render_template("register.html")


@app.post("/register")
def register_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not username or not password:
        return render_template("register.html", error="Missing username/password"), 400
    if username.lower() == "admin":
        return render_template("register.html", error="Username not allowed"), 400
    if get_user_by_username(username):
        return render_template("register.html", error="Username already exists"), 400

    user_id = create_user(username, password)
    resp = make_response(redirect(url_for("inbox")))
    issue_session_cookie(resp, user_id)
    return resp


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    user = get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error="Invalid credentials"), 403

    resp = make_response(redirect(url_for("inbox")))
    issue_session_cookie(resp, int(user["id"]))
    return resp


@app.get("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie(COOKIE_NAME_SESSION, path="/")
    return resp


@app.get("/motd")
def motd_redirect():
    return redirect(f"{get_motd_origin()}/motd", code=302)


@motd_app.get("/motd")
def motd():
    flag2 = _read_flag_file("flag2.txt") if _is_loopback(request.remote_addr) else None
    raw_motd = request.cookies.get(COOKIE_NAME_MOTD)
    motd_text = (
        unquote_plus(raw_motd)
        if raw_motd is not None
        else '"Go Go Squid! is peak fiction" - Sun Tzu'
    )
    resp = make_response(render_template("motd.html", motd=motd_text, flag=flag2))
    if request.cookies.get(COOKIE_NAME_MOTD) is None:
        resp.set_cookie(
            COOKIE_NAME_MOTD,
            motd_text,
            httponly=True,
            samesite="Lax",
            secure=False,
            path="/motd",
        )
    resp.headers["Content-Type"] = "text/html"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; img-src http: https:; style-src 'self';"
    return resp

@motd_app.route(
    "/",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
@motd_app.route(
    "/<path:path>",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
def motd_fallback(path: str):
    target = f"{get_main_origin()}{request.path}"
    qs = request.query_string.decode("utf-8", errors="ignore")
    if qs:
        target = f"{target}?{qs}"

    code = 302 if request.method in {"GET", "HEAD"} else 307
    return redirect(target, code=code)

@app.get("/inbox")
@require_login
def inbox():
    resp = make_response(render_template("inbox.html"))
    nonce = g.csp_nonce
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}';"
        "style-src 'self'; "
        "connect-src 'self';"
    )
    return resp


@app.get("/compose")
@require_login
def compose():
    return render_template("compose.html")


@app.post("/compose")
@require_login
def compose_post():
    to_username = (request.form.get("to") or "").strip()
    body = request.form.get("body") or ""
    if not to_username or not body:
        return render_template("compose.html", error="Missing to/body"), 400
    user = get_user_by_username(to_username)
    if not user:
        return render_template("compose.html", error="Recipient not found"), 404

    message_id = create_message(int(user["id"]), body)
    resp = make_response(json.dumps({"id": message_id}), 303)
    resp.headers["Location"] = url_for("inbox")
    resp.mimetype = "application/json"
    return resp


@app.get("/api/messages")
@require_api_auth
def api_messages():
    if request.headers.get("X-Server-Function") != "read":
        return make_response("Invalid X-Server-Function", 400)
    rows = list_messages_for_user(g.user_id)
    return json.dumps(
        {
            "messages": [
                {"id": r["id"], "created_at": r["created_at"]} for r in rows
            ]
        }
    )


@app.route("/api/messages/<message_id>", methods=["GET"]) 
@require_api_auth
def api_message(message_id: str):
    if request.headers.get("X-Server-Function") == "read":
        row = get_message_for_user(g.user_id, message_id)
        if not row:
            abort(404)
        resp = make_response(json.dumps({"id": row["id"], "body": row["body"], "created_at": row["created_at"]}))
    elif request.headers.get("X-Server-Function") == "delete":
        ok = delete_message_for_user(g.user_id, message_id)
        resp = make_response(json.dumps({"deleted": ok}))
    else:
        abort(400)
    return resp


@app.get("/flag")
def flag():
    session = _parse_session()
    if not session:
        abort(403)
    if not _is_loopback(request.remote_addr):
        abort(403)

    flag = _read_flag_file("flag1.txt")
    resp = make_response("OK")
    issue_session_cookie(resp, int(session["sub"]), extra_claims={"flag": flag})
    return resp


def _validate_bot_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://127.0.0.1:5000"):
        raise ValueError("URL must start with http://127.0.0.1:5000")
    return url

@app.get("/bot")
def bot_page():
    return render_template("bot.html")

@app.post("/bot")
def bot_post():
    target = request.form.get("url") or ""
    try:
        target = _validate_bot_url(target)
    except ValueError as e:
        return render_template("bot.html", error=str(e)), 400

    try:
        from bot_runner import run_admin_bot
        run_admin_bot(target)
    except Exception as e:
        return render_template("bot.html", error=f"Bot failed: {e}"), 500

    return render_template("bot.html", ok=True)

def init() -> None:
    os.environ["ADMIN_PASSWORD"] = secrets.token_urlsafe(32)
    os.environ["JWT_SECRET"] = secrets.token_urlsafe(64)
    app.config["JWT_SECRET"] = os.environ["JWT_SECRET"]
    motd_app.config["JWT_SECRET"] = os.environ["JWT_SECRET"]

    init_db()
    admin = get_user_by_username("admin")
    password_hash = generate_password_hash(os.environ["ADMIN_PASSWORD"])
    print(f"Admin credentials: admin / {os.environ['ADMIN_PASSWORD']}")
    created_at = int(time.time())
    db = get_db()
    if admin:
        db.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (password_hash, "admin"),
        )
    else:
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", password_hash, created_at),
        )
    db.commit()


with app.app_context():
    init()


if __name__ == "__main__":
    import threading

    def _run_motd_server():
        motd_app.run(host="0.0.0.0", port=5001, debug=False, use_reloader=False, threaded=True)

    t = threading.Thread(target=_run_motd_server, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True)
