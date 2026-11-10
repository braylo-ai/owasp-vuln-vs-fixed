"""Deliberately vulnerable / fixed Flask app for OWASP Top 10 demos.

One codebase, two modes. ``create_app("vulnerable")`` ships the bugs.
``create_app("fixed")`` ships the controls. Each route keeps both versions side
by side so a reader can diff the vulnerable line against the fixed line.

LOCAL USE ONLY. Never expose vulnerable mode on a network.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import sqlite3
import tempfile
import time
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    make_response,
    render_template_string,
    request,
    session,
)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

MODES = ("vulnerable", "fixed")

# Synthetic demo users. Passwords are fake and documented in README.
SEED_USERS = [
    # (id, username, password, balance)
    (1, "alice", "alice-pass-123", 1000),
    (2, "bob", "bob-pass-456", 500),
    (3, "admin", "Adm1n-demo-only!", 99999),
]
SEED_INVOICES = [
    # (id, owner_id, description, amount)
    (101, 1, "alice invoice: laptop", 1200),
    (102, 2, "bob invoice: monitor", 300),
    (103, 3, "admin invoice: server rack", 8000),
]

LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 300

PAGE = """<!doctype html><html><head><title>{{ title }}</title></head>
<body><h1>{{ title }}</h1>{{ body }}</body></html>"""


def _db_init(path: str, mode: str) -> None:
    con = sqlite3.connect(path)
    con.executescript(
        """
        DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS invoices;
        DROP TABLE IF EXISTS comments;
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                           password TEXT, balance INTEGER);
        CREATE TABLE invoices(id INTEGER PRIMARY KEY, owner_id INTEGER,
                              description TEXT, amount INTEGER);
        CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT);
        """
    )
    for uid, name, pw, bal in SEED_USERS:
        # Vulnerable mode stores plaintext (broken auth / crypto failure).
        stored = pw if mode == "vulnerable" else generate_password_hash(pw)
        con.execute("INSERT INTO users VALUES (?,?,?,?)", (uid, name, stored, bal))
    con.executemany("INSERT INTO invoices VALUES (?,?,?,?)", SEED_INVOICES)
    con.commit()
    con.close()


def is_safe_url(url: str) -> tuple[bool, str]:
    """SSRF guard used by fixed mode.

    Allow only http/https. Resolve the host. Reject the request when any
    resolved address is private, loopback, link-local, reserved or multicast.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "unparseable url"
    if parsed.scheme not in ("http", "https"):
        return False, f"scheme {parsed.scheme!r} not allowed"
    host = parsed.hostname
    if not host:
        return False, "missing host"
    try:
        infos = socket.getaddrinfo(host, parsed.port or 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, "host does not resolve"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False, f"address {ip} is internal"
    return True, "ok"


def create_app(mode: str = "vulnerable", db_path: str | None = None) -> Flask:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    app = Flask(__name__)
    app.config["MODE"] = mode
    fixed = mode == "fixed"

    if fixed:
        app.config["SECRET_KEY"] = os.environ.get(
            "APP_SECRET_KEY"
        ) or secrets.token_hex(32)
        app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Strict",
            SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        )
    else:
        # Hard-coded, guessable key: anyone can forge a session cookie.
        app.config["SECRET_KEY"] = "dev"
        app.config.update(SESSION_COOKIE_HTTPONLY=False, SESSION_COOKIE_SAMESITE=None)

    if db_path is None:
        fd, db_path = tempfile.mkstemp(suffix=".db", prefix=f"vulnapp-{mode}-")
        os.close(fd)
    app.config["DB_PATH"] = db_path
    _db_init(db_path, mode)

    failed_logins: dict[str, list[float]] = {}

    def db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def _close(_exc):
        con = g.pop("db", None)
        if con is not None:
            con.close()

    def current_user():
        uid = session.get("uid")
        if uid is None:
            return None
        return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if current_user() is None:
                abort(401)
            return fn(*a, **kw)

        return wrapper

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def check_csrf() -> None:
        if not fixed:
            return  # vulnerable: no CSRF check at all
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(403, "CSRF token missing or invalid")

    @app.after_request
    def headers(resp):
        if fixed:
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; object-src 'none'; "
                "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            )
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Permissions-Policy"] = (
                "geolocation=(), camera=(), microphone=()"
            )
            resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
            resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Server"] = "app"
        return resp

    # ---------------------------------------------------------------- index
    @app.get("/")
    def index():
        body = Markup(
            "<p>Mode: <b>{}</b></p><ul>"
            "<li>/search?q= (SQLi)</li><li>/greet?name= (reflected XSS)</li>"
            "<li>/comments (stored XSS)</li><li>/transfer (CSRF)</li>"
            "<li>/fetch?url= (SSRF)</li><li>/api/invoices/&lt;id&gt; (IDOR)</li>"
            "<li>/login (broken auth)</li></ul>"
        ).format(mode)
        return render_template_string(PAGE, title="OWASP vuln-vs-fixed", body=body)

    @app.get("/robots.txt")
    def robots():
        return app.response_class("User-agent: *\nDisallow:\n", mimetype="text/plain")

    @app.get("/sitemap.xml")
    def sitemap():
        return app.response_class(
            '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"/>',
            mimetype="application/xml",
        )

    # ------------------------------------------------------------- A03 SQLi
    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        if fixed:
            rows = (
                db()
                .execute("SELECT id, username FROM users WHERE username = ?", (q,))
                .fetchall()
            )
        else:
            # String concatenation -> classic SQL injection.
            sql = f"SELECT id, username FROM users WHERE username = '{q}'"
            try:
                rows = db().execute(sql).fetchall()
            except sqlite3.Error as e:  # leaks DB errors, as many real apps do
                return jsonify(error=str(e), sql=sql), 500
        return jsonify(results=[dict(r) for r in rows])

    # ------------------------------------------------------- A03 XSS (refl.)
    @app.get("/greet")
    def greet():
        name = request.args.get("name", "guest")
        if fixed:
            body = Markup("<p>Hello, {}!</p>").format(name)  # escapes `name`
        else:
            body = Markup(f"<p>Hello, {name}!</p>")  # marks raw input as safe
        return render_template_string(PAGE, title="Greet", body=body)

    # ------------------------------------------------------ A03 XSS (stored)
    @app.route("/comments", methods=["GET", "POST"])
    def comments():
        if request.method == "POST":
            check_csrf()
            db().execute(
                "INSERT INTO comments(body) VALUES (?)", (request.form.get("body", ""),)
            )
            db().commit()
        rows = db().execute("SELECT body FROM comments ORDER BY id").fetchall()
        if fixed:
            items = Markup("").join(
                Markup("<li>{}</li>").format(r["body"]) for r in rows
            )
            form = Markup(
                '<form method="post"><input type="hidden" name="csrf_token" value="{}">'
                '<input name="body"><button>Post</button></form>'
            ).format(csrf_token())
        else:
            items = Markup("".join(f"<li>{r['body']}</li>" for r in rows))
            form = Markup(
                '<form method="post"><input name="body"><button>Post</button></form>'
            )
        return render_template_string(
            PAGE, title="Comments", body=Markup("<ul>{}</ul>{}").format(items, form)
        )

    # ------------------------------------------- A07 broken authentication
    @app.post("/login")
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if fixed:
            now = time.time()
            recent = [
                t for t in failed_logins.get(username, []) if now - t < LOCKOUT_SECONDS
            ]
            failed_logins[username] = recent
            if len(recent) >= LOCKOUT_THRESHOLD:
                return jsonify(error="too many attempts, try later"), 429
            row = (
                db()
                .execute("SELECT * FROM users WHERE username=?", (username,))
                .fetchone()
            )
            # Constant work: hash check runs even for unknown users.
            stored = row["password"] if row else generate_password_hash("x")
            ok = check_password_hash(stored, password) and row is not None
            if not ok:
                failed_logins[username].append(now)
                return jsonify(error="invalid username or password"), 401
            session.clear()  # session fixation defence
            session["uid"] = row["id"]
            csrf_token()
            return jsonify(ok=True, user=row["username"])
        row = (
            db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        )
        if row is None:
            return jsonify(error="no such user"), 401  # user enumeration
        if row["password"] != password:  # plaintext compare, no lockout
            return jsonify(error="wrong password"), 401
        session["uid"] = row["id"]  # no session rotation
        resp = make_response(jsonify(ok=True, user=row["username"]))
        # Predictable "remember me" token: md5(username).
        resp.set_cookie("remember", hashlib.md5(username.encode()).hexdigest())
        return resp

    @app.get("/me")
    def me():
        user = current_user()
        if user is None and not fixed:
            # Vulnerable: trusts the predictable remember-me cookie.
            token = request.cookies.get("remember")
            if token:
                for r in db().execute("SELECT * FROM users").fetchall():
                    if hashlib.md5(r["username"].encode()).hexdigest() == token:
                        user = r
                        break
        if user is None:
            abort(401)
        return jsonify(
            id=user["id"], username=user["username"], balance=user["balance"]
        )

    @app.get("/csrf-token")
    @login_required
    def get_csrf():
        return jsonify(csrf_token=csrf_token())

    # ------------------------------------------------------------ A01 CSRF
    @app.post("/transfer")
    @login_required
    def transfer():
        check_csrf()
        to = request.form.get("to", "")
        amount = int(request.form.get("amount", "0"))
        user = current_user()
        if fixed and (amount <= 0 or amount > user["balance"]):
            return jsonify(error="invalid amount"), 400
        con = db()
        con.execute(
            "UPDATE users SET balance = balance - ? WHERE id=?", (amount, user["id"])
        )
        con.execute(
            "UPDATE users SET balance = balance + ? WHERE username=?", (amount, to)
        )
        con.commit()
        return jsonify(ok=True, new_balance=user["balance"] - amount)

    # ------------------------------------------------------------- A10 SSRF
    @app.get("/fetch")
    def fetch():
        url = request.args.get("url", "")
        if fixed:
            ok, reason = is_safe_url(url)
            if not ok:
                return jsonify(error=f"blocked: {reason}"), 400
            # No redirects: a public host must not bounce us to an internal one.
            r = requests.get(url, timeout=3, allow_redirects=False)
        else:
            if url.startswith("file://"):
                path = url[len("file://") :]
                with open(path, encoding="utf-8", errors="replace") as fh:
                    return jsonify(status=200, body=fh.read()[:2000])
            r = requests.get(url, timeout=3)
        return jsonify(status=r.status_code, body=r.text[:2000])

    # ------------------------------------------------------------- A01 IDOR
    @app.get("/api/invoices/<int:invoice_id>")
    @login_required
    def invoice(invoice_id: int):
        if fixed:
            row = (
                db()
                .execute(
                    "SELECT * FROM invoices WHERE id=? AND owner_id=?",
                    (invoice_id, current_user()["id"]),
                )
                .fetchone()
            )
            if row is None:
                abort(404)  # 404, not 403: do not confirm the id exists
        else:
            row = (
                db()
                .execute("SELECT * FROM invoices WHERE id=?", (invoice_id,))
                .fetchone()
            )
            if row is None:
                abort(404)
        return jsonify(dict(row))

    return app


def main() -> None:  # pragma: no cover - CLI entry
    mode = os.environ.get("APP_MODE", "vulnerable")
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "5000"))
    if mode == "fixed":
        # The dev server adds "Server: Werkzeug/x Python/y" after the app runs,
        # so after_request cannot hide it. Blank the version here (ZAP 10036).
        from werkzeug.serving import WSGIRequestHandler

        WSGIRequestHandler.server_version = "app"
        WSGIRequestHandler.sys_version = ""
    create_app(mode).run(host=host, port=port, debug=False)


if __name__ == "__main__":  # pragma: no cover
    main()
