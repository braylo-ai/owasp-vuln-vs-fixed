"""Each OWASP issue gets two kinds of test.

* ``vulnerable`` mode: the exploit must WORK (proves the bug is real).
* ``fixed`` mode: the same exploit must be BLOCKED (proves the control works).

All targets are local: the Flask test client and a throwaway HTTP server on
127.0.0.1 that plays the "internal service" for SSRF.
"""

from __future__ import annotations

import hashlib
import http.server
import threading

import pytest

from vulnapp.app import create_app, is_safe_url

INTERNAL_SECRET = "INTERNAL-ONLY-metadata-token-FAKE"


@pytest.fixture
def vuln(tmp_path):
    app = create_app("vulnerable", db_path=str(tmp_path / "v.db"))
    return app.test_client()


@pytest.fixture
def fixed(tmp_path):
    app = create_app("fixed", db_path=str(tmp_path / "f.db"))
    return app.test_client()


def login(client, user="alice", pw="alice-pass-123"):
    return client.post("/login", data={"username": user, "password": pw})


@pytest.fixture(scope="module")
def internal_server():
    """A loopback-only HTTP server that stands in for an internal service."""

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(INTERNAL_SECRET.encode())

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/latest/meta-data"
    srv.shutdown()


# ----------------------------------------------------------------- SQLi
SQLI_DUMP = "' OR '1'='1"
SQLI_UNION = "x' UNION SELECT id, password FROM users --"


def test_sqli_tautology_dumps_all_users_vulnerable(vuln):
    r = vuln.get("/search", query_string={"q": SQLI_DUMP})
    assert r.status_code == 200
    assert len(r.json["results"]) == 3


def test_sqli_union_leaks_passwords_vulnerable(vuln):
    r = vuln.get("/search", query_string={"q": SQLI_UNION})
    leaked = {row["username"] for row in r.json["results"]}
    assert "alice-pass-123" in leaked  # plaintext password came back


def test_sqli_error_leaks_query_vulnerable(vuln):
    r = vuln.get("/search", query_string={"q": "'"})
    assert r.status_code == 500 and "SELECT" in r.json["sql"]


@pytest.mark.parametrize("payload", [SQLI_DUMP, SQLI_UNION, "'"])
def test_sqli_blocked_fixed(fixed, payload):
    r = fixed.get("/search", query_string={"q": payload})
    assert r.status_code == 200
    assert r.json["results"] == []


def test_search_still_works_fixed(fixed):
    r = fixed.get("/search", query_string={"q": "bob"})
    assert r.json["results"] == [{"id": 2, "username": "bob"}]


# ------------------------------------------------------------------ XSS
XSS = "<script>alert(document.domain)</script>"


def test_reflected_xss_vulnerable(vuln):
    r = vuln.get("/greet", query_string={"name": XSS})
    assert XSS in r.get_data(as_text=True)


def test_reflected_xss_escaped_fixed(fixed):
    body = fixed.get("/greet", query_string={"name": XSS}).get_data(as_text=True)
    assert XSS not in body
    assert "&lt;script&gt;" in body


def test_stored_xss_vulnerable(vuln):
    vuln.post("/comments", data={"body": '<img src=x onerror="alert(1)">'})
    body = vuln.get("/comments").get_data(as_text=True)
    assert '<img src=x onerror="alert(1)">' in body


def test_stored_xss_escaped_fixed(fixed):
    page = fixed.get("/comments").get_data(as_text=True)
    token = page.split('name="csrf_token" value="')[1].split('"')[0]
    fixed.post(
        "/comments",
        data={"body": '<img src=x onerror="alert(1)">', "csrf_token": token},
    )
    body = fixed.get("/comments").get_data(as_text=True)
    assert "<img src=x" not in body and "&lt;img" in body


def test_csp_header_present_fixed_absent_vulnerable(vuln, fixed):
    assert "Content-Security-Policy" not in vuln.get("/").headers
    csp = fixed.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp


# ----------------------------------------------------------------- CSRF
def test_csrf_transfer_without_token_succeeds_vulnerable(vuln):
    login(vuln)
    # A forged cross-site form post carries the cookie but no token.
    r = vuln.post(
        "/transfer",
        data={"to": "bob", "amount": "900"},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 200 and r.json["new_balance"] == 100


def test_csrf_transfer_without_token_blocked_fixed(fixed):
    login(fixed)
    r = fixed.post("/transfer", data={"to": "bob", "amount": "900"})
    assert r.status_code == 403
    assert fixed.get("/me").json["balance"] == 1000


def test_csrf_transfer_with_wrong_token_blocked_fixed(fixed):
    login(fixed)
    r = fixed.post(
        "/transfer", data={"to": "bob", "amount": "1", "csrf_token": "guess"}
    )
    assert r.status_code == 403


def test_csrf_transfer_with_valid_token_allowed_fixed(fixed):
    login(fixed)
    tok = fixed.get("/csrf-token").json["csrf_token"]
    r = fixed.post("/transfer", data={"to": "bob", "amount": "10", "csrf_token": tok})
    assert r.status_code == 200 and r.json["new_balance"] == 990


def test_negative_transfer_steals_money_vulnerable_blocked_fixed(vuln, fixed):
    login(vuln, "bob", "bob-pass-456")
    assert (
        vuln.post("/transfer", data={"to": "alice", "amount": "-5000"}).json[
            "new_balance"
        ]
        == 5500
    )
    login(fixed, "bob", "bob-pass-456")
    tok = fixed.get("/csrf-token").json["csrf_token"]
    r = fixed.post(
        "/transfer", data={"to": "alice", "amount": "-5000", "csrf_token": tok}
    )
    assert r.status_code == 400


def test_session_cookie_flags(vuln, fixed):
    v = login(vuln).headers.get("Set-Cookie", "")
    f = login(fixed).headers.get("Set-Cookie", "")
    assert "HttpOnly" not in v
    assert "HttpOnly" in f and "SameSite=Strict" in f


# ----------------------------------------------------------------- SSRF
def test_ssrf_reaches_internal_service_vulnerable(vuln, internal_server):
    r = vuln.get("/fetch", query_string={"url": internal_server})
    assert INTERNAL_SECRET in r.json["body"]


def test_ssrf_file_scheme_reads_local_file_vulnerable(vuln, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("FAKE-LOCAL-FILE-SECRET")
    r = vuln.get("/fetch", query_string={"url": f"file://{secret}"})
    assert "FAKE-LOCAL-FILE-SECRET" in r.json["body"]


def test_ssrf_internal_service_blocked_fixed(fixed, internal_server):
    r = fixed.get("/fetch", query_string={"url": internal_server})
    assert r.status_code == 400 and INTERNAL_SECRET not in r.get_data(as_text=True)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:80/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://2130706433/",  # 127.0.0.1 in decimal
        "http://[::1]/",
        "http://10.0.0.5/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ],
)
def test_ssrf_bypass_variants_blocked_fixed(fixed, url):
    r = fixed.get("/fetch", query_string={"url": url})
    assert r.status_code == 400, url


def test_is_safe_url_allows_public_ip_literal():
    # Unit-level check only: no request is sent.
    assert is_safe_url("https://93.184.216.34/")[0] is True


# ----------------------------------------------------------------- IDOR
def test_idor_read_other_users_invoice_vulnerable(vuln):
    login(vuln)  # alice
    r = vuln.get("/api/invoices/103")  # admin's invoice
    assert r.status_code == 200 and r.json["owner_id"] == 3


def test_idor_blocked_fixed(fixed):
    login(fixed)
    assert fixed.get("/api/invoices/103").status_code == 404
    assert fixed.get("/api/invoices/102").status_code == 404


def test_idor_own_invoice_allowed_fixed(fixed):
    login(fixed)
    assert fixed.get("/api/invoices/101").json["owner_id"] == 1


def test_idor_requires_login_both_modes(vuln, fixed):
    assert vuln.get("/api/invoices/101").status_code == 401
    assert fixed.get("/api/invoices/101").status_code == 401


# ---------------------------------------------------------- broken auth
def test_user_enumeration_vulnerable(vuln):
    a = login(vuln, "nobody", "x").json["error"]
    b = login(vuln, "alice", "x").json["error"]
    assert a != b  # attacker learns which usernames exist


def test_user_enumeration_blocked_fixed(fixed):
    a = login(fixed, "nobody", "x").json["error"]
    b = login(fixed, "alice", "x").json["error"]
    assert a == b


def test_no_lockout_brute_force_vulnerable(vuln):
    guesses = [f"wrong{i}" for i in range(20)] + ["alice-pass-123"]
    codes = [login(vuln, "alice", g).status_code for g in guesses]
    assert codes[-1] == 200  # 20 failures, then success: no throttling


def test_lockout_after_5_failures_fixed(fixed):
    codes = [login(fixed, "alice", f"wrong{i}").status_code for i in range(5)]
    assert codes == [401] * 5
    assert login(fixed).status_code == 429  # even the right password waits


def test_predictable_remember_cookie_forges_admin_vulnerable(vuln):
    vuln.set_cookie("remember", hashlib.md5(b"admin").hexdigest())
    r = vuln.get("/me")
    assert r.status_code == 200 and r.json["username"] == "admin"


def test_forged_remember_cookie_ignored_fixed(fixed):
    fixed.set_cookie("remember", hashlib.md5(b"admin").hexdigest())
    assert fixed.get("/me").status_code == 401


def test_hardcoded_secret_key_allows_session_forgery_vulnerable(tmp_path):
    from flask.sessions import SecureCookieSessionInterface

    app = create_app("vulnerable", db_path=str(tmp_path / "s.db"))
    # Attacker knows the key "dev" and signs their own session.
    attacker = create_app("vulnerable", db_path=str(tmp_path / "a.db"))
    serializer = SecureCookieSessionInterface().get_signing_serializer(attacker)
    forged = serializer.dumps({"uid": 3})
    c = app.test_client()
    c.set_cookie("session", forged)
    assert c.get("/me").json["username"] == "admin"


def test_session_forgery_fails_fixed(tmp_path):
    from flask import Flask
    from flask.sessions import SecureCookieSessionInterface

    app = create_app("fixed", db_path=str(tmp_path / "s.db"))
    attacker = Flask("x")
    attacker.secret_key = "dev"
    forged = (
        SecureCookieSessionInterface()
        .get_signing_serializer(attacker)
        .dumps({"uid": 3})
    )
    c = app.test_client()
    c.set_cookie("session", forged)
    assert c.get("/me").status_code == 401


def test_passwords_hashed_at_rest_fixed_plaintext_vulnerable(tmp_path):
    import sqlite3

    create_app("vulnerable", db_path=str(tmp_path / "v.db"))
    create_app("fixed", db_path=str(tmp_path / "f.db"))
    v = (
        sqlite3.connect(tmp_path / "v.db")
        .execute("SELECT password FROM users WHERE id=1")
        .fetchone()[0]
    )
    f = (
        sqlite3.connect(tmp_path / "f.db")
        .execute("SELECT password FROM users WHERE id=1")
        .fetchone()[0]
    )
    assert v == "alice-pass-123"
    assert f != "alice-pass-123" and f.startswith(("scrypt:", "pbkdf2:"))


def test_session_rotated_on_login_fixed(fixed):
    fixed.get("/")
    with fixed.session_transaction() as s:
        s["planted"] = "attacker-fixation-value"
    login(fixed)
    with fixed.session_transaction() as s:
        assert "planted" not in s
