import os, re, time, uuid, hashlib, sqlite3, functools, secrets, json, html, io, hmac, math
from datetime import datetime, timedelta
from collections import defaultdict
import urllib.request, urllib.error

# ── Server-side session interface ──────────────────────────────────────────
# Replaces Flask's default cookie-based sessions with DB-backed sessions.
# The browser only gets a small random session_id cookie (≤64 bytes).
# This eliminates "Request Header Fields Too Large" errors caused by
# oversized signed-cookie sessions.
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict

class _DbSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        def on_update(self): self.modified = True
        super().__init__(initial or {}, on_update)
        self.sid      = sid
        self.new      = new
        self.modified = False

class _DbSessionInterface(SessionInterface):
    _TABLE = "flask_sessions"
    SESSION_COOKIE = "dn_sid"
    LIFETIME       = 7200   # seconds — matches PERMANENT_SESSION_LIFETIME

    # ── DB helpers (re-use the app's SQLite file) ──────────────────────────
    @staticmethod
    def _conn(app):
        path = app.config["DATABASE"]
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @classmethod
    def _ensure_table(cls, app):
        with cls._conn(app) as db:
            db.execute(f"""
                CREATE TABLE IF NOT EXISTS {cls._TABLE} (
                    sid     TEXT PRIMARY KEY,
                    data    TEXT NOT NULL DEFAULT '{{}}',
                    expires INTEGER NOT NULL
                )
            """)
            db.execute(f"CREATE INDEX IF NOT EXISTS idx_ses_exp ON {cls._TABLE}(expires)")
            db.commit()

    @classmethod
    def _load(cls, app, sid):
        with cls._conn(app) as db:
            row = db.execute(
                f"SELECT data,expires FROM {cls._TABLE} WHERE sid=?", (sid,)
            ).fetchone()
        if not row:
            return None
        if row["expires"] < int(time.time()):
            cls._delete(app, sid)
            return None
        try:
            return json.loads(row["data"])
        except Exception:
            return {}

    @classmethod
    def _save(cls, app, sid, data, expires):
        with cls._conn(app) as db:
            db.execute(
                f"INSERT OR REPLACE INTO {cls._TABLE} (sid,data,expires) VALUES (?,?,?)",
                (sid, json.dumps(data), expires)
            )
            db.commit()

    @classmethod
    def _delete(cls, app, sid):
        with cls._conn(app) as db:
            db.execute(f"DELETE FROM {cls._TABLE} WHERE sid=?", (sid,))
            db.commit()

    @classmethod
    def _purge(cls, app):
        """Delete expired sessions — called occasionally."""
        with cls._conn(app) as db:
            db.execute(f"DELETE FROM {cls._TABLE} WHERE expires<?", (int(time.time()),))
            db.commit()

    # ── Flask SessionInterface API ─────────────────────────────────────────
    def open_session(self, app, request):
        sid = request.cookies.get(self.SESSION_COOKIE)
        if sid and len(sid) <= 128:
            data = self._load(app, sid)
            if data is not None:
                return _DbSession(data, sid=sid)
        # New session
        new_sid = secrets.token_urlsafe(48)
        return _DbSession(sid=new_sid, new=True)

    def save_session(self, app, session, response):
        domain   = self.get_cookie_domain(app)
        path     = self.get_cookie_path(app)
        httponly = self.get_cookie_httponly(app)
        samesite = self.get_cookie_samesite(app)
        secure   = self.get_cookie_secure(app)

        if not session:
            if not session.new:
                self._delete(app, session.sid)
                response.delete_cookie(self.SESSION_COOKIE, domain=domain, path=path)
            return

        expires = int(time.time()) + self.LIFETIME
        # Occasional cleanup (roughly 1% of saves)
        if secrets.randbelow(100) == 0:
            try: self._purge(app)
            except Exception: pass

        self._save(app, session.sid, dict(session), expires)
        response.set_cookie(
            self.SESSION_COOKIE,
            session.sid,
            max_age   = self.LIFETIME,
            httponly  = httponly,
            samesite  = samesite,
            secure    = secure,
            domain    = domain,
            path      = path,
        )

def _rotate_session() -> None:
    """Regenerate session ID on privilege escalation (login) to prevent session fixation.
    Copies all existing session data into a brand-new session ID.
    The old session row is deleted from the DB on the next save_session call.
    """
    old_data = dict(session)
    old_sid  = getattr(session, "sid", None)
    # Delete old session from DB immediately
    if old_sid:
        try:
            db = get_db()
            db.execute(f"DELETE FROM {_DbSessionInterface._TABLE} WHERE sid=?", (old_sid,))
            db.commit()
        except Exception:
            pass
    # Assign new SID and mark session as modified
    session.sid      = secrets.token_urlsafe(48)
    session.new      = True
    session.modified = True
    # Restore data
    session.update(old_data)

from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect,
                   url_for, abort, g, session, make_response, send_from_directory)
from werkzeug.middleware.proxy_fix import ProxyFix
from markupsafe import Markup

# ── Bootstrap ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

for d in ("instance", "static/uploads", "static/avatars"):
    os.makedirs(os.path.join(BASE_DIR, d), exist_ok=True)

def _admin_path() -> tuple[str, str]:
    """Admin URL parts from .env, or a random pair saved in instance/ (never a value from the code)."""
    pre = os.environ.get("DNet_ADMIN_PREFIX", "").strip("/")
    suf = os.environ.get("DNet_ADMIN_SUFFIX", "").strip("/")
    if pre and suf:
        return pre, suf
    kf = os.path.join(BASE_DIR, "instance", ".admin_path")
    if os.path.exists(kf):
        parts = open(kf).read().split()
        if len(parts) == 2:
            return parts[0], parts[1]
    pre, suf = secrets.token_urlsafe(12), secrets.token_urlsafe(12)
    with open(kf, "w") as fh:
        fh.write(f"{pre} {suf}\n")
    os.chmod(kf, 0o600)
    return pre, suf

ADMIN_PREFIX, ADMIN_SUFFIX = _admin_path()

# ── FiroGate payment config ────────────────────────────────────────────────
FIROGATE_API_KEY        = os.environ.get("FIROGATE_API_KEY", "")
FIROGATE_WEBHOOK_SECRET = os.environ.get("FIROGATE_WEBHOOK_SECRET", "")
FIROGATE_BASE_URL       = os.environ.get("FIROGATE_BASE_URL", "https://api.firogate.com")
FIROGATE_ONION_URL      = os.environ.get("FIROGATE_ONION_URL", "")   # optional .onion endpoint
FIROGATE_USE_TOR        = os.environ.get("FIROGATE_USE_TOR", "0") == "1"
FIROGATE_TOR_PROXY      = os.environ.get("FIROGATE_TOR_PROXY", "socks5h://127.0.0.1:9050")
FIROGATE_VERIFY_AMOUNT  = float(os.environ.get("FIROGATE_VERIFY_AMOUNT", "3.99"))
FIROGATE_TIMEOUT_MIN    = int(os.environ.get("FIROGATE_TIMEOUT_MIN", "20"))

ALL_ROLES = ["Owner", "Admin", "Moderator", "Support", "Hacktivist",
             "Reporter", "Editor", "Analyst", "Correspondent", "Guest"]
DEFAULT_AUTHOR = "GateForum"

# ── Admin password (PBKDF2-HMAC-SHA256) ───────────────────────────────────
# DNet_ADMIN_HASH format: pbkdf2$<iterations>$<hex_salt>$<hex_dk>
# Generated by setup_password.py — never store plaintext passwords.

def _pbkdf2_hash(pw: str, salt: bytes | None = None, iterations: int = 600_000) -> str:
    """Return a storable hash string for pw."""
    if salt is None:
        salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"

def check_admin_password(pw: str) -> bool:
    stored = os.environ.get("DNet_ADMIN_HASH", "")
    if not stored or not stored.startswith("pbkdf2$"):
        return False
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        candidate = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, int(iters))
        return hmac.compare_digest(expected, candidate)
    except Exception:
        return False

# ── Persistent SECRET_KEY ──────────────────────────────────────────────────
def _secret_key() -> bytes:
    ev = os.environ.get("DNet_SECRET", "")
    if ev and len(ev) >= 32:
        return ev.encode()
    kf = os.path.join(BASE_DIR, "instance", ".secret_key")
    if os.path.exists(kf):
        k = open(kf, "rb").read()
        if len(k) >= 32:
            return k
    k = secrets.token_bytes(48)
    open(kf, "wb").write(k)
    os.chmod(kf, 0o600)
    return k

SECRET_KEY = _secret_key()

# ── Flask ──────────────────────────────────────────────────────────────────
app = Flask(__name__, instance_path=os.path.join(BASE_DIR, "instance"))
app.config.update(
    SECRET_KEY              = SECRET_KEY,
    DATABASE                = os.path.join(BASE_DIR, "instance", "DNet.db"),
    UPLOAD_FOLDER           = os.path.join(BASE_DIR, "static", "uploads"),
    AVATAR_FOLDER           = os.path.join(BASE_DIR, "static", "avatars"),
    MAX_CONTENT_LENGTH      = 20 * 1024 * 1024,
    ALLOWED_EXTENSIONS      = {"png","jpg","jpeg","gif","webp"},
    MAX_IMAGES_PER_POST     = 6,
    SINGLE_IMAGE_MAX        = 5  * 1024 * 1024,
    AVATAR_MAX              = 2  * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    SESSION_COOKIE_SECURE   = False,
    PERMANENT_SESSION_LIFETIME = 7200,
)
# Use DB-backed sessions — cookie is a 64-byte random ID only, never bloated
_ses_iface = _DbSessionInterface()
_ses_iface._ensure_table(app)   # create table before first request
app.session_interface = _ses_iface
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# ── Magic-byte validation ──────────────────────────────────────────────────
_MAGIC = [(b"\xff\xd8\xff","jpg"),(b"\x89PNG\r\n\x1a\n","png"),
          (b"GIF87a","gif"),(b"GIF89a","gif")]

def _real_ext(data: bytes):
    for sig, ext in _MAGIC:
        if data[:len(sig)] == sig: return ext
    if len(data)>=12 and data[:4]==b"RIFF" and data[8:12]==b"WEBP": return "webp"
    return None

def _valid_image(data: bytes, declared: str) -> bool:
    r = _real_ext(data)
    if r is None: return False
    if declared in ("jpg","jpeg"): return r == "jpg"
    return r == declared

# ── Rate limiters ──────────────────────────────────────────────────────────
_rl_page     = defaultdict(list)
_rl_login    = defaultdict(list)
_rl_search   = defaultdict(list)
_rl_upload   = defaultdict(list)
_rl_post     = defaultdict(list)   # POST flood guard
_rl_register = defaultdict(list)   # registration flood guard
_rl_webhook  = defaultdict(list)   # webhook endpoint guard
_rl_pay      = defaultdict(list)   # payment-creation flood guard (per token)
_rl_status   = defaultdict(list)   # payment status polling guard (per token)

def _chk(store, ip, limit, window) -> bool:
    now = time.time(); cut = now - window
    store[ip] = [t for t in store[ip] if t > cut]
    if len(store[ip]) >= limit: return True
    store[ip].append(now); return False

# ── CSRF protection ────────────────────────────────────────────────────────
def _csrf_token() -> str:
    """Return (and create if missing) a per-session CSRF token."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]

def _csrf_ok() -> bool:
    """Validate CSRF token from POST form data."""
    expected = session.get("csrf")
    submitted = request.form.get("_csrf", "")
    if not expected or not submitted:
        return False
    return hmac.compare_digest(expected, submitted)

app.jinja_env.globals["csrf_token"] = _csrf_token

# ── Security headers ───────────────────────────────────────────────────────
@app.after_request
def _sec(r):
    h = r.headers
    h["X-Frame-Options"]        = "DENY"
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"]        = "no-referrer"
    h["Permissions-Policy"]     = "geolocation=(), camera=(), microphone=()"

    # Allow inline scripts only on /verify/success (polling) and admin pages
    # All other pages get script-src 'none'
    p = request.path
    if p.startswith("/verify/") or p.startswith("/" + ADMIN_PREFIX):
        script_src = "script-src 'self' 'unsafe-inline'"
    else:
        script_src = "script-src 'self' 'unsafe-inline'"  # allow inline JS site-wide (chat, etc.)

    h["Content-Security-Policy"] = (
        f"default-src 'self'; img-src 'self' data: blob:; "
        f"style-src 'self' 'unsafe-inline'; "
        f"{script_src}; "
        f"object-src 'none'; frame-ancestors 'none'; base-uri 'self';"
    )
    h.pop("Server", None)
    h.pop("X-Powered-By", None)

    if "/static/uploads/" in p or "/static/avatars/" in p:
        h["Cache-Control"] = "private, no-store"
    elif r.status_code == 200 and ("/static/css/" in p or "/static/fonts/" in p or "/static/js/" in p):
        h["Cache-Control"] = "public, max-age=86400"
    else:
        h["Cache-Control"] = "no-store"
    return r

# ── Attack / DDoS guard ────────────────────────────────────────────────────
# On Tor all requests appear from 127.0.0.1; we fingerprint by
# header patterns, payload signatures, and request-rate anomalies.

_BAD_UA = [
    "sqlmap","nikto","masscan","zgrab","nmap","python-requests","curl","wget",
    "scrapy","go-http","libwww","headless","phantomjs","semrush","ahrefsbot",
    "mj12bot","dotbot","dirbuster","gobuster","wfuzz","nuclei","acunetix",
    "hydra","medusa","burpsuite","zap","w3af","openvas","nessus","shodan",
]
_BAD_PATHS = [
    "/.env","/.git","/wp-","/phpmyadmin","/admin.php","/shell","/.htaccess",
    "/xmlrpc","/cgi-bin","/boaform","/GponForm","/.well-known/acme",
    "/backup","/db","/database","/config","/.bash","/proc/","/etc/passwd",
    "/bin/sh","/var/www","/usr/bin","/setup.php","/install.php",
]
_BAD_REFERERS = ["masscan","burpsuite","sqlmap"]

# Suspicious header combinations (no-JS browser fingerprints for scanners)
def _header_anomaly() -> bool:
    ua  = request.headers.get("User-Agent", "")
    acc = request.headers.get("Accept", "")

    # Tor Browser intentionally strips Accept-Language and limits headers
    # to prevent fingerprinting — never flag it as an anomaly.
    is_tor_like = (
        request.remote_addr in ("127.0.0.1", "::1")
        or ".onion" in (request.host or "")
        or not request.headers.get("Accept-Language")  # Tor strips this
    )
    if is_tor_like:
        # Still block if Accept is completely missing (raw scanner, not browser)
        if request.method == "GET" and not acc:
            return True
        return False

    # Real clearnet browsers always send Accept
    if request.method == "GET" and not acc:
        return True
    # Clearnet: no Accept-Language is suspicious
    if request.method == "GET" and not request.headers.get("Accept-Language"):
        if request.remote_addr not in ("127.0.0.1", "::1"):
            return True
    # Suspiciously short UA
    if ua and len(ua) < 10:
        return True
    return False

# Payload inspection — only catches unambiguous server-side injection.
# Does NOT flag common words like eval(), exec(), base64, system that
# appear legitimately in news articles and code tutorials.
_INJECT_RE = re.compile(
    r"(<script[\s>]|javascript:\s*[a-z]|onerror\s*=|onload\s*=|"
    r"union\s+all\s+select|union\s+select\s+null|"
    r"\.\./\.\./|%2e%2e%2f|"
    r"cmd\.exe|/bin/sh\s|/bin/bash\s|"
    r"(?:passthru|shell_exec|popen)\s*\()",
    re.IGNORECASE
)

def _payload_suspicious(data: str) -> bool:
    return bool(_INJECT_RE.search(data))

@app.before_request
def _detect_network():
    """
    Detect whether the current request came via Tor (.onion) or clearnet.
    Stored in flask.g for use anywhere in the request lifecycle.
    """
    host = (request.host or "").lower()
    g.via_tor   = host.endswith(".onion") or host in ("127.0.0.1", "::1")
    g.site_host = host

def _client_key() -> str:
    """Rate-limit key. Behind Tor every visitor is 127.0.0.1, so use the session cookie there."""
    ip = request.remote_addr or "unknown"
    if ip in ("127.0.0.1", "::1"):
        sid = request.cookies.get("dn_sid") or request.cookies.get("dn_token") or ""
        if sid:
            return "s:" + hashlib.sha256(sid.encode()).hexdigest()[:24]
        return "loopback"
    return ip

@app.before_request
def _guard():
    ip = _client_key()

    # Webhook endpoint: skip browser-oriented guards; use dedicated rate limiting
    if request.path == "/webhook/firogate":
        if _chk(_rl_webhook, ip, 30, 60):
            abort(429)
        return

    # Global page rate limit (the shared cookieless Tor bucket gets more room)
    if _chk(_rl_page, ip, 1500 if ip == "loopback" else 150, 60):
        abort(429)

    # POST flood guard (separate tighter limit)
    if request.method == "POST":
        if _chk(_rl_post, ip, 30, 60):
            abort(429)

    # Block bad paths
    p = request.path.lower()
    for bp in _BAD_PATHS:
        if p.startswith(bp):
            abort(403)

    # Block scanner user-agents
    ua = (request.headers.get("User-Agent") or "").lower()
    if not ua.strip():
        abort(403)
    for f in _BAD_UA:
        if f in ua:
            abort(403)

    # Header anomaly detection
    if _header_anomaly():
        abort(403)

    # Check Referer for scanner signatures
    ref = (request.headers.get("Referer") or "").lower()
    for br in _BAD_REFERERS:
        if br in ref:
            abort(403)

    # Oversized Content-Length
    cl = request.content_length
    if cl and cl > app.config["MAX_CONTENT_LENGTH"]:
        abort(413)

    # Payload injection check on form data (non-file, non-admin POST only)
    if request.method == "POST" and request.content_type and \
       "multipart" not in request.content_type and \
       not session.get("admin"):
        raw = request.get_data(as_text=True, cache=True)[:4096]
        if _payload_suspicious(raw):
            abort(403)

# ── Database ───────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"],
                               detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA cache_size=-8000")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def _close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS authors (
            id       TEXT PRIMARY KEY,
            name     TEXT NOT NULL UNIQUE,
            avatar   TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            role_badge TEXT NOT NULL DEFAULT '',
            created  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS posts (
            id        TEXT PRIMARY KEY,
            title     TEXT NOT NULL,
            body      TEXT NOT NULL,
            images    TEXT NOT NULL DEFAULT '[]',
            author    TEXT NOT NULL DEFAULT 'GateForum',
            role      TEXT NOT NULL DEFAULT '',
            views     INTEGER NOT NULL DEFAULT 0,
            pinned    INTEGER NOT NULL DEFAULT 0,
            created   TEXT NOT NULL,
            edited    TEXT NOT NULL DEFAULT '',
            token_id  TEXT NOT NULL DEFAULT '',
            author_id TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_pc ON posts(created DESC);
        CREATE INDEX IF NOT EXISTS idx_pp ON posts(pinned DESC, created DESC);
        CREATE TABLE IF NOT EXISTS tokens (
            id            TEXT PRIMARY KEY,
            label         TEXT NOT NULL,
            token_hash    TEXT NOT NULL UNIQUE,
            allowed_roles TEXT NOT NULL DEFAULT '',
            note          TEXT NOT NULL DEFAULT '',
            created       TEXT NOT NULL,
            revoked       INTEGER NOT NULL DEFAULT 0,
            is_pool       INTEGER NOT NULL DEFAULT 0,
            pool_token    TEXT NOT NULL DEFAULT '',
            claimed       INTEGER NOT NULL DEFAULT 0,
            claimed_at    TEXT NOT NULL DEFAULT '',
            claimed_by    TEXT NOT NULL DEFAULT '',
            claimed_name  TEXT NOT NULL DEFAULT '',
            claimed_avatar TEXT NOT NULL DEFAULT '',
            verified      INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS activity_log (
            id      TEXT PRIMARY KEY,
            action  TEXT NOT NULL,
            detail  TEXT NOT NULL DEFAULT '',
            ts      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS firo_payments (
            id           TEXT PRIMARY KEY,
            token_id     TEXT NOT NULL,
            order_id     TEXT NOT NULL UNIQUE,
            amount_firo  REAL NOT NULL DEFAULT 3.99,
            status       TEXT NOT NULL DEFAULT 'pending',
            checkout_url TEXT NOT NULL DEFAULT '',
            created      TEXT NOT NULL,
            confirmed_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_firo_token ON firo_payments(token_id);
        CREATE INDEX IF NOT EXISTS idx_firo_order ON firo_payments(order_id);
        CREATE TABLE IF NOT EXISTS webhook_nonces (
            nonce TEXT PRIMARY KEY,
            seen  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS products (
            id          TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            summary     TEXT NOT NULL DEFAULT '',
            body        TEXT NOT NULL DEFAULT '',
            price_firo  REAL NOT NULL,
            image       TEXT NOT NULL DEFAULT '',
            file_name   TEXT NOT NULL DEFAULT '',
            file_label  TEXT NOT NULL DEFAULT '',
            file_size   INTEGER NOT NULL DEFAULT 0,
            secret_text TEXT NOT NULL DEFAULT '',
            active      INTEGER NOT NULL DEFAULT 1,
            sales       INTEGER NOT NULL DEFAULT 0,
            created     TEXT NOT NULL,
            updated     TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_prod_active ON products(active, created DESC);
        CREATE TABLE IF NOT EXISTS purchases (
            id          TEXT PRIMARY KEY,
            product_id  TEXT NOT NULL,
            token_id    TEXT NOT NULL,
            payment_id  TEXT NOT NULL DEFAULT '',
            amount_firo REAL NOT NULL DEFAULT 0,
            txid        TEXT NOT NULL DEFAULT '',
            created     TEXT NOT NULL,
            UNIQUE(product_id, token_id)
        );
        CREATE INDEX IF NOT EXISTS idx_purchase_tok ON purchases(token_id);
        CREATE TABLE IF NOT EXISTS product_ratings (
            product_id TEXT NOT NULL,
            token_id   TEXT NOT NULL,
            stars      INTEGER NOT NULL,
            note       TEXT NOT NULL DEFAULT '',
            created    TEXT NOT NULL,
            updated    TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (product_id, token_id)
        );
        CREATE TABLE IF NOT EXISTS chat (
            id          TEXT PRIMARY KEY,
            message     TEXT NOT NULL,
            image       TEXT NOT NULL DEFAULT '',
            nickname    TEXT NOT NULL,
            is_token    INTEGER NOT NULL DEFAULT 0,
            token_id    TEXT NOT NULL DEFAULT '',
            reply_to    TEXT NOT NULL DEFAULT '',
            reply_to_nick TEXT NOT NULL DEFAULT '',
            replied     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_chat_created ON chat(created_at DESC);

        CREATE TABLE IF NOT EXISTS post_reactions (
            id         TEXT PRIMARY KEY,
            post_id    TEXT NOT NULL,
            ip_hash    TEXT NOT NULL,
            token_hash TEXT NOT NULL DEFAULT '',
            reaction   TEXT NOT NULL,
            created    TEXT NOT NULL DEFAULT '',
            UNIQUE(post_id, ip_hash, reaction)
        );
        CREATE INDEX IF NOT EXISTS idx_react_post ON post_reactions(post_id);

        CREATE TABLE IF NOT EXISTS post_reports (
            id         TEXT PRIMARY KEY,
            post_id    TEXT NOT NULL,
            ip_hash    TEXT NOT NULL,
            reason     TEXT NOT NULL DEFAULT '',
            created    TEXT NOT NULL DEFAULT '',
            resolved   INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_report_post    ON post_reports(post_id);
        CREATE INDEX IF NOT EXISTS idx_report_resolved ON post_reports(resolved);

        CREATE TABLE IF NOT EXISTS post_views (
            post_id    TEXT NOT NULL,
            sid_hash   TEXT NOT NULL,
            created    TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (post_id, sid_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_pv_post ON post_views(post_id);
    """)
    # FTS5 virtual table for full-text search
    try:
        db.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts
            USING fts5(title, body, content=posts, content_rowid=rowid,
                       tokenize='unicode61')
        """)
        db.execute("""
            CREATE TRIGGER IF NOT EXISTS posts_fts_insert AFTER INSERT ON posts BEGIN
                INSERT INTO posts_fts(rowid, title, body)
                VALUES (new.rowid, new.title, new.body);
            END
        """)
        db.execute("""
            CREATE TRIGGER IF NOT EXISTS posts_fts_delete AFTER DELETE ON posts BEGIN
                INSERT INTO posts_fts(posts_fts, rowid, title, body)
                VALUES ('delete', old.rowid, old.title, old.body);
            END
        """)
        db.execute("""
            CREATE TRIGGER IF NOT EXISTS posts_fts_update AFTER UPDATE ON posts BEGIN
                INSERT INTO posts_fts(posts_fts, rowid, title, body)
                VALUES ('delete', old.rowid, old.title, old.body);
                INSERT INTO posts_fts(rowid, title, body)
                VALUES (new.rowid, new.title, new.body);
            END
        """)
        db.commit()
        # Rebuild FTS index for existing posts
        db.execute("INSERT INTO posts_fts(posts_fts) VALUES ('rebuild')")
        db.commit()
    except Exception:
        pass  # FTS5 not available — graceful fallback to LIKE search
    # Safe column migrations
    migs = [
        ("authors", "verified",     "INTEGER NOT NULL DEFAULT 0"),
        ("authors", "role_badge",   "TEXT NOT NULL DEFAULT ''"),
        ("posts",   "edited",       "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "allowed_roles","TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "note",         "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "author_id",    "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "default_role", "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "is_pool",      "INTEGER NOT NULL DEFAULT 0"),
        ("tokens",  "pool_token",   "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "claimed",      "INTEGER NOT NULL DEFAULT 0"),
        ("tokens",  "claimed_at",   "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "claimed_by",   "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "claimed_name", "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "claimed_avatar", "TEXT NOT NULL DEFAULT ''"),
        ("tokens",  "verified",     "INTEGER NOT NULL DEFAULT 0"),
        ("posts",   "images",       "TEXT NOT NULL DEFAULT '[]'"),
        ("posts",   "author",       "TEXT NOT NULL DEFAULT 'GateForum'"),
        ("posts",   "role",         "TEXT NOT NULL DEFAULT ''"),
        ("posts",   "views",        "INTEGER NOT NULL DEFAULT 0"),
        ("posts",   "pinned",       "INTEGER NOT NULL DEFAULT 0"),
        ("posts",   "token_id",     "TEXT NOT NULL DEFAULT ''"),
        ("posts",   "author_id",    "TEXT NOT NULL DEFAULT ''"),
        ("chat",    "reply_to_nick","TEXT NOT NULL DEFAULT ''"),
        ("firo_payments", "confirmed_at", "TEXT NOT NULL DEFAULT ''"),
        ("firo_payments", "txid",         "TEXT NOT NULL DEFAULT ''"),
        ("firo_payments", "fg_payment_id", "TEXT NOT NULL DEFAULT ''"),
        ("firo_payments", "expires_at",    "TEXT NOT NULL DEFAULT ''"),
        ("firo_payments", "amount_received", "REAL NOT NULL DEFAULT 0"),
        ("firo_payments", "refunded_at",   "TEXT NOT NULL DEFAULT ''"),
        ("firo_payments", "kind",          "TEXT NOT NULL DEFAULT 'verify'"),
        ("firo_payments", "product_id",    "TEXT NOT NULL DEFAULT ''"),
        ("posts", "reaction_fire",   "INTEGER NOT NULL DEFAULT 0"),
        ("posts", "reaction_skull",  "INTEGER NOT NULL DEFAULT 0"),
        ("posts", "reaction_eye",    "INTEGER NOT NULL DEFAULT 0"),
        ("posts", "reaction_bolt",   "INTEGER NOT NULL DEFAULT 0"),
        ("post_reactions", "token_hash", "TEXT NOT NULL DEFAULT ''"),
    ]
    for tbl, col, defn in migs:
        try:
            db.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {defn}")
            db.commit()
        except Exception:
            pass
    db.execute("DROP TABLE IF EXISTS likes")
    # Old image migration
    try:
        rows = db.execute(
            "SELECT id,image FROM posts WHERE image IS NOT NULL"
            " AND image!='' AND (images IS NULL OR images='[]')"
        ).fetchall()
        for row in rows:
            db.execute("UPDATE posts SET images=? WHERE id=?",
                       (json.dumps([row["image"]]), row["id"]))
        db.commit()
    except Exception:
        pass
    # Default author
    if not db.execute("SELECT id FROM authors WHERE name='GateForum'").fetchone():
        db.execute(
            "INSERT INTO authors (id,name,avatar,verified,role_badge,created) VALUES (?,?,?,0,'',?)",
            (uuid.uuid4().hex, "GateForum", "",
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
    # Default settings
    for k, v in [("site_title","GateForum"),("site_tagline","Independent · Anonymous · Uncensored"),
                 ("posts_per_page","10"),("maintenance","0"),
                 ("shop_enabled","1"),("shop_visibility","everyone")]:
        db.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)", (k, v))
    db.commit()

with app.app_context():
    init_db()

# ── Settings helper ────────────────────────────────────────────────────────
def get_setting(key: str, default: str = "") -> str:
    db  = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, value))
    db.commit()

# ── Activity log ───────────────────────────────────────────────────────────
def log_action(action: str, detail: str = ""):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO activity_log (id,action,detail,ts) VALUES (?,?,?,?)",
            (uuid.uuid4().hex, action[:60], detail[:200],
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        # Keep only last 200 entries
        db.execute(
            "DELETE FROM activity_log WHERE id NOT IN "
            "(SELECT id FROM activity_log ORDER BY ts DESC LIMIT 200)"
        )
        db.commit()
    except Exception:
        app.logger.warning("Failed to write action_log: %s", detail[:80])

# ── Auth helpers ───────────────────────────────────────────────────────────
def _hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()

def _get_token_row(tok: str):
    if not tok or len(tok) > 200: return None
    return get_db().execute(
        "SELECT * FROM tokens WHERE token_hash=? AND revoked=0",
        (_hash_token(tok),)
    ).fetchone()

def _current_tok():
    return _get_token_row(request.cookies.get("dn_token",""))

def _is_admin() -> bool:
    return bool(session.get("admin"))

def _is_contributor() -> bool:
    return _current_tok() is not None

def require_admin(view):
    @functools.wraps(view)
    def w(*a, **kw):
        if not _is_admin(): return redirect(url_for("admin_login"))
        return view(*a, **kw)
    return w

def require_poster(view):
    @functools.wraps(view)
    def w(*a, **kw):
        if _is_admin() or _is_contributor(): return view(*a, **kw)
        return redirect(url_for("token_login"))
    return w

# ── Token role helpers ─────────────────────────────────────────────────────
def token_roles(tok_row) -> list:
    """Return list of roles allowed for this token. Empty = all roles."""
    if not tok_row: return ALL_ROLES
    raw = tok_row["allowed_roles"].strip()
    if not raw: return ALL_ROLES
    allowed = [r.strip() for r in raw.split(",") if r.strip() in ALL_ROLES]
    return allowed if allowed else ALL_ROLES

# ── Author helpers ─────────────────────────────────────────────────────────
def _author_by_name(name: str):
    return get_db().execute("SELECT * FROM authors WHERE name=?", (name,)).fetchone()

def _author_by_id(aid: str):
    if not aid: return None
    return get_db().execute("SELECT * FROM authors WHERE id=?", (aid,)).fetchone()

def _enrich(post) -> dict:
    try:   imgs = json.loads(post["images"])
    except Exception: imgs = []
    ar = _author_by_id(post["author_id"]) or _author_by_name(post["author"])
    tok_verified = False
    tok_avatar   = ""
    if post["token_id"]:
        db  = get_db()
        tok = db.execute(
            "SELECT verified, claimed_avatar FROM tokens WHERE id=?",
            (post["token_id"],)
        ).fetchone()
        if tok:
            tok_verified = bool(tok["verified"])
            tok_avatar   = tok["claimed_avatar"] or ""

    # Realistic read time — 200 wpm, round up to nearest even number
    words    = len(post["body"].split())
    raw_mins = words / 200
    if raw_mins <= 1:
        rt = 1
    elif raw_mins <= 2:
        rt = 2
    else:
        # Round up to next even: 3→4, 5→6, 7→8, 9→10...
        rt = math.ceil(raw_mins / 2) * 2

    return {
        "post": post, "imgs": imgs, "author_row": ar,
        "rt": rt, "tok_verified": tok_verified, "tok_avatar": tok_avatar
    }

# ── Sidebar ────────────────────────────────────────────────────────────────
def _sidebar(db) -> dict:
    return {
        "top_posts":   db.execute("SELECT id,title,views FROM posts ORDER BY views DESC LIMIT 5").fetchall(),
        "latest":      db.execute("SELECT id,title,created FROM posts ORDER BY created DESC LIMIT 5").fetchall(),
        "total_posts": db.execute("SELECT COUNT(*) FROM posts").fetchone()[0],
        "total_views": db.execute("SELECT COALESCE(SUM(views),0) FROM posts").fetchone()[0],
        "site_title":  get_setting("site_title","GateForum"),
        "site_tagline":get_setting("site_tagline",""),
    }

# ── File helpers ───────────────────────────────────────────────────────────
def _save_file(data: bytes, ext: str, folder: str, prefix: str = "") -> str | None:
    name = f"{prefix}{uuid.uuid4().hex}.{ext}"
    dest = os.path.join(folder, name)
    if not os.path.realpath(dest).startswith(os.path.realpath(folder)):
        return None
    open(dest, "wb").write(data)
    return name

def process_post_image(data: bytes) -> bytes:
    """Strip ALL metadata, re-encode as JPEG — post images."""
    Image.MAX_IMAGE_PIXELS = 20_000_000   # ~4472x4472 — prevents decompression bombs
    img = Image.open(io.BytesIO(data))
    if img.mode in ("RGBA", "P", "LA"):
        bg  = Image.new("RGB", img.size, (0, 0, 0))
        src = img.convert("RGBA") if img.mode == "P" else img
        mask = src.split()[-1] if src.mode in ("RGBA", "LA") else None
        bg.paste(src.convert("RGB"), mask=mask)
        img = bg
    elif img.mode != "RGB":
        img = img.convert("RGB")
    # Cap dimensions — 2048px max
    if img.width > 2048 or img.height > 2048:
        img.thumbnail((2048, 2048), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=82, optimize=True, progressive=True)
    return out.getvalue()

def save_images(files: list) -> list:
    ip = _client_key()
    saved = []
    if _chk(_rl_upload, ip, 20, 300): return saved
    for f in files:
        if not f or not f.filename: continue
        if len(saved) >= app.config["MAX_IMAGES_PER_POST"]: break
        ext = f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else ""
        if ext not in app.config["ALLOWED_EXTENSIONS"]: continue
        data = f.read(app.config["SINGLE_IMAGE_MAX"]+1)
        if len(data) > app.config["SINGLE_IMAGE_MAX"]: continue
        if not _valid_image(data, ext): continue
        try:
            clean = process_post_image(data)     # strip EXIF, re-encode as JPEG
        except Exception:
            continue                              # corrupt / decompression bomb
        name = _save_file(clean, "jpg", app.config["UPLOAD_FOLDER"])
        if name: saved.append(name)
    return saved

def process_avatar_image(data: bytes) -> bytes:
    """Strip metadata, resize to max 400×400, return JPEG bytes at quality 78."""
    Image.MAX_IMAGE_PIXELS = 20_000_000
    img = Image.open(io.BytesIO(data))
    if img.mode in ("RGBA", "P", "LA"):
        bg = Image.new("RGB", img.size, (0, 0, 0))
        src = img.convert("RGBA") if img.mode == "P" else img
        mask = src.split()[-1] if src.mode in ("RGBA", "LA") else None
        bg.paste(src.convert("RGB"), mask=mask)
        img = bg
    elif img.mode != "RGB":
        img = img.convert("RGB")
    if img.width > 400 or img.height > 400:
        img.thumbnail((400, 400), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=78, optimize=True)
    return out.getvalue()

def save_avatar(f) -> str:
    if not f or not f.filename: return ""
    ext = f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else ""
    if ext not in app.config["ALLOWED_EXTENSIONS"]: return ""
    data = f.read(app.config["AVATAR_MAX"]+1)
    if len(data) > app.config["AVATAR_MAX"]: return ""
    if not _valid_image(data, ext): return ""
    try:
        clean = process_avatar_image(data)
    except Exception:
        return ""
    name = f"av_{uuid.uuid4().hex}.jpg"
    dest = os.path.join(app.config["AVATAR_FOLDER"], name)
    if not os.path.realpath(dest).startswith(os.path.realpath(app.config["AVATAR_FOLDER"])):
        return ""
    open(dest, "wb").write(clean)
    return name

def _del_images(post):
    try:
        for img in json.loads(post["images"] or "[]"):
            p = os.path.join(app.config["UPLOAD_FOLDER"], img)
            if os.path.realpath(p).startswith(os.path.realpath(app.config["UPLOAD_FOLDER"])):
                try: os.remove(p)
                except FileNotFoundError: pass
    except Exception: pass

# ── Markdown renderer ──────────────────────────────────────────────────────
_URL_RE    = re.compile(r'(https?://[^\s<>"\')\]]+)', re.IGNORECASE)
_BOLD_RE   = re.compile(r'\*\*(.+?)\*\*')
_ITALIC_RE = re.compile(r'\*(.+?)\*')
_INLINE_RE = re.compile(r'`([^`]+)`')

def _escape(s): return html.escape(s, quote=False)
def _linkify(s):
    return _URL_RE.sub(
        lambda m: f'<a href="{_escape(m.group(1))}" target="_blank" rel="noopener noreferrer">{_escape(m.group(1))}</a>',
        s)
def _inline(s):
    s = _escape(s)
    s = _BOLD_RE.sub(r'<strong>\1</strong>', s)
    s = _ITALIC_RE.sub(r'<em>\1</em>', s)
    s = _INLINE_RE.sub(r'<code class="inline">\1</code>', s)
    return _linkify(s)

def render_body(text: str) -> str:
    lines = text.splitlines(); out = []; i = 0; in_par = False
    def close_p():
        nonlocal in_par
        if in_par: out.append("</p>"); in_par = False
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            close_p()
            lang = _escape(line.strip()[3:].strip().lower() or "text")[:20]
            code = []; i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i]); i += 1
            out.append(f'<pre class="code-block"><div class="code-lang">{lang}</div>'
                       f'<code class="language-{lang}">{_escape(chr(10).join(code))}</code></pre>')
            i += 1; continue
        m = re.match(r'^(#{1,3})\s+(.*)', line)
        if m:
            close_p()
            out.append(f"<h{len(m.group(1))+2} class='post-h'>{_inline(m.group(2))}</h{len(m.group(1))+2}>")
            i += 1; continue
        if re.match(r'^[-*_]{3,}\s*$', line):
            close_p(); out.append("<hr class='post-hr'>"); i += 1; continue
        if re.match(r'^[-*]\s+', line):
            close_p()
            cleaned = re.sub(r'^[-*]\s+','',line)
            out.append(f"<li class='post-li'>{_inline(cleaned)}</li>")
            i += 1; continue
        if not line.strip():
            close_p(); i += 1; continue
        if not in_par: out.append("<p>"); in_par = True
        else: out.append("<br>")
        out.append(_inline(line)); i += 1
    close_p()
    return "\n".join(out)

@app.template_filter("md")
def md_filter(text: str) -> Markup:
    return Markup(render_body(text or ""))

@app.template_filter("strip_md")
def strip_md_filter(text: str) -> str:
    """Strip markdown symbols for plain-text excerpts (post cards, previews)."""
    s = text or ""
    s = re.sub(r'\*\*(.+?)\*\*', r'\1', s)   # **bold**
    s = re.sub(r'\*(.+?)\*',     r'\1', s)   # *italic*
    s = re.sub(r'`([^`]+)`',     r'\1', s)   # `code`
    s = re.sub(r'^#{1,3}\s+',    '',    s, flags=re.MULTILINE)  # headings
    s = re.sub(r'^[-*]\s+',      '',    s, flags=re.MULTILINE)  # list bullets
    s = re.sub(r'```[\s\S]*?```','',    s)    # code blocks
    s = re.sub(r'\n+',           ' ',   s).strip()
    return s

@app.template_filter("filesize")
def filesize_filter(n) -> str:
    n = int(n or 0)
    if n >= 1048576:
        return f"{n / 1048576:.1f} MB"
    return f"{max(1, round(n / 1024))} KB"

@app.template_filter("from_json")
def from_json_filter(s: str) -> list:
    try: return json.loads(s or "[]")
    except Exception: return []

# ── Public routes ──────────────────────────────────────────────────────────
@app.route("/")
def index():
    # Maintenance mode
    if get_setting("maintenance","0") == "1" and not _is_admin():
        return render_template("error.html", code=503, msg="Site under maintenance. Back soon."), 503

    import random as _random

    page = max(1, request.args.get("page", 1, type=int))
    ppp  = int(get_setting("posts_per_page", "10"))
    db   = get_db()

    # ── Pinned posts (first page only, always on top) ──────────────────────
    pinned = db.execute(
        "SELECT * FROM posts WHERE pinned=1 ORDER BY created DESC LIMIT 3"
    ).fetchall() if page == 1 else []
    pids = [p["id"] for p in pinned]
    ph   = ("," + ",".join("?" * len(pids))) if pids else ""

    # ── News roles = Reporter, Editor, Correspondent, Analyst ──────────────
    NEWS_ROLES = ("Reporter", "Editor", "Correspondent", "Analyst")
    news_ph    = ",".join("?" * len(NEWS_ROLES))
    offset     = (page - 1) * ppp

    # Fetch a larger pool so we can mix (fetch 3× ppp to have enough)
    pool = ppp * 3

    news_posts = db.execute(
        f"SELECT * FROM posts WHERE role IN ({news_ph})"
        f" AND id NOT IN ('__dummy__'{ph})"
        f" ORDER BY created DESC LIMIT ? OFFSET ?",
        list(NEWS_ROLES) + pids + [pool, offset]
    ).fetchall()

    other_posts = db.execute(
        f"SELECT * FROM posts WHERE (role NOT IN ({news_ph}) OR role = '')"
        f" AND id NOT IN ('__dummy__'{ph})"
        f" ORDER BY RANDOM() LIMIT ? OFFSET ?",
        list(NEWS_ROLES) + pids + [pool, offset]
    ).fetchall()

    # ── Mix: 70% news, 30% others ──────────────────────────────────────────
    n_news  = round(ppp * 0.70)   # 7 news posts per page of 10
    n_other = ppp - n_news         # 3 other posts per page of 10

    chosen_news  = news_posts[:n_news]
    chosen_other = other_posts[:n_other]

    # Pad with whichever has more if one side is short
    if len(chosen_news) < n_news:
        extra = n_news - len(chosen_news)
        chosen_other = other_posts[:n_other + extra]
    if len(chosen_other) < n_other:
        extra = n_other - len(chosen_other)
        chosen_news = news_posts[:n_news + extra]

    # Interleave: roughly every 2-3 news posts, insert 1 other
    mixed = []
    ni, oi = 0, 0
    while ni < len(chosen_news) or oi < len(chosen_other):
        # Add 2-3 news
        batch = 2 if oi % 2 == 0 else 3
        for _ in range(batch):
            if ni < len(chosen_news):
                mixed.append(chosen_news[ni]); ni += 1
        # Add 1 other
        if oi < len(chosen_other):
            mixed.append(chosen_other[oi]); oi += 1

    # Deduplicate (preserve order) and cap at ppp
    seen  = set(pids)
    final = []
    for p in mixed:
        if p["id"] not in seen:
            seen.add(p["id"])
            final.append(p)
        if len(final) >= ppp + 1:
            break

    has_next = len(final) > ppp
    final    = final[:ppp]

    all_post_ids = [p["id"] for p in pinned + final]

    # Live reaction counts from post_reactions table — single source of truth
    card_counts: dict = {}
    if all_post_ids:
        try:
            ph   = ",".join("?" * len(all_post_ids))
            rows = db.execute(
                f"SELECT post_id, reaction, COUNT(*) as n FROM post_reactions "
                f"WHERE post_id IN ({ph}) AND reaction IN ('fire','bolt') "
                f"GROUP BY post_id, reaction",
                all_post_ids
            ).fetchall()
            for r in rows:
                card_counts.setdefault(r["post_id"], {"fire": 0, "bolt": 0})
                card_counts[r["post_id"]][r["reaction"]] = r["n"]
        except Exception:
            pass

    return render_template("index.html",
        pinned_data=[_enrich(p) for p in pinned],
        posts_data=[_enrich(p) for p in final],
        page=page, has_next=has_next, has_prev=page > 1,
        sidebar=_sidebar(db),
        card_counts=card_counts,
        my_reactions_map=_user_reactions_for_posts(db, all_post_ids))

def _ip_hash() -> str:
    """One-way hash of IP+secret — anonymous dedup, not reversible."""
    ip  = _client_key()
    sal = (SECRET_KEY[:16].hex() if isinstance(SECRET_KEY, bytes)
           else hashlib.sha256(str(SECRET_KEY).encode()).hexdigest()[:16])
    return hashlib.sha256(f"{sal}:{ip}".encode()).hexdigest()[:32]

def _reactor_id() -> tuple:
    """Return (reactor_id, token_hash) for reaction deduplication.
    - If user is logged in with a token: reactor_id = hash(token), token_hash = same
    - If anonymous: reactor_id = ip_hash, token_hash = ''
    Logged-in users' reactions persist across devices and IPs.
    """
    raw = request.cookies.get("dn_token", "")
    if raw:
        tok_h = hashlib.sha256(f"tok:{raw}".encode()).hexdigest()[:32]
        return tok_h, tok_h
    return _ip_hash(), ""


def _reaction_counts(db, post_id: str) -> dict:
    """Always read live from post_reactions table — single source of truth."""
    counts = {"fire": 0, "bolt": 0}
    try:
        rows = db.execute(
            "SELECT reaction, COUNT(*) as n FROM post_reactions "
            "WHERE post_id=? AND reaction IN ('fire','bolt') "
            "GROUP BY reaction",
            (post_id,)
        ).fetchall()
        for r in rows:
            counts[r["reaction"]] = r["n"]
    except Exception:
        pass
    return counts


def _user_reactions_for_posts(db, post_ids: list) -> dict:
    """Returns {post_id: set(reactions)} for current user — token-based if logged in, else IP."""
    if not post_ids:
        return {}
    reactor, tok_h = _reactor_id()
    try:
        ph   = ",".join("?" * len(post_ids))
        # If logged in: match by token_hash (works across devices)
        # If anonymous: match by ip_hash
        if tok_h:
            rows = db.execute(
                f"SELECT post_id, reaction FROM post_reactions "
                f"WHERE token_hash=? AND post_id IN ({ph}) AND reaction IN ('fire','bolt')",
                [tok_h] + list(post_ids)
            ).fetchall()
        else:
            rows = db.execute(
                f"SELECT post_id, reaction FROM post_reactions "
                f"WHERE ip_hash=? AND token_hash='' AND post_id IN ({ph}) AND reaction IN ('fire','bolt')",
                [reactor] + list(post_ids)
            ).fetchall()
        result: dict = {}
        for r in rows:
            result.setdefault(r["post_id"], set()).add(r["reaction"])
        return result
    except Exception:
        return {}


def _user_reactions(db, post_id: str) -> set:
    """Reactions already cast by this user on this post (token-aware)."""
    reactor, tok_h = _reactor_id()
    try:
        if tok_h:
            rows = db.execute(
                "SELECT reaction FROM post_reactions "
                "WHERE post_id=? AND token_hash=? AND reaction IN ('fire','bolt')",
                (post_id, tok_h)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT reaction FROM post_reactions "
                "WHERE post_id=? AND ip_hash=? AND token_hash='' AND reaction IN ('fire','bolt')",
                (post_id, reactor)
            ).fetchall()
        return {r["reaction"] for r in rows}
    except Exception:
        return set()


@app.route("/post/<post_id>")
def post_detail(post_id):
    if get_setting("maintenance","0")=="1" and not _is_admin():
        return render_template("error.html", code=503, msg="Site under maintenance."), 503
    db   = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post: abort(404)

    # ── Session-based view tracking (Tor-safe) ─────────────────────────────
    sid      = session.get("sid") or secrets.token_hex(16)
    session["sid"] = sid
    sid_hash = hashlib.sha256(f"{SECRET_KEY[:4] if isinstance(SECRET_KEY,bytes) else SECRET_KEY[:4]}:{sid}:{post_id}".encode()).hexdigest()[:32]
    try:
        db.execute(
            "INSERT OR IGNORE INTO post_views (post_id, sid_hash, created) VALUES (?,?,?)",
            (post_id, sid_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        if db.execute("SELECT changes()").fetchone()[0]:
            db.execute("UPDATE posts SET views=views+1 WHERE id=?", (post_id,))
        db.commit()
    except Exception:
        pass

    post   = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    ed     = _enrich(post)
    counts = _reaction_counts(db, post_id)
    mine   = _user_reactions(db, post_id)

    # ── Unresolved reports count (admin only) ──────────────────────────────
    report_count = 0
    if _is_admin():
        r = db.execute(
            "SELECT COUNT(*) FROM post_reports WHERE post_id=? AND resolved=0", (post_id,)
        ).fetchone()
        report_count = r[0] if r else 0

    return render_template("post.html",
        post=post, imgs=ed["imgs"], author_row=ed["author_row"], rt=ed["rt"],
        tok_verified=ed["tok_verified"], tok_avatar=ed["tok_avatar"],
        sidebar=_sidebar(db), reactions=counts, my_reactions=mine,
        report_count=report_count)

@app.route("/post/<post_id>/react/<reaction>", methods=["POST"])
def post_react(post_id, reaction):
    """
    Toggle anonymous reaction. Eye is NOT a reaction — it's auto-counted as views.
    Only fire/bolt are user-toggled. Skull removed. Eye is auto view tracking only.
    Counts always come from post_reactions table, never from posts.reaction_* columns.
    """
    VALID = {"fire", "bolt"}   # fire + bolt only
    if reaction not in VALID:
        abort(400)

    # Sanitize post_id — must be hex
    if not re.match(r'^[a-f0-9]{32}$', post_id):
        abort(400)

    if not _csrf_ok():
        abort(403)

    db   = get_db()
    post = db.execute("SELECT id FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        abort(404)

    reactor, tok_h = _reactor_id()

    # Look up existing reaction: token users matched by token_hash, anon by ip_hash
    if tok_h:
        existing = db.execute(
            "SELECT id FROM post_reactions WHERE post_id=? AND token_hash=? AND reaction=?",
            (post_id, tok_h, reaction)
        ).fetchone()
    else:
        existing = db.execute(
            "SELECT id FROM post_reactions WHERE post_id=? AND ip_hash=? AND token_hash='' AND reaction=?",
            (post_id, reactor, reaction)
        ).fetchone()

    if existing:
        # Toggle off
        db.execute("DELETE FROM post_reactions WHERE id=?", (existing["id"],))
    else:
        # Toggle on
        db.execute(
            "INSERT OR IGNORE INTO post_reactions (id,post_id,ip_hash,token_hash,reaction,created) "
            "VALUES (?,?,?,?,?,?)",
            (uuid.uuid4().hex, post_id, reactor, tok_h, reaction,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
    db.commit()

    # Redirect: whitelist-only — never trust user-supplied URLs
    _SAFE_NEXT = {"/", url_for("index"), url_for("search")}
    next_url   = request.form.get("next", "")
    if next_url in _SAFE_NEXT:
        return redirect(next_url)
    return redirect(url_for("post_detail", post_id=post_id) + "#reactions")


@app.route("/post/<post_id>/report", methods=["POST"])
def post_report(post_id):
    """Anonymous report — IP-hashed, no identity stored."""
    if not _csrf_ok(): abort(403)
    db      = get_db()
    post    = db.execute("SELECT id FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post: abort(404)
    ip_hash = _ip_hash()
    reason  = request.form.get("reason","").strip()[:200]
    # Limit: 1 report per IP per post
    existing = db.execute(
        "SELECT id FROM post_reports WHERE post_id=? AND ip_hash=?",
        (post_id, ip_hash)
    ).fetchone()
    if not existing:
        db.execute(
            "INSERT INTO post_reports (id,post_id,ip_hash,reason,created) VALUES (?,?,?,?,?)",
            (uuid.uuid4().hex, post_id, ip_hash, reason,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        db.commit()
    return redirect(url_for("post_detail", post_id=post_id) + "?reported=1")


@app.route("/u/<username>")
def public_profile(username):
    """Public contributor profile — shows posts and badge, no private info."""
    db  = get_db()
    tok = db.execute(
        "SELECT id, claimed_name, claimed_avatar, verified, label "
        "FROM tokens WHERE (claimed_name=? OR label=?) AND revoked=0 LIMIT 1",
        (username, username)
    ).fetchone()
    if not tok: abort(404)
    posts = db.execute(
        "SELECT * FROM posts WHERE token_id=? ORDER BY created DESC LIMIT 20",
        (tok["id"],)
    ).fetchall()
    return render_template("public_profile.html",
        profile=tok, posts=[_enrich(p) for p in posts])


@app.route("/feed.xml")
def rss_feed():
    """RSS 2.0 feed — last 20 posts. Works on Tor and clearnet."""
    db    = get_db()
    posts = db.execute(
        "SELECT * FROM posts ORDER BY created DESC LIMIT 20"
    ).fetchall()
    base  = _get_site_base() or f"http://{request.host}"
    title = get_setting("site_title", "GateForum")
    desc  = get_setting("site_tagline", "Independent · Anonymous · Uncensored")

    items = []
    for p in posts:
        link    = f"{base}/post/{p['id']}"
        pub     = p["created"].replace(" ", "T") + "+00:00"
        excerpt = re.sub(r'[<>&"\']', '', (p["body"] or ""))[:300]
        items.append(
            f"<item>"
            f"<title><![CDATA[{p['title']}]]></title>"
            f"<link>{link}</link>"
            f"<guid isPermaLink=\"true\">{link}</guid>"
            f"<pubDate>{pub}</pubDate>"
            f"<description><![CDATA[{excerpt}]]></description>"
            f"</item>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">'
        f'<channel>'
        f'<title>{title}</title>'
        f'<link>{base}</link>'
        f'<description>{desc}</description>'
        f'<language>en</language>'
        f'<atom:link href="{base}/feed.xml" rel="self" type="application/rss+xml"/>'
        + "".join(items) +
        '</channel></rss>'
    )
    resp = make_response(xml)
    resp.headers["Content-Type"]  = "application/rss+xml; charset=utf-8"
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


# ── Anonymous Chat System ──────────────────────────────────────────────────
import random
from PIL import Image

def _del_chat_image(filename: str):
    """Safely delete a chat image file."""
    if not filename:
        return
    p = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.realpath(p).startswith(os.path.realpath(app.config["UPLOAD_FOLDER"])):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass

def process_chat_image(data: bytes) -> bytes:
    """Strip ALL metadata, resize to max 800px, return JPEG bytes at quality 72."""
    Image.MAX_IMAGE_PIXELS = 20_000_000
    img = Image.open(io.BytesIO(data))
    # Convert mode so we always get a clean RGB (drops EXIF, ICC, XMP etc.)
    if img.mode in ("RGBA", "P", "LA"):
        bg = Image.new("RGB", img.size, (0, 0, 0))
        src = img.convert("RGBA") if img.mode == "P" else img
        mask = src.split()[-1] if src.mode in ("RGBA", "LA") else None
        bg.paste(src.convert("RGB"), mask=mask)
        img = bg
    elif img.mode != "RGB":
        img = img.convert("RGB")
    # Resize if needed (keep aspect ratio)
    max_dim = 800
    if img.width > max_dim or img.height > max_dim:
        img.thumbnail((max_dim, max_dim), Image.LANCZOS)
    # Save as JPEG — PIL never copies EXIF unless you pass exif= explicitly
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=72, optimize=True, progressive=True)
    return out.getvalue()

CHAT_ADJECTIVES = [
    "Shadow", "Dark", "Silent", "Ghost", "Phantom", "Mystic", "Crypto",
    "Hidden", "Anon", "Void", "Null", "Zero", "Rogue", "Stealth", "Cipher",
    "Toxic", "Frozen", "Neon", "Blaze", "Hollow", "Rusty", "Broken", "Steel",
    "Blind", "Burning", "Cold", "Cursed", "Dead", "Fallen", "Feral",
    "Glitch", "Grim", "Haze", "Iron", "Jagged", "Lost", "Lunar", "Metal",
    "Night", "Obsidian", "Pale", "Rapid", "Scarlet", "Sharp", "Smoke",
    "Solar", "Static", "Storm", "Twisted", "Wild", "Wired", "Acid",
    "Ancient", "Binary", "Chrome", "Cobalt", "Corrupt", "Crimson",
    "Deleted", "Digital", "Dim", "Electric", "Exiled", "Fallen", "Flame",
    "Fractured", "Fuzzy", "Glow", "Gravity", "Heavy", "Hex", "Hyper",
    "Infected", "Infra", "Inky", "Inverse", "Invisible", "Jade", "Kinetic",
    "Lava", "Liquid", "Locked", "Logic", "Low", "Macro", "Marble",
    "Mirror", "Muted", "Naked", "Nebula", "Nitro", "Oblique", "Offline",
    "Overload", "Paranoid", "Phase", "Pixel", "Plasma", "Polarity",
    "Psycho", "Quantum", "Raw", "Rebel", "Red", "Remote", "Rust",
    "Savage", "Shattered", "Signal", "Slim", "Snapped", "Sonic", "Spectral",
    "Spiked", "Stray", "Sub", "Super", "Surge", "Terminal", "Thermal",
    "Ultra", "Unknown", "Unstable", "Venom", "Viral", "Virtual", "Volt",
    "Warp", "White", "Wiped", "Xenon", "Zero", "Zone",
]

CHAT_NOUNS = [
    "Fox", "Wolf", "Hawk", "Raven", "Snake", "Spider", "Owl", "Cat",
    "Rat", "Bat", "Dragon", "Tiger", "Bear", "Shark", "Viper",
    "Falcon", "Lynx", "Panther", "Cobra", "Crow", "Eagle", "Hyena",
    "Jaguar", "Mantis", "Mole", "Moose", "Moth", "Puma", "Scorpion",
    "Squid", "Wasp", "Weasel", "Jackal", "Hound", "Kraken", "Leech",
    "Lizard", "Locust", "Piranha", "Porcupine", "Python", "Talon",
    "Termite", "Toad", "Vulture", "Wyvern", "Eel", "Ferret", "Gecko",
    "Ghost", "Golem", "Gremlin", "Hacker", "Hulk", "Imp", "Insect",
    "Knight", "Lurker", "Maverick", "Mirage", "Monk", "Node",
    "Nomad", "Oracle", "Outlaw", "Phantom", "Pirate", "Predator",
    "Proton", "Punk", "Ranger", "Reaper", "Revenant", "Riot",
    "Ronin", "Runner", "Sage", "Shade", "Shroud", "Siren",
    "Skull", "Specter", "Sprite", "Stalker", "Stinger", "Sword",
    "Titan", "Tracker", "Troll", "Vampire", "Vector", "Vortex",
    "Wanderer", "Warlock", "Wraith", "Xenomorph", "Yeti", "Zero",
]

def _generate_nickname():
    """Generate a random anonymous nickname."""
    return f"{random.choice(CHAT_ADJECTIVES)}{random.choice(CHAT_NOUNS)}{random.randint(10,99)}"

def _get_chat_nickname():
    """Get or create chat nickname from session."""
    if "chat_nick" not in session:
        session["chat_nick"] = _generate_nickname()
    return session["chat_nick"]

def _sanitize_chat_msg(msg):
    """Sanitize chat message - strip HTML, limit length."""
    if not msg:
        return ""
    msg = str(msg).strip()[:1000]
    # Remove any HTML tags
    msg = re.sub(r'<[^>]+>', '', msg)
    # Escape HTML entities (keep quote=False so apostrophes aren't encoded)
    msg = html.escape(msg, quote=False)
    # Remove control characters
    msg = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', msg)
    return msg.strip()

def _cleanup_replied_messages(db):
    """Delete replied messages and their image files."""
    rows = db.execute("SELECT image FROM chat WHERE replied=1").fetchall()
    for r in rows:
        _del_chat_image(r["image"])
    db.execute("DELETE FROM chat WHERE replied=1")
    db.commit()

@app.route("/chat", methods=["GET", "POST"])
def chat_page():
    db = get_db()
    ip = _client_key()
    
    # Rate limit: 30 messages per minute
    if request.method == "POST" and _chk(_rl_post, ip, 30, 60):
        abort(429)

    # CSRF check for all POST actions
    if request.method == "POST" and not _csrf_ok():
        abort(403)
    
    # Get current user info
    tok = _current_tok()
    is_token_user = tok is not None
    
    # Handle nickname
    if request.method == "POST" and request.form.get("action") == "set_nick":
        new_nick = request.form.get("nickname", "").strip()[:30]
        new_nick = re.sub(r'[<>&"\']', '', new_nick)
        if new_nick and len(new_nick) >= 2:
            session["chat_nick"] = new_nick
        return redirect(url_for("chat_page"))
    
    nickname = _get_chat_nickname()
    if is_token_user and tok["claimed_name"]:
        nickname = tok["claimed_name"]
    
    error = None
    
    # Handle message submission
    if request.method == "POST" and request.form.get("action") == "send":
        msg_text = _sanitize_chat_msg(request.form.get("message", ""))
        reply_to = request.form.get("reply_to", "").strip()[:50]
        
        if not msg_text:
            error = "Message cannot be empty."
        else:
            # Handle image upload — verified users only
            img_filename = ""
            if is_token_user and tok["verified"]:
                img_file = request.files.get("image")
                if img_file and img_file.filename:
                    allowed = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
                    ext = img_file.filename.rsplit('.', 1)[-1].lower() if '.' in img_file.filename else ''
                    if ext in allowed:
                        raw_data = img_file.read(app.config["SINGLE_IMAGE_MAX"] + 1)
                        if len(raw_data) <= app.config["SINGLE_IMAGE_MAX"]:
                            try:
                                clean_data = process_chat_image(raw_data)
                                img_filename = f"chat_{uuid.uuid4().hex[:16]}.jpg"
                                img_path = os.path.join(app.config["UPLOAD_FOLDER"], img_filename)
                                with open(img_path, "wb") as f:
                                    f.write(clean_data)
                            except Exception:
                                img_filename = ""
            
            # If replying, get the original author's nickname and mark as replied
            reply_to_nick = ""
            if reply_to:
                orig = db.execute("SELECT nickname FROM chat WHERE id=?", (reply_to,)).fetchone()
                if orig:
                    reply_to_nick = orig["nickname"]
                db.execute("UPDATE chat SET replied=1 WHERE id=?", (reply_to,))
            
            # Insert new message
            msg_id = uuid.uuid4().hex
            db.execute(
                "INSERT INTO chat (id, message, image, nickname, is_token, token_id, reply_to, reply_to_nick, replied, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (msg_id, msg_text, img_filename, nickname, 1 if is_token_user else 0,
                 tok["id"] if tok else "", reply_to, reply_to_nick,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            db.commit()
            
            # Cleanup replied messages
            _cleanup_replied_messages(db)
            
            # Keep only the last 10 messages — delete image files of evicted messages
            old_imgs = db.execute(
                "SELECT image FROM chat WHERE id NOT IN "
                "(SELECT id FROM chat ORDER BY created_at DESC LIMIT 10)"
            ).fetchall()
            for r in old_imgs:
                _del_chat_image(r["image"])
            db.execute(
                "DELETE FROM chat WHERE id NOT IN "
                "(SELECT id FROM chat ORDER BY created_at DESC LIMIT 10)"
            )
            db.commit()
            
            return redirect(url_for("chat_page"))
    
    # Handle new nickname generation
    if request.method == "POST" and request.form.get("action") == "new_nick":
        session["chat_nick"] = _generate_nickname()
        return redirect(url_for("chat_page"))
    
    # Get all active messages (not replied to yet)
    messages_raw = db.execute(
        "SELECT * FROM chat WHERE replied=0 ORDER BY created_at ASC"
    ).fetchall()
    
    # Enrich messages with token avatar + verified info
    messages = []
    for msg in messages_raw:
        msg_dict = dict(msg)
        msg_dict['avatar'] = ''
        msg_dict['tok_verified'] = 0
        if msg['token_id']:
            tok_info = db.execute(
                "SELECT claimed_avatar, verified FROM tokens WHERE id=?",
                (msg['token_id'],)
            ).fetchone()
            if tok_info:
                if tok_info['claimed_avatar']:
                    msg_dict['avatar'] = tok_info['claimed_avatar']
                msg_dict['tok_verified'] = tok_info['verified']
        messages.append(msg_dict)
    
    # Get reply_to message if replying
    reply_id = request.args.get('reply', '')
    reply_msg = None
    if reply_id:
        reply_msg = db.execute("SELECT * FROM chat WHERE id=?", (reply_id,)).fetchone()
    
    return render_template("chat.html",
        messages=messages,
        nickname=nickname,
        is_token_user=is_token_user,
        tok_row=tok,
        error=error,
        reply_msg=reply_msg)

@app.route("/img/<msg_id>")
def chat_img(msg_id):
    """Serve a chat image by message ID — hides real file path."""
    # Validate: must be a 32-char hex UUID
    if not re.match(r'^[a-f0-9]{32}$', msg_id):
        abort(404)
    db  = get_db()
    row = db.execute("SELECT image FROM chat WHERE id=?", (msg_id,)).fetchone()
    if not row or not row["image"]:
        abort(404)
    filename = row["image"]
    # Security: only serve chat images
    if not filename.startswith("chat_"):
        abort(404)
    upload_dir = app.config["UPLOAD_FOLDER"]
    full_path  = os.path.join(upload_dir, filename)
    if not os.path.realpath(full_path).startswith(os.path.realpath(upload_dir)):
        abort(404)
    if not os.path.exists(full_path):
        abort(404)
    resp = send_from_directory(upload_dir, filename, mimetype="image/jpeg")
    resp.headers["Cache-Control"] = "private, max-age=300"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

@app.route("/search")
def search():
    ip = _client_key()
    if _chk(_rl_search, ip, 20, 60): abort(429)
    q    = request.args.get("q","").strip()[:200]
    page = max(1, request.args.get("page", 1, type=int))
    ppp  = 20
    db   = get_db()
    results = []
    total  = 0
    if q:
        like = f"%{q}%"
        # Count total matches first
        try:
            q_fts = re.sub(r'["\*\^\(\)\[\]\{\}\\]', ' ', q).strip()
            total = db.execute(
                "SELECT COUNT(*) FROM posts_fts WHERE posts_fts MATCH ?",
                (q_fts,)
            ).fetchone()[0]
        except Exception:
            total = db.execute(
                "SELECT COUNT(*) FROM posts WHERE title LIKE ? OR body LIKE ?",
                (like, like)
            ).fetchone()[0]

        offset = (page - 1) * ppp
        # Try FTS5 first
        try:
            q_fts = re.sub(r'["\*\^\(\)\[\]\{\}\\]', ' ', q).strip()
            rows  = db.execute(
                """SELECT posts.* FROM posts
                   JOIN posts_fts ON posts.rowid = posts_fts.rowid
                   WHERE posts_fts MATCH ?
                   ORDER BY rank LIMIT ? OFFSET ?""",
                (q_fts, ppp, offset)
            ).fetchall()
        except Exception:
            rows = db.execute(
                "SELECT * FROM posts WHERE title LIKE ? OR body LIKE ? ORDER BY created DESC LIMIT ? OFFSET ?",
                (like, like, ppp, offset)
            ).fetchall()
        results = [_enrich(r) for r in rows]
    return render_template("search.html", q=q, results=results, total=total,
                           page=page, ppp=ppp, sidebar=_sidebar(db))

# ── Token login ────────────────────────────────────────────────────────────
@app.route("/token-access", methods=["GET","POST"])
def token_login():
    if _current_tok(): return redirect(url_for("contributor_dashboard"))
    if _is_admin():    return redirect(url_for("admin_dashboard"))
    error = None
    db = get_db()
    
    # Get available pool tokens (not claimed, not revoked)
    pool_tokens = db.execute(
        "SELECT id, label, pool_token FROM tokens WHERE is_pool=1 AND claimed=0 AND revoked=0 ORDER BY created DESC"
    ).fetchall()
    
    if request.method == "POST":
        ip = _client_key()
        if _chk(_rl_login, ip, 5, 300):
            error = "Too many attempts. Please wait 5 minutes."
        elif not _csrf_ok():
            error = "Invalid form submission. Please refresh and try again."
        else:
            raw = request.form.get("token","").strip()
            row = _get_token_row(raw)
            if row:
                # If this is a pool token being claimed, mark it as claimed
                if row["is_pool"] == 1 and row["claimed"] == 0:
                    db.execute(
                        "UPDATE tokens SET claimed=1, claimed_at=?, claimed_by='' WHERE id=?",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         row["id"])
                    )
                    db.commit()
                    log_action("token_claimed", f"Pool token '{row['label']}' claimed")

                _rotate_session()                # prevent session fixation
                resp = make_response(redirect(url_for("contributor_dashboard")))
                resp.set_cookie("dn_token", raw, max_age=7776000,
                                httponly=True, samesite="Lax", secure=False)
                return resp
            time.sleep(1)
            error = "Invalid or revoked token."
    return render_template("token_login.html", error=error, pool_tokens=pool_tokens)

def _captcha_new() -> None:
    """Generate a new CAPTCHA answer and store it server-side in the session.
    The answer NEVER leaves the server — only the image is sent to the client.
    """
    import random
    chars  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    answer = "".join(random.choices(chars, k=5))
    session["captcha_answer"] = answer
    session["captcha_ts"]     = int(time.time())

def _captcha_verify(user_input: str) -> tuple[bool, str]:
    """Verify CAPTCHA by comparing user input against server-session answer.
    The answer is stored only in session — never sent to client.
    Returns (ok, error_msg).
    """
    answer = session.get("captcha_answer", "")
    ts     = session.get("captcha_ts", 0)
    if not answer:
        return False, "CAPTCHA session missing — please refresh."
    if abs(time.time() - ts) > 600:                    # 10 min expiry
        session.pop("captcha_answer", None)
        session.pop("captcha_ts",     None)
        return False, "CAPTCHA expired — please refresh the page."
    if not user_input or not hmac.compare_digest(
        user_input.strip().upper(), answer.upper()
    ):
        # Invalidate after wrong attempt — force new CAPTCHA
        session.pop("captcha_answer", None)
        session.pop("captcha_ts",     None)
        return False, "Incorrect CAPTCHA — please try again."
    # Success — invalidate so it can't be reused
    session.pop("captcha_answer", None)
    session.pop("captcha_ts",     None)
    return True, ""


@app.route("/captcha.png")
def captcha_image():
    """
    Self-hosted image CAPTCHA.
    Answer is stored ONLY in the server-side session — never sent to client.
    No token, no header, no JS needed.
    """
    import random, io
    from PIL import Image, ImageDraw, ImageFont, ImageFilter

    _captcha_new()                           # stores answer in session
    answer = session["captcha_answer"]       # read back for image rendering only

    W, H = 220, 76
    img  = Image.new("RGB", (W, H), color=(15, 15, 15))
    draw = ImageDraw.Draw(img)

    # Background noise dots
    for _ in range(700):
        x = random.randint(0, W - 1)
        y = random.randint(0, H - 1)
        c = random.randint(28, 65)
        draw.point((x, y), fill=(c, c, c))

    # Random interference lines
    for _ in range(7):
        draw.line(
            [(random.randint(0,W), random.randint(0,H)),
             (random.randint(0,W), random.randint(0,H))],
            fill=(random.randint(35, 75),)*3, width=1
        )

    # Draw each character
    x_pos = 8
    for ch in answer:
        size  = random.randint(27, 35)
        r     = random.randint(195, 230)
        g     = random.randint(170, 210)
        b     = random.randint(40,  75)
        y_off = random.randint(6, 20)
        angle = random.randint(-18, 18)

        try:
            font = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size
            )
        except Exception:
            try:
                font = ImageFont.truetype(
                    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", size
                )
            except Exception:
                font = ImageFont.load_default()

        # Draw on tiny canvas then rotate for distortion
        ch_w, ch_h = size + 10, size + 10
        ch_img  = Image.new("RGBA", (ch_w, ch_h), (0, 0, 0, 0))
        ch_draw = ImageDraw.Draw(ch_img)
        ch_draw.text((4, 2), ch, fill=(r, g, b, 255), font=font)
        ch_img  = ch_img.rotate(angle, expand=True, resample=Image.BICUBIC)

        img.paste(ch_img, (x_pos, y_off), ch_img)
        x_pos += size + random.randint(0, 8)

    # Slight blur to blend
    img = img.filter(ImageFilter.GaussianBlur(radius=0.6))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    resp = make_response(buf.read())
    resp.headers["Content-Type"]  = "image/png"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    # No token in headers — answer lives only in server session
    return resp


@app.route("/register", methods=["GET", "POST"])
def self_register():
    """
    Self-service account creation with CAPTCHA.
    Creates a new token and logs the user in immediately.
    Admin tokens and roles are unaffected.
    """
    if _current_tok():  return redirect(url_for("contributor_dashboard"))
    if _is_admin():     return redirect(url_for("admin_dashboard"))

    db    = get_db()
    error = None

    if request.method == "POST":
        ip = _client_key()
        if _chk(_rl_register, ip, 5, 600):
            error = "Too many registration attempts. Please wait a few minutes."
        elif not _csrf_ok():
            error = "Invalid form submission. Please refresh and try again."
        else:
            captcha_input = request.form.get("captcha_input", "").strip().upper()
            display_name  = request.form.get("display_name", "").strip()

            cap_ok, cap_err = _captcha_verify(captcha_input)
            if not cap_ok:
                error = cap_err
            elif not display_name or len(display_name) < 2:
                error = "Name must be at least 2 characters."
            elif len(display_name) > 40:
                error = "Name too long (max 40 characters)."
            elif re.search(r'[<>&"\']', display_name):
                error = "Name contains invalid characters."
            else:
                taken = db.execute(
                    "SELECT id FROM tokens WHERE claimed_name=? UNION "
                    "SELECT id FROM authors WHERE name=?",
                    (display_name, display_name)
                ).fetchone()
                if taken:
                    error = "That name is already taken — choose another."
                else:
                    raw      = secrets.token_urlsafe(32)
                    tok_id   = uuid.uuid4().hex
                    tok_hash = _hash_token(raw)
                    now_str  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    db.execute(
                        "INSERT INTO tokens "
                        "(id, label, token_hash, allowed_roles, note, author_id, default_role, "
                        " is_pool, pool_token, created, revoked, claimed, claimed_at, claimed_by, "
                        " claimed_name, verified) "
                        "VALUES (?,?,?,?,?,?,?,0,'',?,0,1,?,?,?,0)",
                        (tok_id, display_name, tok_hash, "", "self-registered", "", "",
                         now_str, now_str, "",
                         display_name)
                    )
                    db.commit()
                    log_action("self_register", f"New account: {display_name}")

                    _rotate_session()            # prevent session fixation
                    session["claimed_token"]       = raw
                    session["claimed_token_label"] = display_name
                    session["claimed_token_name"]  = display_name
                    return redirect(url_for("token_claimed"))

    # Always generate a fresh CAPTCHA answer for GET (and re-render after error)
    if request.method == "GET" or error:
        _captcha_new()
    return render_template("register.html", error=error)


@app.route("/token-logout")
def token_logout():
    """Log out the current contributor by deleting the dn_token cookie."""
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("dn_token")
    return resp


# ── FiroGate helpers ───────────────────────────────────────────────────────

_CONFIRMED_STATES = {"confirmed"}
_AMOUNT_EPSILON   = 1e-8


class GatewayError(RuntimeError):
    """FiroGate could not be reached or answered with an error."""


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _firogate_base() -> tuple[str, bool]:
    """Pick the FiroGate URL and whether to send the request through Tor."""
    if FIROGATE_ONION_URL:
        return FIROGATE_ONION_URL.rstrip("/"), True
    return FIROGATE_BASE_URL.rstrip("/"), FIROGATE_USE_TOR


def _firogate_request(endpoint: str, payload: dict | None = None, method: str = "POST") -> dict:
    """Call the FiroGate API. Never disables TLS checks and never leaks the key."""
    if not FIROGATE_API_KEY:
        raise GatewayError("FIROGATE_API_KEY is not set")
    try:
        import requests as _req
    except ImportError:
        raise GatewayError("the requests library is missing")

    base, use_tor = _firogate_base()
    url     = f"{base}{endpoint}"
    headers = {"Accept": "application/json", "X-API-Key": FIROGATE_API_KEY}
    proxies = {"http": FIROGATE_TOR_PROXY, "https": FIROGATE_TOR_PROXY} if use_tor else None
    timeout = 45 if use_tor else 20
    try:
        if method == "GET":
            r = _req.get(url, headers=headers, proxies=proxies, timeout=timeout)
        else:
            r = _req.post(url, json=payload or {}, headers=headers, proxies=proxies, timeout=timeout)
    except _req.exceptions.Timeout:
        raise GatewayError(f"timeout after {timeout}s")
    except _req.exceptions.RequestException as exc:
        raise GatewayError(f"{type(exc).__name__}")

    if not r.ok:
        app.logger.warning("FiroGate %s %s -> HTTP %s", method, endpoint.split("?")[0], r.status_code)
        raise GatewayError(f"HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        raise GatewayError("non-JSON response")
    if not isinstance(data, dict):
        raise GatewayError("unexpected response")
    return data


def _paid_enough(received, expected) -> bool:
    try:
        return float(received) + _AMOUNT_EPSILON >= float(expected)
    except (TypeError, ValueError):
        return False


def _grant_badge(db, pmt, *, txid: str, received: float, source: str) -> bool:
    """Mark a payment confirmed and give what it paid for. Returns True if this call did it."""
    cur = db.execute(
        "UPDATE firo_payments SET status='confirmed', confirmed_at=?, txid=?, amount_received=? "
        "WHERE id=? AND status!='confirmed'",
        (_now(), txid[:128], float(received or 0), pmt["id"])
    )
    if (pmt["kind"] or "verify") == "product":
        added = db.execute(
            "INSERT OR IGNORE INTO purchases (id, product_id, token_id, payment_id, amount_firo, txid, created) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uuid.uuid4().hex, pmt["product_id"], pmt["token_id"], pmt["id"],
             float(received or 0), txid[:128], _now())
        )
        if added.rowcount:
            db.execute("UPDATE products SET sales = sales + 1 WHERE id=?", (pmt["product_id"],))
    else:
        db.execute("UPDATE tokens SET verified=1 WHERE id=?", (pmt["token_id"],))
    db.commit()
    if cur.rowcount:
        log_action("firo_payment_confirmed", f"order={pmt['order_id']} via={source}")
    return bool(cur.rowcount)


def _apply_gateway_state(db, pmt, data: dict, source: str) -> str:
    """Apply a FiroGate payment object to our record. Returns our new status."""
    if data.get("payment_id") and pmt["fg_payment_id"] and data["payment_id"] != pmt["fg_payment_id"]:
        app.logger.warning("FiroGate payment id mismatch for order %s", pmt["order_id"])
        return pmt["status"]
    if data.get("order_id") and data["order_id"] != pmt["order_id"]:
        app.logger.warning("FiroGate order id mismatch for order %s", pmt["order_id"])
        return pmt["status"]

    status = str(data.get("status") or "").lower()
    if status in _CONFIRMED_STATES:
        txid     = str(data.get("txid") or "")
        received = data.get("amount_received")
        if received is None:
            received = data.get("amount_firo")
        if not txid:
            return pmt["status"]
        if not _paid_enough(received, pmt["amount_firo"]):
            app.logger.warning("FiroGate underpaid order %s: %s < %s", pmt["order_id"], received, pmt["amount_firo"])
            db.execute("UPDATE firo_payments SET status='underpaid', amount_received=? WHERE id=? AND status='pending'",
                       (float(received or 0), pmt["id"]))
            db.commit()
            return "underpaid"
        _grant_badge(db, pmt, txid=txid, received=float(received), source=source)
        return "confirmed"
    if status in ("expired", "cancelled") and pmt["status"] == "pending":
        db.execute("UPDATE firo_payments SET status=? WHERE id=? AND status='pending'", (status, pmt["id"]))
        db.commit()
        return status
    return pmt["status"]


def _remember_nonce(nonce: str) -> bool:
    """Store a webhook nonce. False if it was already used (replay)."""
    db = get_db()
    db.execute("DELETE FROM webhook_nonces WHERE seen < ?", (int(time.time()) - 900,))
    try:
        db.execute("INSERT INTO webhook_nonces (nonce, seen) VALUES (?, ?)", (nonce[:128], int(time.time())))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        db.rollback()
        return False


def _webhook_sig_ok(raw: bytes, payload: dict, signature: str) -> bool:
    """FiroGate signs sorted, compact JSON. Check the exact bytes first."""
    if not FIROGATE_WEBHOOK_SECRET or not signature:
        return False
    key = FIROGATE_WEBHOOK_SECRET.encode()
    sig = signature.strip().lower()
    if hmac.compare_digest(hmac.new(key, raw, hashlib.sha256).hexdigest(), sig):
        return True
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.compare_digest(hmac.new(key, canonical, hashlib.sha256).hexdigest(), sig)


def _get_site_base() -> str:
    """Public base URL used for FiroGate redirects."""
    base = os.environ.get("SITE_BASE_URL", "").rstrip("/")
    if base:
        return base
    host = request.host or ""
    if host.endswith(".onion"):
        return f"http://{host}"
    if host in ("127.0.0.1", "localhost", "::1") or host.startswith("127."):
        app.logger.warning("Set SITE_BASE_URL in .env so FiroGate can send buyers back")
        return ""
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    return f"{'https' if proto == 'https' else 'http'}://{host}"


def _pending_payment(db, token_id: str, kind: str = "verify", product_id: str = ""):
    """Latest pending payment of this kind for this token that has not expired yet."""
    row = db.execute(
        "SELECT * FROM firo_payments WHERE token_id=? AND status='pending' AND kind=? AND product_id=? "
        "ORDER BY created DESC LIMIT 1", (token_id, kind, product_id)
    ).fetchone()
    if not row:
        return None
    exp = row["expires_at"]
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if exp_dt.tzinfo is not None:
                exp_dt = exp_dt.astimezone().replace(tzinfo=None)
            if exp_dt <= datetime.now():
                db.execute("UPDATE firo_payments SET status='expired' WHERE id=? AND status='pending'", (row["id"],))
                db.commit()
                return None
        except ValueError:
            pass
    return row


# ── Firo payment routes ────────────────────────────────────────────────────

_PAY_DOWN_MSG = "Payments are not available right now. Please try again later."


@app.route("/verify/pay", methods=["POST"])
@require_poster
def firo_pay():
    if not _csrf_ok(): abort(403)
    if _is_admin():
        return redirect(url_for("admin_dashboard"))

    tok = _current_tok()
    if not tok:
        return redirect(url_for("token_login"))
    if tok["verified"]:
        return redirect(url_for("contributor_dashboard"))
    if _chk(_rl_pay, tok["id"], 5, 600):
        return render_template("error.html", code=429,
                               msg="Too many tries. Please wait a few minutes."), 429
    if not FIROGATE_API_KEY:
        app.logger.error("firo_pay: FIROGATE_API_KEY is not set")
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503

    db = get_db()
    existing = _pending_payment(db, tok["id"])
    if existing and existing["checkout_url"]:
        return redirect(existing["checkout_url"])

    base = _get_site_base()
    if not base:
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503

    order_id = f"VERIFY-{tok['id'][:12]}-{uuid.uuid4().hex[:8]}"
    try:
        result = _firogate_request("/api/payments/create", {
            "amount_firo":       FIROGATE_VERIFY_AMOUNT,
            "order_id":          order_id,
            "order_description": "Verified badge",
            "success_url":       f"{base}/verify/success",
            "cancel_url":        f"{base}/verify/cancel",
            "timeout_minutes":   FIROGATE_TIMEOUT_MIN,
        })
    except GatewayError as exc:
        app.logger.error("firo_pay: %s", exc)
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503

    checkout_url = str(result.get("checkout_url") or "")
    fg_id        = str(result.get("payment_id") or "")
    if not checkout_url.startswith(("https://", "http://")) or not fg_id:
        app.logger.error("firo_pay: FiroGate answer had no checkout_url or payment_id")
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503

    db.execute(
        "INSERT INTO firo_payments (id, token_id, order_id, fg_payment_id, amount_firo, status, "
        "checkout_url, expires_at, created) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
        (uuid.uuid4().hex, tok["id"], order_id, fg_id[:64], FIROGATE_VERIFY_AMOUNT,
         checkout_url, str(result.get("expires_at") or "")[:40], _now())
    )
    db.commit()
    log_action("firo_payment_started", f"order={order_id}")
    return redirect(checkout_url)


def _check_pending(tok, kind: str = "verify", product_id: str = "") -> str:
    """Ask FiroGate about this token's open payment. Returns our status for it."""
    db  = get_db()
    pmt = db.execute(
        "SELECT * FROM firo_payments WHERE token_id=? AND status IN ('pending','underpaid') "
        "AND kind=? AND product_id=? ORDER BY created DESC LIMIT 1", (tok["id"], kind, product_id)
    ).fetchone()
    if not pmt or not pmt["fg_payment_id"] or not FIROGATE_API_KEY:
        return ""
    if _chk(_rl_status, tok["id"], 20, 60):
        return pmt["status"]
    try:
        data = _firogate_request(f"/api/payments/{pmt['fg_payment_id']}", method="GET")
    except GatewayError as exc:
        app.logger.info("payment check: %s", exc)
        return pmt["status"]
    return _apply_gateway_state(db, pmt, data, "status")


@app.route("/verify/success")
@require_poster
def firo_success():
    """Landing page after checkout. Never grants anything from URL params."""
    if _is_admin():
        return redirect(url_for("admin_dashboard"))
    tok = _current_tok()
    if not tok:
        return redirect(url_for("token_login"))
    if not tok["verified"] and _check_pending(tok) == "confirmed":
        tok = _current_tok()
    payment = None
    if tok["verified"]:
        payment = get_db().execute(
            "SELECT amount_firo, amount_received, txid, confirmed_at FROM firo_payments "
            "WHERE token_id=? AND status='confirmed' AND kind='verify' ORDER BY confirmed_at DESC LIMIT 1",
            (tok["id"],)
        ).fetchone()
    open_payment = None
    if not tok["verified"]:
        open_payment = get_db().execute(
            "SELECT status FROM firo_payments WHERE token_id=? AND status IN ('pending','underpaid') "
            "AND kind='verify' ORDER BY created DESC LIMIT 1", (tok["id"],)
        ).fetchone()
    return render_template("verify_success.html", tok_row=tok, payment=payment,
                           open_payment=open_payment, verify_amount=FIROGATE_VERIFY_AMOUNT)


@app.route("/verify/status")
@require_poster
def firo_status():
    """Polled by the success page."""
    if _is_admin():
        return {"verified": False}
    tok = _current_tok()
    if not tok:
        return {"verified": False}
    if tok["verified"]:
        return {"verified": True}
    state = _check_pending(tok)
    return {"verified": state == "confirmed", "state": state}


@app.route("/verify/cancel")
@require_poster
def firo_cancel():
    if _is_admin():
        return redirect(url_for("admin_dashboard"))
    tok   = _current_tok()
    fg_id = request.args.get("payment_id", "")[:64]
    if tok and fg_id:
        db = get_db()
        db.execute(
            "UPDATE firo_payments SET status='cancelled' "
            "WHERE token_id=? AND fg_payment_id=? AND status='pending'",
            (tok["id"], fg_id)
        )
        db.commit()
    return render_template("verify_cancel.html")


_WEBHOOK_EVENTS = {"payment.confirmed", "payment.expired", "payment.cancelled", "payment.refunded"}


@app.route("/webhook/firogate", methods=["POST"])
def firo_webhook():
    raw = request.get_data(cache=False)
    if len(raw) > 64 * 1024:
        return "", 413
    try:
        payload = json.loads(raw)
    except ValueError:
        return "", 400
    if not isinstance(payload, dict):
        return "", 400

    signature = request.headers.get("X-FiroGate-Signature", "")
    event     = request.headers.get("X-FiroGate-Event", "") or str(payload.get("event") or "")
    nonce     = request.headers.get("X-FiroGate-Nonce", "") or str(payload.get("nonce") or "")
    try:
        ts = int(request.headers.get("X-FiroGate-Timestamp") or payload.get("timestamp") or 0)
    except (TypeError, ValueError):
        return "", 400

    if not FIROGATE_WEBHOOK_SECRET:
        app.logger.error("webhook: FIROGATE_WEBHOOK_SECRET is not set, ignoring")
        return "", 503
    if not _webhook_sig_ok(raw, payload, signature):
        app.logger.warning("webhook: bad signature")
        return "", 403
    if abs(time.time() - ts) > 300:
        return "", 403
    if "timestamp" in payload and str(payload.get("timestamp")) != str(ts):
        return "", 403
    if not nonce or not _remember_nonce(nonce):
        return "", 200

    if event not in _WEBHOOK_EVENTS:
        return "", 200
    order_id = str(payload.get("order_id") or "")
    if not order_id:
        return "", 200

    db  = get_db()
    pmt = db.execute("SELECT * FROM firo_payments WHERE order_id=?", (order_id,)).fetchone()
    if not pmt:
        return "", 200

    if event == "payment.refunded":
        db.execute("UPDATE firo_payments SET status='refunded', refunded_at=? WHERE id=?", (_now(), pmt["id"]))
        if (pmt["kind"] or "verify") == "product":
            gone = db.execute("DELETE FROM purchases WHERE payment_id=?", (pmt["id"],))
            if gone.rowcount:
                db.execute("UPDATE products SET sales = MAX(sales - 1, 0) WHERE id=?", (pmt["product_id"],))
            db.execute("DELETE FROM product_ratings WHERE product_id=? AND token_id=?",
                       (pmt["product_id"], pmt["token_id"]))
        else:
            still_paid = db.execute(
                "SELECT 1 FROM firo_payments WHERE token_id=? AND status='confirmed' AND kind='verify' AND id!=?",
                (pmt["token_id"], pmt["id"])
            ).fetchone()
            if not still_paid:
                db.execute("UPDATE tokens SET verified=0 WHERE id=?", (pmt["token_id"],))
        db.commit()
        log_action("firo_payment_refunded", f"order={order_id}")
        return "", 200

    data = dict(payload)
    data["status"] = {"payment.confirmed": "confirmed", "payment.expired": "expired",
                      "payment.cancelled": "cancelled"}[event]
    _apply_gateway_state(db, pmt, data, "webhook")
    return "", 200


# ── Shop (digital products, paid with FiroGate) ────────────────────────────

PRODUCT_DIR       = os.path.join(BASE_DIR, "instance", "products")
PRODUCT_FILE_MAX  = 20 * 1024 * 1024
PRODUCT_FILE_EXTS = {"zip", "7z", "gz", "tar", "pdf", "epub", "txt", "md", "csv", "json",
                     "png", "jpg", "jpeg", "webp", "gif", "mp3", "ogg", "flac", "wav", "mp4", "webm"}
_rl_rate = defaultdict(list)
_rl_dl   = defaultdict(list)
os.makedirs(PRODUCT_DIR, exist_ok=True)


def _shop_on() -> bool:
    return get_setting("shop_enabled", "1") == "1"


def _shop_visible() -> bool:
    """Who may browse the shop. Buying always needs an account."""
    if not _shop_on():
        return _is_admin()
    if get_setting("shop_visibility", "everyone") == "members":
        return _is_admin() or _current_tok() is not None
    return True


def _product(db, pid: str, *, only_active: bool = True):
    if not re.fullmatch(r"[0-9a-f]{32}", pid or ""):
        return None
    row = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not row or (only_active and not row["active"] and not _is_admin()):
        return None
    return row


def _rating_map(db, ids: list) -> dict:
    if not ids:
        return {}
    qs = ",".join("?" * len(ids))
    rows = db.execute(
        f"SELECT product_id, AVG(stars) AS avg, COUNT(*) AS n FROM product_ratings "
        f"WHERE product_id IN ({qs}) GROUP BY product_id", ids
    ).fetchall()
    return {r["product_id"]: {"avg": round(r["avg"] or 0, 1), "n": r["n"]} for r in rows}


def _owns(db, tok, pid: str) -> bool:
    if not tok:
        return False
    return db.execute("SELECT 1 FROM purchases WHERE product_id=? AND token_id=?",
                      (pid, tok["id"])).fetchone() is not None


def _clean_label(name: str) -> str:
    base = os.path.basename(name or "").strip()
    base = re.sub(r"[^A-Za-z0-9._ -]+", "", base)[:80].strip(" .")
    return base or "download"


def _save_product_file(f) -> tuple[str, str, int] | None:
    """Store an uploaded product file outside static/. Returns (stored, label, size)."""
    if not f or not f.filename:
        return None
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in PRODUCT_FILE_EXTS:
        raise ValueError("That file type is not allowed.")
    data = f.read(PRODUCT_FILE_MAX + 1)
    if len(data) > PRODUCT_FILE_MAX:
        raise ValueError("File is bigger than 20 MB.")
    if not data:
        raise ValueError("File is empty.")
    stored = f"{uuid.uuid4().hex}.bin"
    path = os.path.join(PRODUCT_DIR, stored)
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)
    return stored, _clean_label(f.filename), len(data)


def _delete_product_file(stored: str):
    if stored and re.fullmatch(r"[0-9a-f]{32}\.bin", stored):
        try:
            os.remove(os.path.join(PRODUCT_DIR, stored))
        except OSError:
            pass


@app.route("/shop")
def shop():
    if not _shop_visible():
        if not _shop_on():
            abort(404)
        return redirect(url_for("token_login"))
    db   = get_db()
    q    = request.args.get("q", "").strip()[:80]
    sort = request.args.get("sort", "new")
    order = {"new": "created DESC", "top": "sales DESC, created DESC",
             "low": "price_firo ASC", "high": "price_firo DESC"}.get(sort, "created DESC")
    if q:
        like = f"%{q}%"
        rows = db.execute(f"SELECT * FROM products WHERE active=1 AND (title LIKE ? OR summary LIKE ?) "
                          f"ORDER BY {order} LIMIT 120", (like, like)).fetchall()
    else:
        rows = db.execute(f"SELECT * FROM products WHERE active=1 ORDER BY {order} LIMIT 120").fetchall()
    tok   = _current_tok()
    owned = set()
    if tok:
        owned = {r["product_id"] for r in db.execute(
            "SELECT product_id FROM purchases WHERE token_id=?", (tok["id"],)).fetchall()}
    return render_template("shop.html", products=rows, q=q, sort=sort, owned=owned,
                           ratings=_rating_map(db, [r["id"] for r in rows]))


@app.route("/shop/<pid>")
def product_page(pid):
    if not _shop_visible():
        if not _shop_on():
            abort(404)
        return redirect(url_for("token_login"))
    db   = get_db()
    prod = _product(db, pid)
    if not prod:
        abort(404)
    tok    = _current_tok()
    owned  = _owns(db, tok, pid)
    state  = ""
    if tok and not owned:
        if request.args.get("check") or request.args.get("paid"):
            state = _check_pending(tok, "product", pid)
            owned = _owns(db, tok, pid)
        else:
            open_pmt = db.execute(
                "SELECT status FROM firo_payments WHERE token_id=? AND kind='product' AND product_id=? "
                "AND status IN ('pending','underpaid') ORDER BY created DESC LIMIT 1", (tok["id"], pid)
            ).fetchone()
            state = open_pmt["status"] if open_pmt else ""
    mine = None
    if tok and owned:
        mine = db.execute("SELECT stars, note FROM product_ratings WHERE product_id=? AND token_id=?",
                          (pid, tok["id"])).fetchone()
    reviews = db.execute(
        "SELECT r.stars, r.note, r.updated, r.created, "
        "COALESCE(NULLIF(t.claimed_name,''), t.label, 'Member') AS who, t.verified AS who_verified "
        "FROM product_ratings r LEFT JOIN tokens t ON t.id = r.token_id "
        "WHERE r.product_id=? ORDER BY COALESCE(NULLIF(r.updated,''), r.created) DESC LIMIT 30", (pid,)
    ).fetchall()
    dist = {k: 0 for k in range(1, 6)}
    for r in db.execute("SELECT stars, COUNT(*) AS n FROM product_ratings WHERE product_id=? GROUP BY stars",
                        (pid,)).fetchall():
        dist[r["stars"]] = r["n"]
    rating = _rating_map(db, [pid]).get(pid, {"avg": 0, "n": 0})
    return render_template("product.html", p=prod, owned=owned, state=state, mine=mine,
                           reviews=reviews, rating=rating, dist=dist,
                           pay_enabled=bool(FIROGATE_API_KEY),
                           just_cancelled=bool(request.args.get("cancelled")))


@app.route("/shop/<pid>/buy", methods=["POST"])
@require_poster
def product_buy(pid):
    if not _csrf_ok(): abort(403)
    if _is_admin():
        return redirect(url_for("product_page", pid=pid))
    tok = _current_tok()
    if not tok:
        return redirect(url_for("token_login"))
    db   = get_db()
    prod = _product(db, pid)
    if not prod or not prod["active"] or not _shop_on():
        abort(404)
    if _owns(db, tok, pid):
        return redirect(url_for("product_page", pid=pid))
    if _chk(_rl_pay, tok["id"], 8, 600):
        return render_template("error.html", code=429, msg="Too many tries. Please wait a few minutes."), 429
    if not FIROGATE_API_KEY:
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503

    existing = _pending_payment(db, tok["id"], "product", pid)
    if existing and existing["checkout_url"]:
        return redirect(existing["checkout_url"])

    base = _get_site_base()
    if not base:
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503
    order_id = f"SHOP-{pid[:8]}-{tok['id'][:8]}-{uuid.uuid4().hex[:8]}"
    try:
        result = _firogate_request("/api/payments/create", {
            "amount_firo":       float(prod["price_firo"]),
            "order_id":          order_id,
            "order_description": prod["title"][:120],
            "success_url":       f"{base}/shop/{pid}?paid=1",
            "cancel_url":        f"{base}/shop/{pid}/cancel",
            "timeout_minutes":   FIROGATE_TIMEOUT_MIN,
        })
    except GatewayError as exc:
        app.logger.error("product_buy: %s", exc)
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503

    checkout_url = str(result.get("checkout_url") or "")
    fg_id        = str(result.get("payment_id") or "")
    if not checkout_url.startswith(("https://", "http://")) or not fg_id:
        app.logger.error("product_buy: FiroGate answer had no checkout_url or payment_id")
        return render_template("error.html", code=503, msg=_PAY_DOWN_MSG), 503

    db.execute(
        "INSERT INTO firo_payments (id, token_id, order_id, fg_payment_id, amount_firo, status, "
        "checkout_url, expires_at, created, kind, product_id) "
        "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, 'product', ?)",
        (uuid.uuid4().hex, tok["id"], order_id, fg_id[:64], float(prod["price_firo"]),
         checkout_url, str(result.get("expires_at") or "")[:40], _now(), pid)
    )
    db.commit()
    log_action("shop_order_started", f"order={order_id}")
    return redirect(checkout_url)


@app.route("/shop/<pid>/status")
@require_poster
def product_status(pid):
    tok = _current_tok()
    if not tok or not _product(get_db(), pid):
        return {"owned": False}
    if _owns(get_db(), tok, pid):
        return {"owned": True}
    state = _check_pending(tok, "product", pid)
    return {"owned": _owns(get_db(), tok, pid), "state": state}


@app.route("/shop/<pid>/cancel")
@require_poster
def product_cancel(pid):
    tok   = _current_tok()
    fg_id = request.args.get("payment_id", "")[:64]
    if tok and fg_id:
        db = get_db()
        db.execute("UPDATE firo_payments SET status='cancelled' WHERE token_id=? AND fg_payment_id=? "
                   "AND kind='product' AND product_id=? AND status='pending'", (tok["id"], fg_id, pid))
        db.commit()
    return redirect(url_for("product_page", pid=pid, cancelled=1))


@app.route("/shop/<pid>/rate", methods=["POST"])
@require_poster
def product_rate(pid):
    if not _csrf_ok(): abort(403)
    tok = _current_tok()
    db  = get_db()
    if not tok or not _product(db, pid) or not _owns(db, tok, pid):
        abort(403)
    if _chk(_rl_rate, tok["id"], 10, 600):
        abort(429)
    try:
        stars = int(request.form.get("stars", "0"))
    except ValueError:
        stars = 0
    if stars < 1 or stars > 5:
        return redirect(url_for("product_page", pid=pid, rate_err=1) + "#rate")
    note = re.sub(r"\s+", " ", request.form.get("note", "")).strip()[:280]
    db.execute(
        "INSERT INTO product_ratings (product_id, token_id, stars, note, created, updated) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(product_id, token_id) DO UPDATE SET stars=excluded.stars, note=excluded.note, updated=excluded.updated",
        (pid, tok["id"], stars, note, _now(), _now())
    )
    db.commit()
    return redirect(url_for("product_page", pid=pid, rated=1) + "#rate")


@app.route("/shop/<pid>/download")
@require_poster
def product_download(pid):
    tok = _current_tok()
    db  = get_db()
    prod = _product(db, pid, only_active=False)
    if not prod or not prod["file_name"]:
        abort(404)
    if not _is_admin() and not (tok and _owns(db, tok, pid)):
        abort(403)
    who = tok["id"] if tok else "admin"
    if _chk(_rl_dl, who, 30, 600):
        abort(429)
    path = os.path.join(PRODUCT_DIR, prod["file_name"])
    if not re.fullmatch(r"[0-9a-f]{32}\.bin", prod["file_name"]) or not os.path.isfile(path):
        abort(404)
    from flask import send_file
    resp = send_file(path, mimetype="application/octet-stream", as_attachment=True,
                     download_name=prod["file_label"] or "download", max_age=0)
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# ── Shop admin ─────────────────────────────────────────────────────────────

def _product_form(db, existing=None):
    """Read and check the product form. Returns (values, error)."""
    f = request.form
    title   = f.get("title", "").strip()[:140]
    summary = f.get("summary", "").strip()[:240]
    body    = f.get("body", "").strip()[:20000]
    secret  = f.get("secret_text", "").strip()[:4000]
    try:
        price = round(float(f.get("price_firo", "0")), 8)
    except ValueError:
        price = 0
    if not title:
        return None, "Add a title."
    if price <= 0 or price > 100000:
        return None, "Price must be more than 0 FIRO."
    vals = {"title": title, "summary": summary, "body": body, "secret_text": secret,
            "price_firo": price, "active": 1 if f.get("active") else 0}
    imgs = save_images([request.files.get("image")]) if request.files.get("image") else []
    if imgs:
        vals["image"] = imgs[0]
    elif existing is not None and f.get("remove_image"):
        vals["image"] = ""
    try:
        saved = _save_product_file(request.files.get("file"))
    except ValueError as exc:
        return None, str(exc)
    if saved:
        vals["file_name"], vals["file_label"], vals["file_size"] = saved
    elif existing is not None and f.get("remove_file"):
        vals.update(file_name="", file_label="", file_size=0)
    has_file = vals.get("file_name", existing["file_name"] if existing else "")
    if not has_file and not secret:
        if saved:
            _delete_product_file(saved[0])
        return None, "Add a file or the text buyers get."
    return vals, None


@app.route(f"/{ADMIN_PREFIX}/products/new", methods=["GET", "POST"])
@require_admin
def admin_product_new():
    error = None
    if request.method == "POST":
        if not _csrf_ok(): abort(403)
        db = get_db()
        vals, error = _product_form(db)
        if vals:
            pid = uuid.uuid4().hex
            db.execute(
                "INSERT INTO products (id, title, summary, body, price_firo, image, file_name, file_label, "
                "file_size, secret_text, active, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, vals["title"], vals["summary"], vals["body"], vals["price_firo"], vals.get("image", ""),
                 vals.get("file_name", ""), vals.get("file_label", ""), vals.get("file_size", 0),
                 vals["secret_text"], vals["active"], _now(), _now()))
            db.commit()
            log_action("product_created", vals["title"][:80])
            return redirect(url_for("admin_dashboard", tab="products"))
    return render_template("admin_product.html", p=None, error=error)


@app.route(f"/{ADMIN_PREFIX}/products/<pid>", methods=["GET", "POST"])
@require_admin
def admin_product_edit(pid):
    db   = get_db()
    prod = _product(db, pid, only_active=False)
    if not prod:
        abort(404)
    error = None
    if request.method == "POST":
        if not _csrf_ok(): abort(403)
        vals, error = _product_form(db, prod)
        if vals:
            if "file_name" in vals and vals["file_name"] != prod["file_name"]:
                _delete_product_file(prod["file_name"])
            vals["updated"] = _now()
            cols = ", ".join(f"{k}=?" for k in vals)
            db.execute(f"UPDATE products SET {cols} WHERE id=?", (*vals.values(), pid))
            db.commit()
            log_action("product_updated", vals["title"][:80])
            return redirect(url_for("admin_dashboard", tab="products"))
    return render_template("admin_product.html", p=prod, error=error)


@app.route(f"/{ADMIN_PREFIX}/products/<pid>/delete", methods=["POST"])
@require_admin
def admin_product_delete(pid):
    if not _csrf_ok(): abort(403)
    db   = get_db()
    prod = _product(db, pid, only_active=False)
    if not prod:
        abort(404)
    if db.execute("SELECT 1 FROM purchases WHERE product_id=?", (pid,)).fetchone():
        db.execute("UPDATE products SET active=0, updated=? WHERE id=?", (_now(), pid))
        log_action("product_hidden", prod["title"][:80])
    else:
        db.execute("DELETE FROM products WHERE id=?", (pid,))
        db.execute("DELETE FROM product_ratings WHERE product_id=?", (pid,))
        _delete_product_file(prod["file_name"])
        log_action("product_deleted", prod["title"][:80])
    db.commit()
    return redirect(url_for("admin_dashboard", tab="products"))


# ── Contributor ────────────────────────────────────────────────────────────
@app.route("/contribute")
@require_poster
def contributor_dashboard():
    if _is_admin(): return redirect(url_for("admin_dashboard"))
    # Re-fetch fresh from DB so verified badge reflects latest state
    raw = request.cookies.get("dn_token", "")
    tok = _get_token_row(raw)
    if not tok: return redirect(url_for("token_login"))
    db    = get_db()
    posts = db.execute("SELECT * FROM posts WHERE token_id=? ORDER BY created DESC",(tok["id"],)).fetchall()
    payments = db.execute(
        "SELECT f.order_id, f.amount_firo, f.amount_received, f.status, f.txid, f.created, f.confirmed_at, "
        "f.kind, f.product_id, COALESCE(p.title, '') AS product_title "
        "FROM firo_payments f LEFT JOIN products p ON p.id = f.product_id "
        "WHERE f.token_id=? ORDER BY f.created DESC LIMIT 10", (tok["id"],)
    ).fetchall()
    purchases = db.execute(
        "SELECT p.id, p.title, p.image, u.created FROM purchases u JOIN products p ON p.id = u.product_id "
        "WHERE u.token_id=? ORDER BY u.created DESC", (tok["id"],)
    ).fetchall()
    return render_template("contributor_dashboard.html",
                           tok_row=tok, posts=[_enrich(p) for p in posts], payments=payments,
                           purchases=purchases,
                           pay_enabled=bool(FIROGATE_API_KEY),
                           verify_amount=FIROGATE_VERIFY_AMOUNT)

@app.route("/contribute/profile", methods=["GET","POST"])
@require_poster
def contributor_profile():
    """Allow contributor to update their profile (avatar)."""
    if _is_admin(): return redirect(url_for("admin_dashboard"))
    raw = request.cookies.get("dn_token", "")
    tok = _get_token_row(raw)
    if not tok: return redirect(url_for("token_login"))
    db = get_db()
    error = None
    success = None
    
    if request.method == "POST":
        if not _csrf_ok():
            error = "Invalid form submission. Please refresh and try again."
            return render_template("contributor_profile.html", tok_row=tok, error=error, success=None, verify_amount=FIROGATE_VERIFY_AMOUNT)
        avatar_file = request.files.get("avatar")

        if avatar_file and avatar_file.filename:
            allowed = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
            ext = avatar_file.filename.rsplit('.', 1)[-1].lower() if '.' in avatar_file.filename else ''
            if ext not in allowed:
                error = "Invalid file type. Use PNG, JPG, GIF or WEBP."
            else:
                raw_data = avatar_file.read(app.config["AVATAR_MAX"] + 1)
                if len(raw_data) > app.config["AVATAR_MAX"]:
                    error = "Image too large (max 2 MB)."
                else:
                    try:
                        clean_data = process_avatar_image(raw_data)
                    except Exception:
                        error = "Could not process image. Please try a different file."
                        clean_data = None
                    if clean_data:
                        filename = f"av_{tok['id'][:8]}_{secrets.token_hex(4)}.jpg"
                        avatar_path = os.path.join(app.config["AVATAR_FOLDER"], filename)
                        # Delete old avatar if exists
                        if tok["claimed_avatar"]:
                            old_path = os.path.join(app.config["AVATAR_FOLDER"], tok["claimed_avatar"])
                            if os.path.exists(old_path):
                                try: os.remove(old_path)
                                except OSError: pass
                        open(avatar_path, "wb").write(clean_data)
                        db.execute("UPDATE tokens SET claimed_avatar=? WHERE id=?", (filename, tok["id"]))
                        db.commit()
                        log_action("profile_updated", f"Avatar updated for {tok['claimed_name'] or tok['label']}")
                        success = "Profile updated!"
                        tok = db.execute("SELECT * FROM tokens WHERE id=?", (tok["id"],)).fetchone()
        else:
            error = "Please select an image file."
    
    return render_template("contributor_profile.html", tok_row=tok, error=error, success=success,
                           verify_amount=FIROGATE_VERIFY_AMOUNT)

@app.route("/contribute/profile/remove-avatar", methods=["POST"])
@require_poster
def contributor_remove_avatar():
    """Remove contributor's avatar."""
    if not _csrf_ok(): abort(403)
    if _is_admin(): return redirect(url_for("admin_dashboard"))
    tok = _current_tok()
    db = get_db()
    
    if tok["claimed_avatar"]:
        old_path = os.path.join(app.static_folder, "avatars", tok["claimed_avatar"])
        if os.path.exists(old_path):
            try: os.remove(old_path)
            except OSError: pass
        db.execute("UPDATE tokens SET claimed_avatar='' WHERE id=?", (tok["id"],))
        db.commit()
    
    return redirect(url_for("contributor_profile"))

@app.route("/contribute/new", methods=["GET","POST"])
@require_poster
def new_post():
    admin = _is_admin()
    db    = get_db()

    # Always re-fetch fresh token from DB (not cached) so verified status is current
    if not admin:
        raw = request.cookies.get("dn_token", "")
        tok = _get_token_row(raw)
        if not tok:
            return redirect(url_for("token_login"))
    else:
        tok = None

    # Contributors must have a verified badge to post
    if not admin and not tok["verified"]:
        return render_template("verify_required.html", tok_row=tok,
                               verify_amount=FIROGATE_VERIFY_AMOUNT)

    # Admin sees full author + role controls; contributor sees none
    authors     = db.execute("SELECT * FROM authors ORDER BY name").fetchall() if admin else []
    avail_roles = ALL_ROLES if admin else []   # contributors never pick role
    error = None

    if request.method == "POST":
        if not _csrf_ok(): abort(403)
        title = request.form.get("title","").strip()
        body  = request.form.get("body","").strip()
        files = request.files.getlist("images")

        if admin:
            # Admin chooses author + role from the form
            author_id = request.form.get("author_id","").strip()
            role      = request.form.get("role","").strip()
            if role not in ALL_ROLES: role = ""
            ar          = _author_by_id(author_id)
            author_name = ar["name"] if ar else DEFAULT_AUTHOR
        else:
            # Contributor: use claimed_name if set, otherwise author profile or default
            author_id = tok["author_id"] if tok else ""
            role      = tok["default_role"] if tok else ""
            if role not in ALL_ROLES: role = ""
            
            # Priority: claimed_name > author profile > default
            if tok and tok["claimed_name"]:
                author_name = tok["claimed_name"]
            else:
                ar = _author_by_id(author_id)
                author_name = ar["name"] if ar else DEFAULT_AUTHOR

        if not title or not body:
            error = "Title and body are required."
        else:
            imgs        = save_images(files)
            token_id    = "" if admin else tok["id"]
            db.execute(
                "INSERT INTO posts (id,title,body,images,author,role,views,pinned,created,token_id,author_id)"
                " VALUES (?,?,?,?,?,?,0,0,?,?,?)",
                (uuid.uuid4().hex, title, body, json.dumps(imgs), author_name, role,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"), token_id, author_id or "")
            )
            db.commit()
            log_action("post_created", f"'{title}' by {'admin' if admin else (tok['claimed_name'] or tok['label'])}")
            return redirect(url_for("admin_dashboard") if admin else url_for("contributor_dashboard"))

    # For contributor: resolve the author name + role from their token so the template can show it
    contrib_author_name = ""
    contrib_role        = ""
    if not admin and tok:
        # Priority: claimed_name > author profile > default
        if tok["claimed_name"]:
            contrib_author_name = tok["claimed_name"]
        else:
            ar = _author_by_id(tok["author_id"])
            contrib_author_name = ar["name"] if ar else DEFAULT_AUTHOR
        contrib_role = tok["default_role"] or ""

    return render_template("new_post.html", error=error,
                           roles=avail_roles, authors=authors,
                           is_admin=admin,
                           tok_label=tok["label"] if tok else "",
                           contrib_author_name=contrib_author_name,
                           contrib_role=contrib_role)

@app.route("/contribute/delete/<post_id>", methods=["POST"])
@require_poster
def contributor_delete(post_id):
    if not _csrf_ok(): abort(403)
    if _is_admin(): return redirect(url_for("admin_delete", post_id=post_id))
    tok  = _current_tok(); db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=? AND token_id=?",
                      (post_id, tok["id"])).fetchone()
    if not post: abort(403)
    _del_images(post)
    db.execute("DELETE FROM posts WHERE id=?", (post_id,))
    db.commit()
    log_action("post_deleted", f"by contributor {tok['label']}")
    return redirect(url_for("contributor_dashboard"))

# ── Admin login ────────────────────────────────────────────────────────────
@app.route(f"/{ADMIN_PREFIX}/{ADMIN_SUFFIX}", methods=["GET","POST"])
def admin_login():
    if _is_admin(): return redirect(url_for("admin_dashboard"))
    ip = request.remote_addr or "unknown"
    error = None
    if request.method == "POST":
        if _chk(_rl_login, ip, 5, 300):
            error = "Too many attempts. Wait 5 minutes."
        elif not _csrf_ok():
            error = "Invalid form submission. Please refresh and try again."
        elif check_admin_password(request.form.get("password","")):
            _rotate_session()                    # prevent session fixation
            session.permanent = True
            session["admin"]  = True
            log_action("admin_login", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            time.sleep(1); error = "Invalid credentials."
            log_action("admin_login_fail", "bad password")
    return render_template("admin_login.html", error=error)

@app.route(f"/{ADMIN_PREFIX}/out")
def admin_logout():
    session.clear()
    return redirect(url_for("index"))

# ── Admin dashboard ────────────────────────────────────────────────────────
@app.route(f"/{ADMIN_PREFIX}/panel")
@require_admin
def admin_dashboard():
    db      = get_db()
    # Post filtering
    q       = request.args.get("q","").strip()[:100]
    filt    = request.args.get("f","all")   # all | pinned | contributor
    base    = "SELECT * FROM posts"
    conds   = []; params = []
    if q:
        conds.append("(title LIKE ? OR author LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if filt == "pinned":
        conds.append("pinned=1")
    elif filt == "contributor":
        conds.append("token_id != ''")
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    posts   = db.execute(f"{base}{where} ORDER BY pinned DESC, created DESC",
                         params).fetchall()
    tokens  = db.execute("SELECT * FROM tokens ORDER BY revoked, created DESC").fetchall()
    authors = db.execute("SELECT * FROM authors ORDER BY name").fetchall()
    # Stats
    total_posts = db.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    total_views = db.execute("SELECT COALESCE(SUM(views),0) FROM posts").fetchone()[0]
    total_contrib = db.execute("SELECT COUNT(*) FROM posts WHERE token_id!=''").fetchone()[0]
    active_toks = db.execute("SELECT COUNT(*) FROM tokens WHERE revoked=0").fetchone()[0]
    activity   = db.execute("SELECT * FROM activity_log ORDER BY ts DESC LIMIT 20").fetchall()
    new_tok    = session.pop("new_token", None)
    new_label  = session.pop("new_token_label", None)
    bulk_created = session.pop("bulk_created", None)
    bulk_batch   = session.pop("bulk_batch", None)
    site_title   = get_setting("site_title","GateForum")
    site_tagline = get_setting("site_tagline","")
    maintenance  = get_setting("maintenance","0")
    ppp          = get_setting("posts_per_page","10")
    tab = request.args.get("tab", "posts")
    if tab not in ("posts", "people", "payments", "products", "settings"):
        tab = "posts"
    payments = get_db().execute(
        "SELECT p.order_id, p.amount_firo, p.amount_received, p.status, p.txid, p.created, p.confirmed_at, "
        "p.kind, COALESCE(pr.title, '') AS product_title, "
        "COALESCE(NULLIF(t.claimed_name,''), t.label, '') AS who "
        "FROM firo_payments p LEFT JOIN tokens t ON t.id = p.token_id "
        "LEFT JOIN products pr ON pr.id = p.product_id "
        "ORDER BY p.created DESC LIMIT 100"
    ).fetchall()
    pay_sum = get_db().execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(COALESCE(NULLIF(amount_received,0), amount_firo)),0) AS firo "
        "FROM firo_payments WHERE status='confirmed'"
    ).fetchone()
    products = get_db().execute(
        "SELECT p.*, (SELECT AVG(stars) FROM product_ratings r WHERE r.product_id=p.id) AS avg_stars, "
        "(SELECT COUNT(*) FROM product_ratings r WHERE r.product_id=p.id) AS n_ratings, "
        "(SELECT COALESCE(SUM(amount_firo),0) FROM purchases u WHERE u.product_id=p.id) AS earned "
        "FROM products p ORDER BY p.active DESC, p.created DESC"
    ).fetchall()
    return render_template("admin_dashboard.html", tab=tab, products=products,
        shop_enabled=get_setting("shop_enabled", "1"), shop_visibility=get_setting("shop_visibility", "everyone"),
        payments=payments, pay_sum=pay_sum,
        pay_ready={"api": bool(FIROGATE_API_KEY), "hook": bool(FIROGATE_WEBHOOK_SECRET),
                   "base": bool(os.environ.get("SITE_BASE_URL", "")),
                   "hook_url": (os.environ.get("SITE_BASE_URL", "").rstrip("/") or "https://your-site") + "/webhook/firogate"},
        verify_amount=FIROGATE_VERIFY_AMOUNT,
        posts=posts, tokens=tokens, authors=authors,
        new_token=new_tok, new_token_label=new_label,
        bulk_created=bulk_created, bulk_batch=bulk_batch,
        stats={"posts":total_posts,"views":total_views,
               "contrib":total_contrib,"active_toks":active_toks},
        activity=activity,
        q=q, filt=filt,
        site_title=site_title, site_tagline=site_tagline,
        maintenance=maintenance, ppp=ppp,
        all_roles=ALL_ROLES)

# ── Admin post actions ─────────────────────────────────────────────────────
@app.route(f"/{ADMIN_PREFIX}/reports")
@require_admin
def admin_reports():
    db = get_db()
    reports = db.execute(
        """SELECT r.*, p.title as post_title
           FROM post_reports r
           LEFT JOIN posts p ON r.post_id = p.id
           WHERE r.resolved=0
           ORDER BY r.created DESC LIMIT 100"""
    ).fetchall()
    return render_template("admin_reports.html", reports=reports)


@app.route(f"/{ADMIN_PREFIX}/reports/resolve/<report_id>", methods=["POST"])
@require_admin
def admin_resolve_report(report_id):
    if not _csrf_ok(): abort(403)
    db = get_db()
    db.execute("UPDATE post_reports SET resolved=1 WHERE id=?", (report_id,))
    db.commit()
    log_action("report_resolved", f"report={report_id[:8]}")
    return redirect(url_for("admin_reports"))


@app.route(f"/{ADMIN_PREFIX}/reports/delete/<report_id>/<post_id>", methods=["POST"])
@require_admin
def admin_delete_reported(report_id, post_id):
    """Delete the reported post and resolve the report in one action."""
    if not _csrf_ok(): abort(403)
    # Validate post_id is safe hex
    if not re.match(r'^[a-f0-9]{32}$', post_id):
        abort(400)
    db   = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if post:
        _del_images(post)
        db.execute("DELETE FROM posts WHERE id=?", (post_id,))
        log_action("post_deleted_reported",
                   f"admin deleted reported post '{post['title']}'")
    # Resolve all reports for this post
    db.execute(
        "UPDATE post_reports SET resolved=1 WHERE post_id=?", (post_id,)
    )
    db.commit()
    return redirect(url_for("admin_reports"))


@app.route(f"/{ADMIN_PREFIX}/delete/<post_id>", methods=["POST"])
@require_admin
def admin_delete(post_id):
    if not _csrf_ok(): abort(403)
    db   = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if post:
        _del_images(post)
        db.execute("DELETE FROM posts WHERE id=?", (post_id,))
        db.commit()
        log_action("post_deleted", f"admin deleted '{post['title']}'")
    return redirect(url_for("admin_dashboard"))

@app.route(f"/{ADMIN_PREFIX}/pin/<post_id>", methods=["POST"])
@require_admin
def admin_pin(post_id):
    if not _csrf_ok(): abort(403)
    db   = get_db()
    post = db.execute("SELECT pinned FROM posts WHERE id=?", (post_id,)).fetchone()
    if post:
        db.execute("UPDATE posts SET pinned=? WHERE id=?",
                   (0 if post["pinned"] else 1, post_id))
        db.commit()
    return redirect(url_for("admin_dashboard"))

@app.route(f"/{ADMIN_PREFIX}/edit/<post_id>", methods=["GET","POST"])
@require_admin
def admin_edit_post(post_id):
    db   = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post: abort(404)
    authors = db.execute("SELECT * FROM authors ORDER BY name").fetchall()
    error   = None
    if request.method == "POST":
        if not _csrf_ok(): abort(403)
        title     = request.form.get("title","").strip()
        body      = request.form.get("body","").strip()
        role      = request.form.get("role","")
        author_id = request.form.get("author_id","").strip()
        if role not in ALL_ROLES + [""]: role = post["role"]
        if not title or not body:
            error = "Title and body are required."
        else:
            ar = _author_by_id(author_id)
            author_name = ar["name"] if ar else post["author"]
            db.execute(
                "UPDATE posts SET title=?,body=?,role=?,author=?,author_id=?,edited=? WHERE id=?",
                (title, body, role, author_name, author_id or "",
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"), post_id)
            )
            # Handle additional images
            new_files = request.files.getlist("images")
            if any(f.filename for f in new_files):
                new_imgs = save_images(new_files)
                try:
                    existing = json.loads(post["images"])
                except Exception:
                    existing = []
                combined = (existing + new_imgs)[:app.config["MAX_IMAGES_PER_POST"]]
                db.execute("UPDATE posts SET images=? WHERE id=?",
                           (json.dumps(combined), post_id))
            db.commit()
            log_action("post_edited", f"admin edited '{title}'")
            return redirect(url_for("admin_dashboard"))
    return render_template("admin_edit_post.html",
                           post=post, authors=authors,
                           roles=ALL_ROLES+[""],
                           error=error)

# ── Admin settings ─────────────────────────────────────────────────────────
@app.route(f"/{ADMIN_PREFIX}/settings", methods=["POST"])
@require_admin
def admin_settings():
    if not _csrf_ok(): abort(403)
    set_setting("site_title",    request.form.get("site_title","GateForum").strip()[:60] or "GateForum")
    set_setting("site_tagline",  request.form.get("site_tagline","").strip()[:120])
    set_setting("posts_per_page",request.form.get("posts_per_page","10").strip())
    set_setting("maintenance",   "1" if request.form.get("maintenance") else "0")
    set_setting("shop_enabled",  "1" if request.form.get("shop_enabled") else "0")
    vis = request.form.get("shop_visibility", "everyone")
    set_setting("shop_visibility", vis if vis in ("everyone", "members") else "everyone")
    log_action("settings_updated","admin updated site settings")
    return redirect(url_for("admin_dashboard", tab="settings"))

# ── Author management ──────────────────────────────────────────────────────
@app.route(f"/{ADMIN_PREFIX}/authors/create", methods=["POST"])
@require_admin
def author_create():
    if not _csrf_ok(): abort(403)
    name = request.form.get("name","").strip()[:80]
    if not name: return redirect(url_for("admin_dashboard", tab="people"))
    db = get_db()
    if db.execute("SELECT id FROM authors WHERE name=?", (name,)).fetchone():
        return redirect(url_for("admin_dashboard", tab="people"))
    av         = save_avatar(request.files.get("avatar"))
    verified   = 1 if request.form.get("verified") else 0
    role_badge = request.form.get("role_badge","").strip()
    if role_badge not in ALL_ROLES: role_badge = ""
    db.execute(
        "INSERT INTO authors (id,name,avatar,verified,role_badge,created) VALUES (?,?,?,?,?,?)",
        (uuid.uuid4().hex, name, av, verified, role_badge,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    db.commit()
    log_action("author_created", name)
    return redirect(url_for("admin_dashboard", tab="people"))

@app.route(f"/{ADMIN_PREFIX}/authors/edit/<aid>", methods=["POST"])
@require_admin
def author_edit(aid):
    if not _csrf_ok(): abort(403)
    db = get_db()
    a  = db.execute("SELECT * FROM authors WHERE id=?", (aid,)).fetchone()
    if not a: abort(404)
    name       = request.form.get("name","").strip()[:80] or a["name"]
    verified   = 1 if request.form.get("verified") else 0
    role_badge = request.form.get("role_badge","").strip()
    if role_badge not in ALL_ROLES: role_badge = ""
    av = a["avatar"]
    new_av = save_avatar(request.files.get("avatar"))
    if new_av:
        if av:
            try: os.remove(os.path.join(app.config["AVATAR_FOLDER"], av))
            except Exception: pass
        av = new_av
    db.execute("UPDATE authors SET name=?,avatar=?,verified=?,role_badge=? WHERE id=?",
               (name, av, verified, role_badge, aid))
    db.execute("UPDATE posts SET author=? WHERE author_id=?", (name, aid))
    db.commit()
    return redirect(url_for("admin_dashboard", tab="people"))

@app.route(f"/{ADMIN_PREFIX}/authors/delete/<aid>", methods=["POST"])
@require_admin
def author_delete(aid):
    if not _csrf_ok(): abort(403)
    db = get_db()
    a  = db.execute("SELECT * FROM authors WHERE id=?", (aid,)).fetchone()
    if a:
        if a["avatar"]:
            try: os.remove(os.path.join(app.config["AVATAR_FOLDER"], a["avatar"]))
            except Exception: pass
        db.execute("DELETE FROM authors WHERE id=?", (aid,))
        db.commit()
    return redirect(url_for("admin_dashboard", tab="people"))

# ── Token management ───────────────────────────────────────────────────────
@app.route(f"/{ADMIN_PREFIX}/tokens/create", methods=["POST"])
@require_admin
def token_create():
    if not _csrf_ok(): abort(403)
    label        = request.form.get("label","").strip()[:80] or "Contributor"
    note         = request.form.get("note","").strip()[:200]
    author_id    = request.form.get("author_id","").strip()
    default_role = request.form.get("default_role","").strip()
    is_pool      = 1 if request.form.get("is_pool") else 0
    if default_role not in ALL_ROLES: default_role = ""
    # Validate author_id belongs to a real author
    db = get_db()
    if author_id and not db.execute("SELECT id FROM authors WHERE id=?", (author_id,)).fetchone():
        author_id = ""
    raw = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO tokens (id,label,token_hash,allowed_roles,note,author_id,default_role,is_pool,pool_token,created,revoked,claimed,claimed_at,claimed_by)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,0,0,'','')",
        (uuid.uuid4().hex, label, _hash_token(raw), "", note, author_id, default_role, is_pool, raw if is_pool else "",
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    db.commit()
    if is_pool:
        log_action("pool_token_created", label)
    else:
        session["new_token"]       = raw
        session["new_token_label"] = label
        log_action("token_created", label)
    return redirect(url_for("admin_dashboard", tab="people"))

@app.route(f"/{ADMIN_PREFIX}/tokens/bulk-create", methods=["POST"])
@require_admin
def token_bulk_create():
    """Generate 10/25/50/100 pool tokens at once with auto-labels."""
    if not _csrf_ok(): abort(403)
    try:
        count = int(request.form.get("count", 10))
    except (ValueError, TypeError):
        count = 10
    if count not in (10, 25, 50, 100):
        count = 10

    raw_prefix = request.form.get("prefix", "").strip()[:20]
    prefix = re.sub(r'[^a-zA-Z0-9_-]', '', raw_prefix) or "Anon"

    db = get_db()
    batch_id = secrets.token_hex(3)   # 6-char hex batch ID
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for i in range(1, count + 1):
        label = f"{prefix}-{batch_id}-{i:02d}"
        raw   = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO tokens "
            "(id,label,token_hash,allowed_roles,note,author_id,default_role,"
            " is_pool,pool_token,created,revoked,claimed,claimed_at,claimed_by)"
            " VALUES (?,?,?,?,?,?,?,1,?,?,0,0,'','')",
            (uuid.uuid4().hex, label, _hash_token(raw), "",
             f"bulk-batch-{batch_id}", "", "", raw, ts)
        )
    db.commit()
    log_action("bulk_tokens_created",
               f"{count} pool tokens — batch {batch_id} — prefix '{prefix}'")
    session["bulk_created"] = count
    session["bulk_batch"]   = batch_id
    return redirect(url_for("admin_dashboard", tab="people"))

@app.route("/claim-token/<token_id>", methods=["GET", "POST"])
def claim_pool_token(token_id):
    """Claim a token from the public pool - show form to enter display name."""
    if _current_tok(): return redirect(url_for("contributor_dashboard"))
    if _is_admin():    return redirect(url_for("admin_dashboard"))
    
    db = get_db()
    token = db.execute(
        "SELECT * FROM tokens WHERE id=? AND is_pool=1 AND claimed=0 AND revoked=0",
        (token_id,)
    ).fetchone()
    
    if not token:
        return redirect(url_for("token_login"))
    
    error = None
    
    if request.method == "POST":
        if not _csrf_ok(): abort(403)
        # Get and validate the display name
        display_name = request.form.get("display_name", "").strip()
        
        # Sanitize: remove dangerous characters, limit length
        display_name = re.sub(r'[<>&"\']', '', display_name)[:50].strip()
        
        if not display_name or len(display_name) < 2:
            error = "Please enter a valid name (at least 2 characters)."
        elif len(display_name) > 50:
            error = "Name is too long (max 50 characters)."
        else:
            # Check if name is already taken by another claimed token or author
            existing = db.execute(
                "SELECT id FROM tokens WHERE claimed_name=? AND id!=?",
                (display_name, token_id)
            ).fetchone()
            existing_author = db.execute(
                "SELECT id FROM authors WHERE name=?",
                (display_name,)
            ).fetchone()
            
            if existing or existing_author:
                error = "This name is already taken. Please choose another."
            else:
                # Mark as claimed with the chosen name
                db.execute(
                    "UPDATE tokens SET claimed=1, claimed_at=?, claimed_by=?, claimed_name=? WHERE id=?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "",
                     display_name,
                     token_id)
                )
                db.commit()
                log_action("token_claimed", f"Pool token '{token['label']}' claimed as '{display_name}'")
                
                # Store in session to show on reveal page
                session["claimed_token"] = token["pool_token"]
                session["claimed_token_label"] = token["label"]
                session["claimed_token_name"] = display_name
                
                return redirect(url_for("token_claimed"))
    
    return render_template("claim_token.html", token=token, error=error)

@app.route("/token-claimed")
def token_claimed():
    """Show the claimed token to the user — once only."""
    claimed_token = session.get("claimed_token")
    claimed_label = session.get("claimed_token_label", "")
    claimed_name  = session.get("claimed_token_name", "")

    if not claimed_token:
        return redirect(url_for("token_login"))

    # Clear sensitive data from session first
    session.pop("claimed_token",       None)
    session.pop("claimed_token_label", None)
    session.pop("claimed_token_name",  None)

    # Rotate session ID — we're elevating to authenticated state
    _rotate_session()

    resp = make_response(render_template("token_claimed.html",
                                         token=claimed_token,
                                         label=claimed_label,
                                         display_name=claimed_name))
    resp.set_cookie("dn_token", claimed_token, max_age=7776000,
                    httponly=True, samesite="Lax", secure=False)
    return resp

@app.route(f"/{ADMIN_PREFIX}/tokens/revoke/<tid>", methods=["POST"])
@require_admin
def token_revoke(tid):
    if not _csrf_ok(): abort(403)
    db = get_db()
    db.execute("UPDATE tokens SET revoked=1 WHERE id=?", (tid,))
    db.commit()
    log_action("token_revoked", tid)
    return redirect(url_for("admin_dashboard", tab="people"))

@app.route(f"/{ADMIN_PREFIX}/tokens/verify/<tid>", methods=["POST"])
@require_admin
def token_verify(tid):
    """Toggle verified badge for a token."""
    if not _csrf_ok(): abort(403)
    db = get_db()
    token = db.execute("SELECT verified FROM tokens WHERE id=?", (tid,)).fetchone()
    if token:
        new_status = 0 if token["verified"] else 1
        db.execute("UPDATE tokens SET verified=? WHERE id=?", (new_status, tid))
        db.commit()
        log_action("token_verified" if new_status else "token_unverified", tid)
    return redirect(url_for("admin_dashboard", tab="people"))

@app.route(f"/{ADMIN_PREFIX}/tokens/delete/<tid>", methods=["POST"])
@require_admin
def token_delete(tid):
    if not _csrf_ok(): abort(403)
    db = get_db()
    db.execute("DELETE FROM tokens WHERE id=?", (tid,))
    db.commit()
    return redirect(url_for("admin_dashboard", tab="people"))

# ── Error handlers ─────────────────────────────────────────────────────────
@app.errorhandler(403)
def e403(e): return render_template("error.html", code=403, msg="Access Denied"), 403
@app.errorhandler(404)
def e404(e): return render_template("error.html", code=404, msg="Page Not Found"), 404
@app.errorhandler(413)
def e413(e): return render_template("error.html", code=413, msg="File Too Large"), 413
@app.errorhandler(429)
def e429(e): return render_template("error.html", code=429, msg="Too Many Requests"), 429
@app.errorhandler(500)
def e500(e): return render_template("error.html", code=500, msg="Server Error"), 500
@app.errorhandler(503)
def e503(e): return render_template("error.html", code=503, msg=str(e.description)), 503

@app.context_processor
def _ctx():
    s = get_setting("site_title","GateForum")
    return {
        "current_is_admin": _is_admin(),
        "current_tok_row":  _current_tok(),
        "shop_link":        _shop_visible(),
        "site_title":       s,
        "site_tagline":     get_setting("site_tagline",""),
    }

if __name__ == "__main__":
    app.run(host=os.environ.get("DNet_HOST", "127.0.0.1"), port=int(os.environ.get("DNet_PORT", "5000")), debug=False)