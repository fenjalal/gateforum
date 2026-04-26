#!/usr/bin/env python3
"""
GateForum — DB migration script.
Run once after any upgrade:  python3 migrate.py
Safe to run multiple times (fully idempotent).
"""
import sqlite3, pathlib, sys, os, time, secrets, hashlib

# ── Find DB ────────────────────────────────────────────────────────────────
for candidate in [
    pathlib.Path(__file__).parent / "instance" / "DNet.db",
    pathlib.Path("instance/DNet.db"),
    pathlib.Path("DNet.db"),
]:
    if candidate.exists():
        DB = candidate
        break
else:
    print("ERROR: Cannot find DNet.db")
    print("Run this script from your project folder.")
    sys.exit(1)

print(f"GateForum DB Migration")
print(f"DB: {DB}\n")

db = sqlite3.connect(str(DB))
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA foreign_keys=ON")

# ── 1. Add missing columns ─────────────────────────────────────────────────
print("── Step 1: Column migrations ──")
columns = [
    ("tokens",        "verified",       "INTEGER NOT NULL DEFAULT 0"),
    ("tokens",        "author_id",      "TEXT NOT NULL DEFAULT ''"),
    ("tokens",        "default_role",   "TEXT NOT NULL DEFAULT ''"),
    ("tokens",        "claimed_name",   "TEXT NOT NULL DEFAULT ''"),
    ("tokens",        "claimed_avatar", "TEXT NOT NULL DEFAULT ''"),
    ("authors",       "verified",       "INTEGER NOT NULL DEFAULT 0"),
    ("authors",       "role_badge",     "TEXT NOT NULL DEFAULT ''"),
    ("posts",         "token_id",       "TEXT NOT NULL DEFAULT ''"),
    ("posts",         "author_id",      "TEXT NOT NULL DEFAULT ''"),
    ("posts",         "edited",         "TEXT NOT NULL DEFAULT ''"),
    ("chat",          "reply_to_nick",  "TEXT NOT NULL DEFAULT ''"),
    ("firo_payments", "confirmed_at",   "TEXT NOT NULL DEFAULT ''"),
    ("settings",      "updated",        "TEXT NOT NULL DEFAULT ''"),
]
for table, col, typedef in columns:
    # Check table exists first
    tbl = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if not tbl:
        continue
    try:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
        db.commit()
        print(f"  + {table}.{col}")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e).lower():
            print(f"  ✓ {table}.{col} (exists)")
        else:
            print(f"  ! {table}.{col}: {e}")

# ── 2. Create missing tables ───────────────────────────────────────────────
print("\n── Step 2: Table creation ──")
db.executescript("""
CREATE TABLE IF NOT EXISTS authors (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    avatar     TEXT NOT NULL DEFAULT '',
    verified   INTEGER NOT NULL DEFAULT 0,
    role_badge TEXT NOT NULL DEFAULT '',
    created    TEXT NOT NULL DEFAULT ''
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
    created   TEXT NOT NULL DEFAULT '',
    edited    TEXT NOT NULL DEFAULT '',
    token_id  TEXT NOT NULL DEFAULT '',
    author_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tokens (
    id             TEXT PRIMARY KEY,
    label          TEXT NOT NULL,
    token_hash     TEXT NOT NULL UNIQUE,
    allowed_roles  TEXT NOT NULL DEFAULT '',
    note           TEXT NOT NULL DEFAULT '',
    created        TEXT NOT NULL DEFAULT '',
    revoked        INTEGER NOT NULL DEFAULT 0,
    is_pool        INTEGER NOT NULL DEFAULT 0,
    pool_token     TEXT NOT NULL DEFAULT '',
    claimed        INTEGER NOT NULL DEFAULT 0,
    claimed_at     TEXT NOT NULL DEFAULT '',
    claimed_by     TEXT NOT NULL DEFAULT '',
    claimed_name   TEXT NOT NULL DEFAULT '',
    claimed_avatar TEXT NOT NULL DEFAULT '',
    author_id      TEXT NOT NULL DEFAULT '',
    default_role   TEXT NOT NULL DEFAULT '',
    verified       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
    name    TEXT PRIMARY KEY,
    value   TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS activity_log (
    id     TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ts     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS chat (
    id           TEXT PRIMARY KEY,
    nick         TEXT NOT NULL,
    msg          TEXT NOT NULL,
    ts           TEXT NOT NULL,
    reply_to_id  TEXT NOT NULL DEFAULT '',
    reply_to_nick TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS firo_payments (
    id           TEXT PRIMARY KEY,
    token_id     TEXT NOT NULL,
    order_id     TEXT NOT NULL UNIQUE,
    amount_firo  REAL NOT NULL DEFAULT 3.99,
    status       TEXT NOT NULL DEFAULT 'pending',
    checkout_url TEXT NOT NULL DEFAULT '',
    created      TEXT NOT NULL DEFAULT '',
    confirmed_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS flask_sessions (
    sid     TEXT PRIMARY KEY,
    data    TEXT NOT NULL DEFAULT '{}',
    expires INTEGER NOT NULL DEFAULT 0
);
""")
db.commit()

# Indexes
idx = [
    ("idx_pc",         "posts",         "created DESC"),
    ("idx_pp",         "posts",         "pinned DESC, created DESC"),
    ("idx_firo_token", "firo_payments", "token_id"),
    ("idx_firo_order", "firo_payments", "order_id"),
    ("idx_ses_exp",    "flask_sessions","expires"),
]
for name, table, cols in idx:
    try:
        db.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table}({cols})")
        db.commit()
    except Exception:
        pass

print("  ✓ All tables and indexes ready")

# ── 3. Auto-grant verified from confirmed payments ─────────────────────────
print("\n── Step 3: Auto-grant verified badges ──")
rows = db.execute(
    "SELECT token_id FROM firo_payments WHERE status='confirmed'"
).fetchall()
auto = 0
for r in rows:
    db.execute("UPDATE tokens SET verified=1 WHERE id=? AND verified=0", (r["token_id"],))
    auto += db.execute("SELECT changes()").fetchone()[0]
db.commit()
print(f"  ✓ Auto-granted verified to {auto} token(s) from confirmed payments")

# ── 4. Show current state ──────────────────────────────────────────────────
print("\n── Current tokens ──")
tokens = db.execute(
    "SELECT id, label, claimed_name, verified, revoked FROM tokens ORDER BY label"
).fetchall()
for t in tokens:
    name   = t["claimed_name"] or t["label"]
    status = []
    if t["verified"]: status.append("VERIFIED ✓")
    if t["revoked"]:  status.append("REVOKED")
    badge = "  [" + ", ".join(status) + "]" if status else ""
    print(f"  {t['id'][:14]}  {name:<30}{badge}")

print(f"\n  Total: {len(tokens)} token(s)")

pmts = db.execute("SELECT COUNT(*) FROM firo_payments").fetchone()[0]
conf = db.execute("SELECT COUNT(*) FROM firo_payments WHERE status='confirmed'").fetchone()[0]
print(f"  Payments: {pmts} total, {conf} confirmed")

# ── 5. Manual verified grant ───────────────────────────────────────────────
print("\n── Manual verified grant ──")
print("Enter token label/claimed_name to grant verified badge.")
print("Type 'all' to verify all active tokens. Press Enter to skip.\n")

while True:
    try:
        inp = input("Token name (blank to finish): ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if not inp:
        break
    if inp.lower() == "all":
        db.execute("UPDATE tokens SET verified=1 WHERE revoked=0")
        db.commit()
        c = db.execute("SELECT COUNT(*) FROM tokens WHERE verified=1").fetchone()[0]
        print(f"  ✓ All active tokens verified ({c} total)")
        break
    tok = db.execute(
        "SELECT id, label, claimed_name, verified FROM tokens "
        "WHERE label=? OR claimed_name=? OR id LIKE ? LIMIT 1",
        (inp, inp, inp + "%")
    ).fetchone()
    if not tok:
        print(f"  ✗ Not found: '{inp}'")
        available = [t["claimed_name"] or t["label"] for t in tokens]
        print(f"    Available: {', '.join(available)}")
    elif tok["verified"]:
        print(f"  Already verified: {tok['claimed_name'] or tok['label']}")
    else:
        db.execute("UPDATE tokens SET verified=1 WHERE id=?", (tok["id"],))
        db.commit()
        print(f"  ✓ Verified: {tok['claimed_name'] or tok['label']}")

# ── Done ───────────────────────────────────────────────────────────────────
db.close()
print("\n✓ Migration complete.")
print("Restart the app:  bash start.sh\n")