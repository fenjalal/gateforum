#!/usr/bin/env python3
"""
Run on the server:  python3 fix_verified.py
Grants verified=1 to every token that has a confirmed firo_payment,
and also lets you manually grant by label/claimed_name.
Safe to run multiple times.
"""
import sqlite3, pathlib, sys

# Auto-detect DB path
for candidate in [
    pathlib.Path(__file__).parent / "instance" / "DNet.db",
    pathlib.Path("instance/DNet.db"),
    pathlib.Path("DNet.db"),
]:
    if candidate.exists():
        DB = candidate
        break
else:
    print("ERROR: Cannot find DNet.db — run this script from the project folder")
    sys.exit(1)

print(f"DB: {DB}\n")
db = sqlite3.connect(str(DB))
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")

# ── Step 1: ensure columns exist ──────────────────────────────────────────
for table, col, typedef in [
    ("tokens",        "verified",      "INTEGER NOT NULL DEFAULT 0"),
    ("firo_payments", "confirmed_at",  "TEXT NOT NULL DEFAULT ''"),
]:
    try:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
        db.commit()
        print(f"Added column {table}.{col}")
    except sqlite3.OperationalError:
        pass  # already exists

# ── Step 2: ensure firo_payments table exists ──────────────────────────────
db.executescript("""
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
CREATE INDEX IF NOT EXISTS idx_firo_token ON firo_payments(token_id);
CREATE INDEX IF NOT EXISTS idx_firo_order ON firo_payments(order_id);

CREATE TABLE IF NOT EXISTS flask_sessions (
    sid     TEXT PRIMARY KEY,
    data    TEXT NOT NULL DEFAULT '{}',
    expires INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ses_exp ON flask_sessions(expires);
""")
db.commit()

# ── Step 3: auto-grant from confirmed payments ─────────────────────────────
rows = db.execute(
    "SELECT token_id FROM firo_payments WHERE status='confirmed'"
).fetchall()
auto = 0
for r in rows:
    db.execute("UPDATE tokens SET verified=1 WHERE id=? AND verified=0", (r["token_id"],))
    auto += db.execute("SELECT changes()").fetchone()[0]
db.commit()
if auto:
    print(f"Auto-granted verified badge to {auto} token(s) from confirmed payments\n")

# ── Step 4: show all tokens ────────────────────────────────────────────────
print("Current tokens:")
tokens = db.execute(
    "SELECT id, label, claimed_name, verified FROM tokens ORDER BY label"
).fetchall()
for t in tokens:
    name   = t["claimed_name"] or t["label"]
    badge  = " ← VERIFIED ✓" if t["verified"] else ""
    print(f"  {t['id'][:16]}  {name:<30}{badge}")

# ── Step 5: manual grant ──────────────────────────────────────────────────
print()
print("Type a name/label to grant verified badge (blank to skip, 'all' to verify everyone):")
inp = input("> ").strip()

if inp.lower() == "all":
    db.execute("UPDATE tokens SET verified=1 WHERE revoked=0")
    db.commit()
    print("✓ Granted verified to ALL active tokens")
elif inp:
    tok = db.execute(
        "SELECT id, label, claimed_name, verified FROM tokens "
        "WHERE label=? OR claimed_name=? OR id LIKE ? LIMIT 1",
        (inp, inp, inp + "%")
    ).fetchone()
    if tok:
        if tok["verified"]:
            print(f"Already verified: {tok['claimed_name'] or tok['label']}")
        else:
            db.execute("UPDATE tokens SET verified=1 WHERE id=?", (tok["id"],))
            db.commit()
            print(f"✓ Granted verified to: {tok['claimed_name'] or tok['label']}")
    else:
        print(f"Token not found: {inp}")
        print("Available names:", [t["claimed_name"] or t["label"] for t in tokens])

db.close()
print("\nDone — restart the app: bash start.sh")
