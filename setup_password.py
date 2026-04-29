import os, sys, hashlib, secrets
from dotenv import dotenv_values

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")

ITERATIONS = 600_000   # OWASP 2024 recommendation for PBKDF2-SHA256

def pbkdf2_hash(pw: str) -> str:
    salt = secrets.token_bytes(32)
    dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS)
    return f"pbkdf2${ITERATIONS}${salt.hex()}${dk.hex()}"

def main():
    print("=" * 50)
    print("  GateForum — Admin Password Setup")
    print("=" * 50)
    print()

    # Load existing .env
    existing = dotenv_values(ENV_FILE) if os.path.exists(ENV_FILE) else {}

    # Warn if old Fernet keys exist
    if existing.get("DNet_FERNET_KEY") or existing.get("DNet_ADMIN_BLOB"):
        print("[!] Old Fernet keys found (DNet_FERNET_KEY / DNet_ADMIN_BLOB).")
        print("    These will be removed — Fernet has been replaced with PBKDF2.")
        print()

    # Get password
    while True:
        try:
            pw  = input("Enter new admin password (min 12 chars): ").strip()
            pw2 = input("Confirm password: ").strip()
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)
        if pw != pw2:
            print("  Passwords do not match.\n"); continue
        if len(pw) < 12:
            print("  Password too short (min 12 chars).\n"); continue
        break

    admin_hash = pbkdf2_hash(pw)
    print(f"\n[+] Password hashed with PBKDF2-HMAC-SHA256 ({ITERATIONS:,} iterations)")

    # Rebuild .env preserving existing keys, removing Fernet junk
    SKIP_KEYS = {"DNet_FERNET_KEY", "DNet_ADMIN_BLOB", "DNet_ADMIN_HASH"}
    lines = []
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    lines.append(line.rstrip()); continue
                k = s.split("=", 1)[0] if "=" in s else ""
                if k not in SKIP_KEYS:
                    lines.append(line.rstrip())

    # Add new hash
    lines.append(f"DNet_ADMIN_HASH={admin_hash}")

    # Add defaults if .env is new
    if not os.path.exists(ENV_FILE):
        lines += [
            "",
            "# Admin panel path segments (change these!)",
            "DNet_ADMIN_PREFIX=ctrl9x4mQ7wZ2pL",
            "DNet_ADMIN_SUFFIX=auth8nK3vR6hJ1sT",
            "",
            "# Gunicorn bind",
            "DNet_HOST=127.0.0.1",
            "DNet_PORT=5000",
        ]

    with open(ENV_FILE, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(ENV_FILE, 0o600)

    print(f"[+] .env updated: {ENV_FILE}")
    print()
    print("  Next steps:")
    print("    1. Edit .env — set custom ADMIN_PREFIX and ADMIN_SUFFIX")
    print("    2. Run: bash start.sh")
    print()
    print("  The hash is one-way — even if .env leaks, password cannot be recovered.")

if __name__ == "__main__":
    main()