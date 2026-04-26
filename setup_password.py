import os, sys
from cryptography.fernet import Fernet
from dotenv import dotenv_values

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")

def main():
    print("=" * 50)
    print("  DNet — Admin Password Setup")
    print("=" * 50)

    # Load existing .env if present
    existing = dotenv_values(ENV_FILE) if os.path.exists(ENV_FILE) else {}

    # Get or generate Fernet key
    fernet_key = existing.get("DNet_FERNET_KEY", "")
    if not fernet_key:
        fernet_key = Fernet.generate_key().decode()
        print(f"[+] Generated new Fernet key")
    else:
        print(f"[=] Using existing Fernet key")

    f = Fernet(fernet_key.encode())

    # Get admin password from user
    print()
    while True:
        pw  = input("Enter new admin password (min 12 chars): ").strip()
        pw2 = input("Confirm password: ").strip()
        if pw != pw2:
            print("  Passwords do not match. Try again.\n")
            continue
        if len(pw) < 12:
            print("  Password too short (min 12 chars). Try again.\n")
            continue
        break

    # Encrypt password
    blob = f.encrypt(pw.encode()).decode()
    print(f"\n[+] Password encrypted with Fernet")

    # Preserve existing env values, update/add ours
    lines = []
    keys_written = set()

    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    lines.append(line.rstrip())
                    continue
                if "=" in stripped:
                    k = stripped.split("=", 1)[0]
                    if k == "DNet_FERNET_KEY":
                        lines.append(f"DNet_FERNET_KEY={fernet_key}")
                        keys_written.add(k)
                    elif k == "DNet_ADMIN_BLOB":
                        lines.append(f"DNet_ADMIN_BLOB={blob}")
                        keys_written.add(k)
                    else:
                        lines.append(line.rstrip())
                else:
                    lines.append(line.rstrip())

    # Append any not yet written
    if "DNet_FERNET_KEY" not in keys_written:
        lines.append(f"DNet_FERNET_KEY={fernet_key}")
    if "DNet_ADMIN_BLOB" not in keys_written:
        lines.append(f"DNet_ADMIN_BLOB={blob}")

    # Add defaults if .env is new
    if not os.path.exists(ENV_FILE):
        lines += [
            "",
            "# Admin panel path segments (change these!)",
            "DNet_ADMIN_PREFIX=ctrl9x4mQ7wZ2pL",
            "DNet_ADMIN_SUFFIX=auth8nK3vR6hJ1sT",
            "",
            "# Gunicorn bind (leave as-is for Tor)",
            "DNet_HOST=127.0.0.1",
            "DNet_PORT=5000",
        ]

    with open(ENV_FILE, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(ENV_FILE, 0o600)

    print(f"[+] .env written to: {ENV_FILE}")
    print()
    print("  Next steps:")
    print("    1. Edit .env to set custom ADMIN_PREFIX and ADMIN_SUFFIX")
    print("    2. Run: bash start.sh")
    print()
    print("  ⚠  Keep .env secret — it contains your encryption key!")

if __name__ == "__main__":
    main()
