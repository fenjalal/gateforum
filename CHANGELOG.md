# Changelog

Each version is also a git tag, for example `v2.0.0`.
The number is in the `VERSION` file and shows in **Admin, Settings**.

How the number works: `MAJOR.MINOR.FIX`

- **MAJOR**: big changes. Read the notes before you update.
- **MINOR**: new features. Safe to update.
- **FIX**: bug fixes only.

## 2.0.0 (2026-11-16)

- New design for every page
- Shop for digital products: files of any type, license keys, ratings from buyers
- Payments fixed: a payment only counts when FiroGate confirms it
- Safer webhooks, checked once and only within 5 minutes
- Simpler setup and a shorter README
- After updating, run `python3 migrate.py`

## 1.0.0 (2026-04-26)

- First release: posts, members, chat, Verified badge with Firo
