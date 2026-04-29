# GateForum — Technical Details

## What It Is

GateForum is a self-hosted anonymous publishing platform. Contributors get a secret token key instead of a username/password. No emails, no phone numbers, no IP logs in user records. Designed to run on Tor hidden services and clearnet simultaneously with zero config changes.

Verified badges are granted via a one-time Firo (FIRO) cryptocurrency payment processed through FiroGate.

---

## Architecture

| Layer | Tech |
|---|---|
| Backend | Python 3.10+ / Flask 3.0+ |
| Database | SQLite (single file, zero config) |
| Frontend | Server-rendered Jinja2, minimal JS |
| Sessions | DB-backed — cookie holds only a 64-byte random session ID |
| Auth | HMAC-hashed tokens stored in DB |
| Payments | FiroGate API (Firo cryptocurrency) |
| CAPTCHA | Self-hosted math CAPTCHA, HMAC-signed — no external service |

---

## Features

### Posts
- Markdown: bold, italic, code blocks, headings, auto-links
- Up to 6 images per post, shown in responsive grid
- Author profiles with avatars and role badges
- Pinning, view counter, read-time estimate
- RSS feed at `/feed.xml`
- Admin: edit, delete, pin any post

### Reactions
- Two reactions: Fire 🔥 and Bolt ⚡
- **Logged-in users:** tracked by token hash — persists across all devices and IPs
- **Anonymous users:** tracked by hashed IP
- Counts stored in `post_reactions` table only — never denormalized into posts

### Users & Tokens
- Self-registration at `/register` with math CAPTCHA
- Token shown **once** at registration with a one-click Copy button
- Verified badge (✓) granted after FiroGate payment or manually by admin
- Admin can bulk-generate pool tokens (10 / 25 / 50 / 100 at once)
- Role badges: Reporter · Editor · Analyst · Hacktivist · Moderator · and more
- Token revocation: instant, no recovery

### Chat
- Anonymous, polling-based (no WebSockets)
- Nickname setting per session
- Rate-limited: 30 messages/minute
- Reply-to support

### Admin Panel
- Hidden URL: `/{DNet_ADMIN_PREFIX}/{DNet_ADMIN_SUFFIX}`
- Posts: create, edit, delete, pin (up to 3 pinned)
- Authors: create/edit/delete with avatars and role badges
- Tokens: create, bulk-create, revoke, verify toggle, delete
- Settings: site title, tagline, posts per page, maintenance mode
- Reports queue: user-reported posts with one-click resolve/delete
- Full audit log of all admin actions

---

## Security

| Protection | Details |
|---|---|
| CSRF | Per-session HMAC token on every POST form |
| Rate limiting | 5/5min login · 5/10min register · 30/min chat · in-memory, no Redis |
| UA blocking | sqlmap, nikto, nmap, curl/wget scanners and 15+ patterns |
| Path blocking | `/.env` · `/.git` · `/wp-admin` · `/phpmyadmin` · 20+ paths |
| XSS | All user content HTML-escaped before markdown processing |
| Webhook HMAC | SHA-256 signature + timestamp + nonce replay protection |
| CSP | Per-route Content-Security-Policy on every response |
| Headers | `X-Frame-Options: DENY` · `Referrer-Policy: no-referrer` |
| File validation | Magic bytes checked — not just extension |
| Cookie | `httponly` + `samesite=Lax` + 90-day expiry |
| Tor-aware | Header anomaly detection skips Tor Browser fingerprints |

---

## Verified Badge & FiroGate

GateForum uses **FiroGate** as a privacy-preserving Firo (FIRO) payment gateway.
FiroGate developed by fenjalal the code will release soon as open-source 
Flow:
1. User clicks "Pay to Verify"
2. Backend creates a payment via FiroGate API
3. User pays the configured FIRO amount to the generated address
4. FiroGate sends a webhook to `/webhook/firogate`
5. Backend verifies HMAC signature → grants badge
6. Badge is permanent in DB — admin can also grant/revoke manually

Configure in `.env`:
```env
FIROGATE_API_KEY=...
FIROGATE_WEBHOOK_SECRET=...
FIROGATE_VERIFY_AMOUNT=1.99
FIROGATE_BASE_URL=https://api.firogate.com
FIROGATE_ONION_URL=http://...onion   # for Tor sites
FIROGATE_USE_TOR=1                   # route API calls via Tor
FIROGATE_TOR_PROXY=socks5h://127.0.0.1:9050
```

---

## Database Tables

| Table | Purpose |
|---|---|
| `posts` | Articles with metadata |
| `authors` | Author profiles (name, avatar, role badge) |
| `tokens` | Contributor access tokens |
| `post_reactions` | Fire/bolt reactions (token-aware across devices) |
| `post_reports` | User reports queue |
| `chat` | Chat messages |
| `firo_payments` | Pending verification payments |
| `settings` | Site-wide key/value config |
| `flask_sessions` | Server-side session storage |
| `action_log` | Admin audit log |

---

## Migrations

Schema migrations run automatically on every startup via `init_db()`. Uses `ALTER TABLE ... ADD COLUMN` inside `try/except` — safe on existing databases.

For manual repair or one-off migrations, run:
```bash
python3 migrate.py
```

---

## Known Limitations

- **SQLite:** fine for low-to-medium traffic. High concurrency → swap to PostgreSQL.
- **Chat polling:** not real-time — 3-second poll interval.
- **Gunicorn workers:** keep at 2–4 max with SQLite to avoid write contention.
