# Open-source Forum — Full Technical Details

## What It Is

Open-source Forum is a self-hosted anonymous publishing platform. There are no user accounts in the traditional sense — each user gets a secret token key at registration which acts as their identity. No emails, no passwords, no IP logs stored in user records.

---

## Architecture

- **Backend:** Python / Flask with DB-backed server-side sessions (no cookie bloat)
- **Database:** SQLite — single file, zero config
- **Frontend:** Server-rendered Jinja2 templates, minimal JS
- **Auth:** Token-based (HMAC-hashed, stored as bcrypt-equivalent hash in DB)
- **Sessions:** Custom `_DbSession` — session data lives in `flask_sessions` table, browser only holds a session ID cookie

---

## Features

### Posts
- Rich markdown body with image uploads (multi-image per post)
- Author profiles with avatars and role badges
- Pinning, view counter, read-time estimate
- RSS feed at `/feed.xml`
- Admin edit/delete

### Reactions
- Two reactions: 🔥 Fire and ⚡ Bolt
- Logged-in users: tracked by token hash — persists across all devices
- Anonymous users: tracked by hashed IP — session-local
- Counts stored in `post_reactions` table (never denormalized into posts columns)

### Users / Tokens
- Self-registration with CAPTCHA (math-based, HMAC-signed)
- Token shown **once** at registration with a Copy button — never shown again
- Verified badge (✓) purchasable via Firo payment (LavaPay/FiroGate integration)
- Admin can manually toggle verified status per token
- Pool tokens: pre-generated invite tokens the admin can distribute
- Token roles: contributor role badge shown on posts and profiles

### Chat
- Anonymous real-time chat (polling-based, no websockets)
- Nickname setting per session
- Rate-limited: 30 messages/minute
- Reply-to support

### Admin Panel
- Hidden URL (`/{PREFIX}/{SUFFIX}`) — configure both via env vars
- Post management: create, edit, delete, pin
- Author management: create/edit authors with avatars and role badges
- Token management: create, bulk-create, revoke, verify, delete
- Site settings: title, tagline, posts per page, maintenance mode
- Reports queue: user-reported posts with one-click delete

### Security
- CSRF protection on all POST forms (per-session HMAC token)
- Rate limiting: login (5/5min), register (5/10min), chat (30/min), search
- No IP addresses stored in user-facing tables
- `httponly` + `samesite=Lax` cookies
- Content Security Policy headers on all responses
- Admin password stored as PBKDF2-SHA256 hash
- All file uploads: type-checked, path-traversal-protected, size-limited (10MB images, 2MB avatars)

### Privacy
- No email collection
- No external CDN or analytics
- Full Tor support — routes payment API calls via SOCKS5 proxy
- Onion address support for FiroGate integration
- Open-source — audit everything

---

## Database Tables

| Table | Purpose |
|---|---|
| `posts` | Articles with metadata |
| `authors` | Author profiles (name, avatar, badge) |
| `tokens` | User access tokens |
| `post_reactions` | Fire/bolt reactions (token-aware) |
| `post_reports` | User reports queue |
| `chat` | Chat messages |
| `firo_payments` | Pending verification payments |
| `settings` | Site-wide key/value config |
| `flask_sessions` | Server-side session storage |
| `action_log` | Admin action audit log |

---

## Payments / Verified Badge

Open-source Forum integrates with **LavaPay** (FiroGate) for Firo cryptocurrency payments. When a contributor pays the configured `FIROGATE_VERIFY_AMOUNT` in Firo, they receive a verified badge (✓) displayed on all their posts and their profile.

- Payment flow: `/verify` → generate address → poll for confirmation → badge granted
- Timeout: configurable via `FIROGATE_TIMEOUT_MIN` (default 20 min)
- Tor-compatible: set `FIROGATE_USE_TOR=1` for full onion routing

---

## CAPTCHA System

Math-based CAPTCHA (e.g. "7 + 4 = ?") with HMAC-signed tokens. No external service. Tokens expire after 10 minutes. Used on registration and the old like system.

---

## Migrations

Schema migrations run automatically on every startup. Adding a new column: just add it to the `migs` list in `init_db()`. Safe to run on existing databases — uses `ALTER TABLE ... ADD COLUMN` with `try/except` for idempotency.

---

## Known Limitations

- SQLite: fine for low-to-medium traffic. For high concurrency, swap to PostgreSQL (requires adapter changes).
- No WebSockets: chat uses polling. Works but not real-time.
- Single process by default: use gunicorn with 2-4 workers max for SQLite safety.
