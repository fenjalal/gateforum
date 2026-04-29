# Sonet

Self-hosted anonymous publishing platform built with Flask + SQLite. Users register with a token key, post articles, and react — no emails, no tracking. Open-source, run it anywhere.

---

## Requirements

- Python 3.10+
- pip packages: `flask pillow`

```bash
pip install flask pillow
```

---

## Install

```bash
git clone https://github.com/yourname/sonet.git
cd sonet
pip install flask pillow
python app.py
```

App runs at `http://127.0.0.1:5000`

---

## Production (recommended)

```bash
pip install gunicorn
gunicorn -w 2 -b 127.0.0.1:5000 app:app
```

Reverse proxy with Nginx:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Environment Variables

Create a `.env` file or export before running:

| Variable | Default | Description |
|---|---|---|
| `DNet_ADMIN_PREFIX` | `ctrl9x4mQ7wZ2pL` | Admin URL prefix |
| `DNet_ADMIN_SUFFIX` | `auth8nK3vR6hJ1sT` | Admin URL suffix |
| `ADMIN_PASSWORD_HASH` | *(required)* | bcrypt hash of admin password |
| `FIROGATE_API_KEY` | — | LavaPay/FiroGate API key (optional) |
| `FIROGATE_WEBHOOK_SECRET` | — | Webhook secret |
| `FIROGATE_BASE_URL` | `https://api.firogate.com` | API base URL |
| `FIROGATE_VERIFY_AMOUNT` | `3.99` | Firo amount required for verified badge |
| `FIROGATE_USE_TOR` | `0` | Set `1` to route via Tor |
| `FIROGATE_ONION_URL` | — | Optional .onion endpoint |
| `FIROGATE_TOR_PROXY` | `socks5h://127.0.0.1:9050` | Tor SOCKS5 proxy |

**Admin URL:**
```
http://yourdomain.com/{DNet_ADMIN_PREFIX}/{DNet_ADMIN_SUFFIX}
```
Change both vars before deploying.

---

## Update

```bash
git pull
python app.py   # DB migrations run automatically on startup
```

No manual SQL needed — schema migrations are handled on every boot.

---

## Tor / Onion

1. Install Tor, add to `torrc`:
   ```
   HiddenServiceDir /var/lib/tor/sonet/
   HiddenServicePort 80 127.0.0.1:5000
   ```
2. Set `FIROGATE_USE_TOR=1` and optionally `FIROGATE_ONION_URL` if your payment gateway has an onion address.

---

## File Structure

```
app.py              Main application
static/
  uploads/          Post images
  avatars/          User avatars
templates/          Jinja2 HTML templates
sonet.db            SQLite database (auto-created)
```

---

## License

MIT
