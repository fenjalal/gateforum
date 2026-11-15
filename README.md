<div align="center">

# GateForum

**Anonymous · Privacy-First · Self-Hosted Publishing Platform**

Open-source. Built for Tor and clearnet. Zero tracking, zero ads, zero external connections.  
Powered by [Firo](https://firo.org) cryptocurrency for contributor verification.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-lightgrey?style=flat-square)](https://flask.palletsprojects.com)
[![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-red?style=flat-square)](#)

</div>

---

# Requirements

- Python 3.10+
- See `requirements.txt` for all dependencies

**Supported:** Debian · Ubuntu · Arch · Termux (Android) · Any Linux

---

# Install

```bash
git clone https://github.com/fenjalal/gateforum.git
cd gateforum
pip install -r requirements.txt
```

On Termux or systems with PEP 668:
```bash
pip install -r requirements.txt --break-system-packages
```

---

# Setup

**1. Set the admin password** (run once):
```bash
python3 setup_password.py
```
It writes `DNet_ADMIN_HASH` (PBKDF2) and a random private admin address
(`DNet_ADMIN_PREFIX` / `DNet_ADMIN_SUFFIX`) to `.env`.
> Never commit `.env` to any repository.

**2. Configure `.env`:**
```env
# Written by setup_password.py
DNet_ADMIN_HASH=pbkdf2$600000$...
DNet_ADMIN_PREFIX=random_value
DNet_ADMIN_SUFFIX=random_value

# Server
DNet_HOST=127.0.0.1
DNet_PORT=5000

# Your public URL (needed so FiroGate can send buyers back)
SITE_BASE_URL=https://yourdomain.com

# FiroGate payments (optional, needed for the Verified badge)
FIROGATE_API_KEY=fgate_your_key_here
FIROGATE_WEBHOOK_SECRET=your_webhook_secret
FIROGATE_BASE_URL=https://your-firogate-host
FIROGATE_ONION_URL=                 # optional .onion address of your FiroGate
FIROGATE_VERIFY_AMOUNT=3.99         # price in FIRO
FIROGATE_TIMEOUT_MIN=20
FIROGATE_USE_TOR=0
FIROGATE_TOR_PROXY=socks5h://127.0.0.1:9050
```

If the admin address is not set, GateForum makes a random one on first start and keeps it in
`instance/.admin_path`.

### Payments (FiroGate)

1. In your FiroGate dashboard, create an API key with the `create_invoice` and `read_invoice` permissions.
2. Set the webhook URL to `https://yourdomain.com/webhook/firogate` and copy the webhook secret.
3. Put both values in `.env` and restart.

How it works:
- A member taps **Pay**. GateForum creates a FiroGate payment and saves its `payment_id`.
- The badge is only turned on when FiroGate says the payment is confirmed, the transaction ID is
  there, and the amount received is at least the price. It never trusts the return link.
- Webhooks are checked with HMAC-SHA256 over the exact body, a 5 minute time window, and a one-time
  nonce stored in the database (safe with several Gunicorn workers).
- Events handled: `payment.confirmed`, `payment.expired`, `payment.cancelled`, `payment.refunded`
  (a refund removes the badge).
- The return page also asks FiroGate directly, so the badge turns on even if a webhook is late, and
  it works without JavaScript.
- Admins see every payment under **Admin, Payments**.

### Shop (digital products)

Admins add products under **Admin, Products**: name, price in FIRO, cover image, description,
and what the buyer gets (a private file of any type such as zip, rar, iso, exe or pdf, a private
text such as a license key, or both).

The file size limit is 2 GB by default. Change it with `SHOP_MAX_UPLOAD_MB` in `.env`. If you run
nginx in front, raise `client_max_body_size` to match. Big uploads only work for a signed-in admin;
the rest of the site keeps a 20 MB limit.

- Anyone can browse (or only members, set in **Admin, Settings**). Buying always needs an account.
  There is no email anywhere.
- Payment uses the same FiroGate flow and checks as the Verified badge. A product payment only
  unlocks that product, never the badge.
- Files are stored in `instance/products/` with random names, never under `static/`. They are
  only sent to people who bought the product, always as a download.
- Only buyers can rate (1 to 5 stars and a short note). A refund removes access and the rating.
- A product someone bought can only be hidden, not deleted, so buyers keep their access.

**3. Start:**
```bash
bash start.sh        # production (Gunicorn)
bash start_dev.sh    # development
```

Admin panel:
```
http://127.0.0.1:5000/{DNet_ADMIN_PREFIX}/{DNet_ADMIN_SUFFIX}
```

---

# Update

```bash
cp -r instance/ instance_backup/
cp -r static/uploads/ uploads_backup/

git pull
pip install -r requirements.txt
python3 migrate.py
bash start.sh
```

If you forked the repo, sync first:
```bash
git remote add upstream https://github.com/fenjalal/gateforum  # once
git fetch upstream && git merge upstream/main && git push
```
Then run `migrate.py` and restart on your server.

---

## Tor Hidden Service

**Debian / Ubuntu:**
```bash
sudo apt install -y tor
sudo bash -c 'cat torrc.snippet >> /etc/tor/torrc'
sudo systemctl restart tor
sudo cat /var/lib/tor/gateforum_hidden_service/hostname
```

**Termux:**
```bash
pkg install tor
echo "HiddenServiceDir $HOME/.tor/gateforum/" >> $PREFIX/etc/tor/torrc
echo "HiddenServicePort 80 127.0.0.1:5000" >> $PREFIX/etc/tor/torrc
tor &
sleep 5 && cat ~/.tor/gateforum/hostname
```

Add to `.env`:
```env
SITE_BASE_URL=http://yourxxxxxxxxxxxxxxxx.onion
FIROGATE_USE_TOR=1
FIROGATE_ONION_URL=http://firogate-onion-address.onion
```

---

## File Structure

```
gateforum/
├── app.py                 Main application
├── setup_password.py      Run once to set admin password
├── migrate.py             DB migration tool
├── start.sh               Production start (Gunicorn)
├── start_dev.sh           Development start
├── requirements.txt       Python dependencies
├── torrc.snippet          Tor config snippet
├── .env                   Secrets — never commit
├── instance/
│   └── DNet.db            SQLite database (auto-created)
├── static/
│   ├── css/
│   ├── fonts/             Local fonts — zero external requests
│   ├── uploads/           Post images
│   └── avatars/           User avatars
└── templates/             Jinja2 HTML templates
```

---

> See `ABOUT.md` for full technical details, security model, and feature documentation.

---

<div align="center">

*Built for privacy. Built for anonymity. Built to last.*

</div>
