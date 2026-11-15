# GateForum

A private, self-hosted forum and shop. Runs on Tor or a normal domain.
No tracking, no ads, no email. Payments in [Firo](https://firo.org) through FiroGate.

## What you need

- Linux (Debian, Ubuntu, Arch) or Termux on Android
- Python 3.10 or newer

## Install

```bash
git clone https://github.com/fenjalal/gateforum.git
cd gateforum
pip install -r requirements.txt
```

If pip refuses (PEP 668), add `--break-system-packages`.

## Set up

**1. Make the admin password**

```bash
python3 setup_password.py
```

This writes your settings to `.env`. Keep that file private and never upload it.

**2. Add your settings to `.env`**

```env
GATEFORUM_HOST=127.0.0.1
GATEFORUM_PORT=5000

# Your site address, so buyers come back after paying
SITE_BASE_URL=https://example.com

# FiroGate (needed for payments)
FIROGATE_BASE_URL=https://your-firogate-host
FIROGATE_API_KEY=your_api_key
FIROGATE_WEBHOOK_SECRET=your_webhook_secret
```

Optional:

| Setting | Default | What it does |
|---|---|---|
| `FIROGATE_VERIFY_AMOUNT` | `3.99` | Price of the Verified badge in FIRO |
| `FIROGATE_TIMEOUT_MIN` | `20` | Minutes a payment stays open |
| `FIROGATE_USE_TOR` | `0` | Set `1` to reach FiroGate over Tor |
| `FIROGATE_ONION_URL` | empty | FiroGate .onion address |
| `SHOP_MAX_UPLOAD_MB` | `2048` | Biggest product file |

**3. Start**

```bash
bash start.sh        # live server
bash start_dev.sh    # testing
```

The start script prints your private admin address. Do not share it.

## Payments

1. In FiroGate, create an API key that can create and read invoices.
2. Set the webhook to `https://example.com/webhook/firogate` and copy the secret.
3. Put both in `.env` and restart.

A payment counts only when FiroGate confirms it. The return link alone never unlocks anything.
Refunds remove what was bought.

## Shop

Add products in **Admin, Products**: name, price, picture, and a file (any type) or a text such as a license key.

- Buying needs an account. No email is asked.
- Files are only sent to people who bought them.
- Only buyers can rate a product.
- A bought product can be hidden, not deleted, so buyers keep access.

If you use nginx, set `client_max_body_size` to match `SHOP_MAX_UPLOAD_MB`.

## Update

```bash
cp -r instance/ instance_backup/
cp -r static/uploads/ uploads_backup/
git pull
pip install -r requirements.txt
python3 migrate.py
bash start.sh
```

`migrate.py` is safe to run many times. On older installs it also renames the database and `.env` keys to the new names.

## Tor

**Debian / Ubuntu**

```bash
sudo apt install -y tor
sudo bash -c 'cat torrc.snippet >> /etc/tor/torrc'
sudo systemctl restart tor
sudo cat /var/lib/tor/gateforum_hidden_service/hostname
```

**Termux**

```bash
pkg install tor
echo "HiddenServiceDir $HOME/.tor/gateforum/" >> $PREFIX/etc/tor/torrc
echo "HiddenServicePort 80 127.0.0.1:5000" >> $PREFIX/etc/tor/torrc
tor &
```

Then set `SITE_BASE_URL` in `.env` to your .onion address.

## Files

```
app.py              The app
setup_password.py   Sets the admin password
migrate.py          Updates the database
start.sh            Live start
start_dev.sh        Test start
torrc.snippet       Tor settings
instance/           Database and private files (never upload)
static/             Styles, fonts, uploads
templates/          Pages
```

More details: [ABOUT.md](ABOUT.md)
