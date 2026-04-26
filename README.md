# DNet

An independent live attacking news and senstive data publishing platform that runs exclusively on the Tor network.
No JavaScript. No tracking. No visitor logs. No ads. No external connections.
---
## 1. Requirements

| Requirement | Minimum Version |
|---|---|
| Python | 3.10 or newer |
| pip | Any recent version |
| Tor | 0.4.7 or newer |
| Disk space | 50 MB for code + space for uploaded images |
| RAM | 128 MB minimum |

**Supported operating systems:** Debian · Ubuntu · Termux (Android) · Any Linux.

---

## 2. Project Structure

```
DNet/
│
├── app.py                         ← Main Flask application (entry point)
├── setup_password.py              ← Password setup tool (run once)
├── start.sh                       ← Production start script via Gunicorn
├── start_dev.sh                   ← Simple development start
├── requirements.txt               ← Python dependencies
├── torrc.snippet                  ← Tor config to append to torrc
├── .env                           ← Secret settings (never share this)
│
├── instance/
│   ├── DNet.db                  ← SQLite database (auto-created)
│   └── .secret_key                ← Persistent Flask secret key (auto-created)
│
├── static/
│   ├── css/
│   │   ├── fonts.css              ← @font-face declarations for local fonts
│   │   └── style.css              ← Full stylesheet
│   ├── fonts/                     ← Local TTF font files (zero external requests)
│   │   ├── Poppins-Bold.ttf
│   │   ├── Poppins-Regular.ttf
│   │   ├── Lora-Variable.ttf
│   │   ├── Lora-Italic-Variable.ttf
│   │   ├── DejaVuSansMono.ttf
│   │   └── DejaVuSansMono-Bold.ttf
│   ├── uploads/                   ← Uploaded post images
│   └── avatars/                   ← Author profile pictures
│
└── templates/
    ├── base.html                  ← Base template (header, footer)
    ├── index.html                 ← Home page — post feed
    ├── post.html                  ← Post detail page
    ├── search.html                ← Search results page
    ├── error.html                 ← Error pages (403, 404, 429, 500)
    ├── admin_login.html           ← Admin login form
    ├── admin_dashboard.html       ← Full admin control panel
    ├── new_post.html              ← New post form (admin + contributors)
    ├── token_login.html           ← Contributor token login
    ├── contributor_dashboard.html ← Contributor control panel
    ├── _byline.html               ← Partial: author name and badge
    ├── _post_card.html            ← Partial: post card in the feed
    ├── _sidebar_left.html         ← Partial: left sidebar
    └── _sidebar_right.html        ← Partial: right sidebar
```

---

## 3. First Installation

### Step 1 — Install system requirements

**Debian / Ubuntu:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip tor
```

**Termux (Android):**
```bash
pkg update
pkg install python tor
```

### Step 2 — Extract the project

```bash
tar -xzf DNet_v8.tar.gz
cd DNet
```

### Step 3 — Install Python libraries

```bash
pip install -r requirements.txt
```

On Termux or if you see a PEP 668 error:
```bash
pip install -r requirements.txt --break-system-packages
```

### Step 4 — Create the password and .env file

This is the most important step. Run it **once only**:

```bash
python3 setup_password.py
```

The script will ask for an admin password (minimum 12 characters), then automatically generate:
- `DNet_FERNET_KEY` — a Fernet encryption key
- `DNet_ADMIN_BLOB` — your admin password encrypted with Fernet

Both values are saved to `.env`.

> ⚠️ **Keep `.env` safe. Never share it. Never commit it to any repository.**

### Step 5 — Customize the admin panel path

Open `.env` and change these two values:

```env
DNet_ADMIN_PREFIX=your_first_secret_word
DNet_ADMIN_SUFFIX=your_second_secret_word
```

The admin panel URL will be:
```
http://youronion.onion/ctrl9x4mQ7wZ2pL/auth8nK3vR6hJ1sT
```

Choose long random strings that are hard to guess.

---

## 4. Tor Hidden Service Setup

### Debian / Ubuntu

```bash
sudo bash -c 'cat torrc.snippet >> /etc/tor/torrc'
sudo systemctl restart tor
sudo cat /var/lib/tor/DNet_hidden_service/hostname
```

### Termux (Android)

```bash
mkdir -p ~/.tor/DNet
echo "HiddenServiceDir $HOME/.tor/DNet/" >> $PREFIX/etc/tor/torrc
echo "HiddenServicePort 80 127.0.0.1:5000"  >> $PREFIX/etc/tor/torrc
tor &
sleep 5
cat ~/.tor/DNet/hostname
```

### torrc content reference

```
HiddenServiceDir /var/lib/tor/DNet_hidden_service/
HiddenServicePort 80 127.0.0.1:5000
```

> The site listens on `127.0.0.1:5000` only. It cannot be reached except through Tor.

---

## 5. Running the Site

### Production (always use this)

```bash
bash start.sh
```

Gunicorn options used by `start.sh` and why:

| Option | Value | Reason |
|---|---|---|
| `--workers` | 2 | Two parallel worker processes |
| `--threads` | 2 | Two threads per worker |
| `--timeout` | 120 | Prevents WORKER TIMEOUT on Tor (default 30s is too short) |
| `--keep-alive` | 10 | Keeps Tor circuit connections alive |
| `--max-requests` | 500 | Restarts workers periodically to prevent memory leaks |
| `--preload` | — | Loads the app once and shares it across workers |

### Development only

```bash
bash start_dev.sh
# or directly
python3 app.py
```

> **Never use** `python3 app.py` in production. Always use `bash start.sh`.

---

## 6. Admin Panel

### Access URL

```
http://youronion.onion/ADMIN_PREFIX/ADMIN_SUFFIX
```

Both values come from `.env`. Default values (change these immediately):
```
http://127.0.0.1:5000/ctrl9x4mQ7wZ2pL/auth8nK3vR6hJ1sT
```

### Full Admin Capabilities

| Feature | Details |
|---|---|
| Publish a post | Title + body + images (up to 6) + author + role badge |
| Pin a post | Appears at the top of the home feed (up to 3 pinned posts) |
| Unpin a post | Returns it to the regular feed |
| Delete any post | Including posts by contributors |
| Manage author profiles | Create / edit / delete authors, photos, verified badge |
| Generate tokens | Grant publishing access to contributors |
| Revoke tokens | Instantly remove contributor access |
| Delete tokens | Permanently remove a token |

### Changing the Admin Password

```bash
python3 setup_password.py
# Enter the new password when prompted
bash start.sh   # Restart the site
```

---

## 7. Contributor key System

### How to generate a key

1. Admin → Dashboard → "Contributor Keys" section
2. Enter a descriptive label (e.g. "Reporter A")
3. Click "Generate key"
4. **Copy the key immediately** — it appears once only in a gold box
5. Send it to the contributor through a secure channel

### How contributors use the key

Navigate to:
```
http://youronion.onion/token-access
```

Paste the key → click "Access" → automatically redirected to `/contribute`.

### Contributor permissions

| Action | Contributor | Admin |
|---|---|---|
| Publish posts | ✅ | ✅ |
| View own posts | ✅ | ✅ |
| Delete own posts | ✅ | ✅ |
| View others' posts | ❌ | ✅ |
| Delete others' posts | ❌ | ✅ |
| Manage authors | ❌ | ✅ |
| Manage tokens | ❌ | ✅ |

### Revoking a key

Admin → Dashboard → keys section → click "Revoke"

Access is denied immediately on the next request. Previous posts remain published until deleted by the admin.

---

## 8. Author Profile Management

### Creating an author

Admin → Dashboard → "Author Profiles" section → fill name + upload photo + check Verified → click "Add"

### Author fields

| Field | Details |
|---|---|
| Name | Free text, up to 80 characters |
| Photo | PNG / JPG / GIF / WebP — max 2 MB — validated with magic bytes |
| Verified | Verification badge displayed next to the name |

### The Verified badge

- **Gold** — the post carries a role badge (Owner, Admin, etc.)
- **Grey** — the post has no role badge

The badge always appears next to the author name on every post.

### Default author

A "DNet" author is created automatically on first run. You can edit it and add a photo from the admin dashboard.

---

## 9. Post System

### Post features

| Feature | Details |
|---|---|
| Multiple images | Up to 6 per post, PNG/JPG/GIF/WebP, 5 MB per image |
| Pinning | Up to 3 pinned posts shown at the top of page 1 |
| View counter | Increments each time the post detail page is opened |
| Reading time | Calculated automatically (200 words per minute) |
| Markdown | Full text formatting in post body |
| Role badge | Owner / Admin / Moderator / Support / Hacktivist / None |
| Search | Searches titles and body text — up to 30 results |
| Pagination | 10 posts per page |

### Image display layout

- **One image** → full width at 16:9 aspect ratio
- **Two or more images** → 2×2 grid; if the count is odd, the first image takes full width

### Role badge colors

| Badge | Color |
|---|---|
| Owner | Gold |
| Admin | Red |
| Moderator | Blue |
| Support | Green |
| Hacktivist | Teal |

---

## 10. Content Formatting — Markdown

Pure Python processing — no JavaScript involved at any step. All content is HTML-escaped before transformation, making injection impossible.

### Supported syntax

**Bold text:**
```
**this text is bold**
```

**Italic text:**
```
*this text is italic*
```

**Inline code:**
```
Use `print("hello")` in Python
```

**Code block with syntax highlighting:**
````
```python
def greet(name):
    return f"Hello, {name}"
```
````

**Supported languages for highlighting:**
`python` · `js` · `javascript` · `html` · `css` · `bash` · `sh` · `json` · `sql`
Any other language label renders in plain white.

**Headings:**
```
# Large heading   (h3)
## Medium heading (h4)
### Small heading  (h5)
```

**Bullet list:**
```
- First item
- Second item
- Third item
```

**Horizontal rule:**
```
---
```

**Automatic URL linking:**
```
Visit https://example.onion for more
```
Automatically becomes a link that opens in a new tab with `rel="noopener noreferrer"`.

---

## 11. The .env File — All Settings

```env
# ─── Encryption keys (generated by setup_password.py) ────────────
DNet_FERNET_KEY=          # Fernet key — never expose this
DNet_ADMIN_BLOB=          # Admin password encrypted with Fernet

# ─── Hidden admin panel path ─────────────────────────────────────
DNet_ADMIN_PREFIX=ctrl9x4mQ7wZ2pL
DNet_ADMIN_SUFFIX=auth8nK3vR6hJ1sT

# ─── Network ─────────────────────────────────────────────────────
DNet_HOST=127.0.0.1       # Always localhost — do not change this
DNet_PORT=5000            # Must match HiddenServicePort in torrc

# ─── Optional ────────────────────────────────────────────────────
# DNet_SECRET=some_very_long_random_string
# If not set, a key is auto-generated and saved to instance/.secret_key
```

### How the password encryption system works

The admin password is **not stored as a hash** — it is encrypted with **Fernet** (symmetric AES-128-CBC encryption). week but you can upgrade it

On login:
1. `DNet_ADMIN_BLOB` is decrypted using `DNet_FERNET_KEY`
2. The submitted password is compared using `secrets.compare_digest` (resistant to timing attacks)

**If you lose `.env`:** Run `python3 setup_password.py` again to set a new password.

---

## 12. Security & Protection

### Protection layers

| Layer | Details |
|---|---|
| Rate limiting — pages | 120 requests/minute per IP no need for tor but you can use it sometimes |
| Rate limiting — file uploads | 20 files per 5 minutes per IP |
| Rate limiting — login | 5 attempts per 5 minutes per IP |
| Rate limiting — search | 20 searches/minute per IP |
| User-Agent blocking | sqlmap, nikto, nmap, curl, wget, scrapy, dirbuster, nuclei, acunetix, and 15+ more |
| Suspicious path blocking | /.env, /.git, /wp-admin, /phpmyadmin, /shell, /cgi-bin, and more |
| Magic bytes validation | Validates actual file content, not just the extension |
| Path traversal protection | `os.path.realpath()` ensures files stay within allowed directories |
| CSP header | `script-src 'none'` — blocks all JavaScript completely |
| Server header removal | Stripped to prevent fingerprinting |
| SameSite=Lax cookies | Works correctly with Tor POST→redirect chains |
| Persistent SECRET_KEY | Saved in `instance/.secret_key` — survives Gunicorn restarts |
| WAL mode database | Safe for concurrent connections |
| Login delay | `time.sleep(1)` on wrong password to slow brute force |
| Content-Length check | Oversized requests rejected before reading the body |

### HTTP security headers sent on every response

```http
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=()
Content-Security-Policy: default-src 'self'; img-src 'self' data:;
                          style-src 'self'; script-src 'none';
                          object-src 'none'; frame-ancestors 'none';
```

### Privacy guarantees

- No JavaScript of any kind
- No external fonts — all fonts are local in `static/fonts/`
- No CDN, no Google Fonts, no external connections of any kind
- No visitor data stored
- `robots` meta: `noindex, nofollow, noarchive, nosnippet`
- Fonts cached for 1 year: `Cache-Control: public, max-age=31536000, immutable`
- Images cached for 5 minutes: `Cache-Control: public, max-age=300`

---

## 13. Upgrading from an Older Version

```bash
# 1. Back up your data
cp -r instance/ instance_backup/
cp -r static/uploads/ uploads_backup/
cp -r static/avatars/ avatars_backup/ 2>/dev/null || true

# 2. Extract the new files over the current directory
tar -xzf DNet_v8_localfonts.tar.gz --strip-components=1

# 3. Install new libraries
pip install -r requirements.txt

# 4. Create a new .env (password system changed in v8)
python3 setup_password.py

# 5. Start the site
bash start.sh
```

### Automatic database migrations on first run

| Migration | Details |
|---|---|
| Add `views` column | If not already present |
| Add `pinned` column | If not already present |
| Add `author_id` column | If not already present |
| Add `token_id` column | If not already present |
| Create `authors` table | If not already present |
| Create `keys` table | If not already present |
| Convert `image` → `images` | Old single text field converted to JSON array |
| Drop `likes` table | Likes removed entirely in v8 |
| Create default "DNet" author | If not already present |

### Key changes in v8 vs older versions

| Change | Details |
|---|---|
| Password system | SHA-256 hash → Fernet encryption — **requires `setup_password.py`** |
| Likes | Removed entirely — no captcha, no like button |
| Fonts | Local TTF — no Google Fonts |
| Markdown | Full Python processing — colored code blocks, auto-links, headings |
| View counter | Now works correctly |
| SameSite=Lax | Fixed Tor redirect cookie issues |
| Persistent SECRET_KEY | Fixed session loss on Gunicorn restart |
| `.env` support | Full python-dotenv integration |


> Do not expose it to the regular internet.
> The server listens on `127.0.0.1` only and is unreachable without Tor.


Upgrade DNet Team
@dnsupportbot
Code: DNAix47
