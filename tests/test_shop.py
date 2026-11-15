import hashlib, hmac, io, json, os, sys, tempfile, time, unittest, uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("GATEFORUM_ADMIN_PREFIX", "t-admin")
os.environ.setdefault("GATEFORUM_ADMIN_SUFFIX", "t-login")
os.environ["SITE_BASE_URL"] = "https://forum.example"

import app as gf  # noqa: E402

SECRET = b"whsec_test"
B = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "Accept": "text/html", "Accept-Language": "en"}
CSRF = "c" * 64


class ShopTests(unittest.TestCase):
    def setUp(self):
        fd, self.dbp = tempfile.mkstemp(suffix=".db"); os.close(fd)
        self.pdir = tempfile.mkdtemp()
        gf.app.config["DATABASE"] = self.dbp
        gf.app.config["TESTING"] = True
        gf.PRODUCT_DIR = self.pdir
        gf.FIROGATE_API_KEY = "fg_test_key"
        gf.FIROGATE_WEBHOOK_SECRET = "whsec_test"
        for st in (gf._rl_page, gf._rl_post, gf._rl_webhook, gf._rl_pay, gf._rl_status, gf._rl_rate, gf._rl_dl, gf._rl_upload):
            st.clear()
        gf._DbSessionInterface._ensure_table(gf.app)
        self.pid = uuid.uuid4().hex
        self.stored = uuid.uuid4().hex + ".bin"
        with open(os.path.join(self.pdir, self.stored), "wb") as fh:
            fh.write(b"PK secret zip bytes")
        with gf.app.app_context():
            gf.init_db()
            db = gf.get_db()
            self.buyer, self.other = uuid.uuid4().hex, uuid.uuid4().hex
            for tid, key in ((self.buyer, b"buyer-key"), (self.other, b"other-key")):
                db.execute("INSERT INTO tokens (id,label,token_hash,created) VALUES (?,?,?,?)",
                           (tid, "m", hashlib.sha256(key).hexdigest(), "2026-01-01"))
            db.execute("INSERT INTO products (id,title,summary,price_firo,file_name,file_label,file_size,secret_text,active,created) "
                       "VALUES (?,?,?,?,?,?,?,?,1,?)",
                       (self.pid, "Guide", "A guide", 1.5, self.stored, "guide.zip", 19, "LICENSE-KEY-1234", "2026-01-01"))
            db.commit()
        self._orig = gf._firogate_request

    def tearDown(self):
        gf._firogate_request = self._orig
        os.remove(self.dbp)

    def client(self, key=None, admin=False):
        c = gf.app.test_client()
        if key:
            c.set_cookie("dn_token", key)
        c.get("/", headers=B)
        with c.session_transaction() as s:
            s["csrf"] = CSRF
            if admin:
                s["admin"] = True
        return c

    def q(self, sql, *a):
        with gf.app.app_context():
            return gf.get_db().execute(sql, a).fetchone()

    def run_sql(self, sql, *a):
        with gf.app.app_context():
            db = gf.get_db(); db.execute(sql, a); db.commit()

    def buy(self, c):
        gf._firogate_request = lambda e, p=None, method="POST": {
            "payment_id": "fg-shop-1", "checkout_url": "https://pay.example/invoice/fg-shop-1", "expires_at": ""}
        return c.post(f"/shop/{self.pid}/buy", data={"_csrf": CSRF}, headers=B)

    def hook(self, event, extra=None):
        order = self.q("SELECT order_id FROM firo_payments WHERE kind='product'")["order_id"]
        payload = {"event": event, "payment_id": "fg-shop-1", "order_id": order, "amount_firo": 1.5,
                   "amount_received": 1.5, "txid": "ef" * 32, "nonce": uuid.uuid4().hex, "timestamp": int(time.time())}
        payload.update(extra or {})
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
        return gf.app.test_client().post("/webhook/firogate", data=raw, content_type="application/json", headers={
            "X-FiroGate-Event": event, "X-FiroGate-Signature": sig, "X-FiroGate-Nonce": payload["nonce"],
            "X-FiroGate-Timestamp": str(payload["timestamp"])})

    def owns(self, tid):
        return self.q("SELECT 1 FROM purchases WHERE product_id=? AND token_id=?", self.pid, tid) is not None

    def test_buying_needs_an_account(self):
        r = self.client().post(f"/shop/{self.pid}/buy", data={"_csrf": CSRF}, headers=B)
        self.assertEqual(r.status_code, 302)
        self.assertIn("token-access", r.headers["Location"])
        self.assertIsNone(self.q("SELECT 1 FROM firo_payments"))

    def test_buy_creates_product_payment_with_product_price(self):
        r = self.buy(self.client("buyer-key"))
        self.assertIn("fg-shop-1", r.headers["Location"])
        row = self.q("SELECT kind, product_id, amount_firo FROM firo_payments")
        self.assertEqual((row["kind"], row["product_id"], row["amount_firo"]), ("product", self.pid, 1.5))

    def test_confirm_gives_product_not_badge(self):
        self.buy(self.client("buyer-key"))
        self.hook("payment.confirmed")
        self.assertTrue(self.owns(self.buyer))
        self.assertEqual(self.q("SELECT verified FROM tokens WHERE id=?", self.buyer)["verified"], 0)
        self.assertEqual(self.q("SELECT sales FROM products WHERE id=?", self.pid)["sales"], 1)

    def test_underpaid_product_not_given(self):
        self.buy(self.client("buyer-key"))
        self.hook("payment.confirmed", {"amount_received": 1.0})
        self.assertFalse(self.owns(self.buyer))

    def test_secret_and_file_only_for_buyer(self):
        self.buy(self.client("buyer-key")); self.hook("payment.confirmed")
        other = self.client("other-key")
        self.assertNotIn(b"LICENSE-KEY-1234", other.get(f"/shop/{self.pid}", headers=B).data)
        self.assertEqual(other.get(f"/shop/{self.pid}/download", headers=B).status_code, 403)
        self.assertEqual(self.client().get(f"/shop/{self.pid}/download", headers=B).status_code, 302)
        buyer = self.client("buyer-key")
        self.assertIn(b"LICENSE-KEY-1234", buyer.get(f"/shop/{self.pid}", headers=B).data)
        d = buyer.get(f"/shop/{self.pid}/download", headers=B)
        self.assertEqual(d.status_code, 200)
        self.assertEqual(d.data, b"PK secret zip bytes")
        self.assertIn("attachment", d.headers["Content-Disposition"])
        self.assertEqual(d.mimetype, "application/octet-stream")

    def test_only_buyers_rate_and_stars_checked(self):
        self.assertEqual(self.client("other-key").post(f"/shop/{self.pid}/rate", data={"_csrf": CSRF, "stars": "5"}, headers=B).status_code, 403)
        self.buy(self.client("buyer-key")); self.hook("payment.confirmed")
        c = self.client("buyer-key")
        c.post(f"/shop/{self.pid}/rate", data={"_csrf": CSRF, "stars": "9"}, headers=B)
        self.assertIsNone(self.q("SELECT 1 FROM product_ratings"))
        c.post(f"/shop/{self.pid}/rate", data={"_csrf": CSRF, "stars": "4", "note": "x" * 900}, headers=B)
        c.post(f"/shop/{self.pid}/rate", data={"_csrf": CSRF, "stars": "5", "note": "great"}, headers=B)
        row = self.q("SELECT stars, note, (SELECT COUNT(*) FROM product_ratings) AS n FROM product_ratings")
        self.assertEqual((row["stars"], row["note"], row["n"]), (5, "great", 1))

    def test_refund_removes_access_and_rating(self):
        self.buy(self.client("buyer-key")); self.hook("payment.confirmed")
        self.client("buyer-key").post(f"/shop/{self.pid}/rate", data={"_csrf": CSRF, "stars": "5"}, headers=B)
        self.hook("payment.refunded")
        self.assertFalse(self.owns(self.buyer))
        self.assertIsNone(self.q("SELECT 1 FROM product_ratings"))

    def test_members_only_and_shop_off(self):
        self.run_sql("UPDATE settings SET value='members' WHERE key='shop_visibility'")
        self.assertEqual(self.client().get("/shop", headers=B).status_code, 302)
        self.assertEqual(self.client("buyer-key").get("/shop", headers=B).status_code, 200)
        self.run_sql("UPDATE settings SET value='0' WHERE key='shop_enabled'")
        self.assertEqual(self.client("buyer-key").get("/shop", headers=B).status_code, 404)

    def test_hidden_product_not_public(self):
        self.run_sql("UPDATE products SET active=0")
        self.assertEqual(self.client("buyer-key").get(f"/shop/{self.pid}", headers=B).status_code, 404)
        self.assertEqual(self.client(admin=True).get(f"/shop/{self.pid}", headers=B).status_code, 200)

    def test_admin_upload_stored_privately(self):
        c = self.client(admin=True)
        r = c.post("/t-admin/products/new", headers=B, content_type="multipart/form-data", data={
            "_csrf": CSRF, "title": "Pack", "price_firo": "2", "active": "on",
            "file": (io.BytesIO(b"hello"), "../../evil name.zip")})
        self.assertEqual(r.status_code, 302)
        row = self.q("SELECT file_name, file_label FROM products WHERE title='Pack'")
        self.assertRegex(row["file_name"], r"^[0-9a-f]{32}\.bin$")
        self.assertEqual(row["file_label"], "evil name.zip")
        self.assertTrue(os.path.isfile(os.path.join(self.pdir, row["file_name"])))

    def test_any_file_type_and_big_files(self):
        c = self.client(admin=True)
        big = b"x" * (25 * 1024 * 1024)
        for name, data in (("disk.iso", big), ("pack.rar", b"Rar!"), ("setup.exe", b"MZ")):
            r = c.post("/t-admin/products/new", headers=B, content_type="multipart/form-data", data={
                "_csrf": CSRF, "title": name, "price_firo": "1", "active": "on", "file": (io.BytesIO(data), name)})
            self.assertEqual(r.status_code, 302, name)
            row = self.q("SELECT file_name, file_label, file_size FROM products WHERE title=?", name)
            self.assertEqual((row["file_label"], row["file_size"]), (name, len(data)))
            self.assertRegex(row["file_name"], r"^[0-9a-f]{32}\.bin$")

    def test_file_over_limit_refused_and_not_kept(self):
        old = gf.PRODUCT_FILE_MAX
        gf.PRODUCT_FILE_MAX = 1024
        try:
            before = set(os.listdir(self.pdir))
            r = self.client(admin=True).post("/t-admin/products/new", headers=B, content_type="multipart/form-data", data={
                "_csrf": CSRF, "title": "Huge", "price_firo": "1", "file": (io.BytesIO(b"y" * 5000), "huge.zip")})
            self.assertIn(b"bigger than", r.data)
            self.assertEqual(set(os.listdir(self.pdir)), before)
            self.assertIsNone(self.q("SELECT 1 FROM products WHERE title='Huge'"))
        finally:
            gf.PRODUCT_FILE_MAX = old

    def test_big_upload_only_for_admin(self):
        r = self.client("buyer-key").post("/t-admin/products/new", headers=B, content_type="multipart/form-data",
                                          data={"_csrf": CSRF, "file": (io.BytesIO(b"z" * (21 * 1024 * 1024)), "a.zip")})
        self.assertEqual(r.status_code, 413)

    def test_badge_payment_does_not_unlock_product(self):
        self.run_sql("INSERT INTO firo_payments (id,token_id,order_id,fg_payment_id,amount_firo,status,checkout_url,created) "
                     "VALUES ('x',?, 'VERIFY-1','fg-v',3.99,'pending','https://p','2026-01-01')", self.buyer)
        payload = {"event": "payment.confirmed", "payment_id": "fg-v", "order_id": "VERIFY-1", "amount_received": 3.99,
                   "txid": "aa" * 32, "nonce": uuid.uuid4().hex, "timestamp": int(time.time())}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        gf.app.test_client().post("/webhook/firogate", data=raw, content_type="application/json", headers={
            "X-FiroGate-Event": "payment.confirmed", "X-FiroGate-Signature": hmac.new(SECRET, raw, hashlib.sha256).hexdigest(),
            "X-FiroGate-Nonce": payload["nonce"], "X-FiroGate-Timestamp": str(payload["timestamp"])})
        self.assertEqual(self.q("SELECT verified FROM tokens WHERE id=?", self.buyer)["verified"], 1)
        self.assertFalse(self.owns(self.buyer))


if __name__ == "__main__":
    unittest.main()
