import hashlib, hmac, json, os, sys, tempfile, time, unittest, uuid
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("GATEFORUM_ADMIN_PREFIX", "t-admin")
os.environ.setdefault("GATEFORUM_ADMIN_SUFFIX", "t-login")
os.environ["FIROGATE_API_KEY"] = "fg_test_key"
os.environ["FIROGATE_WEBHOOK_SECRET"] = "whsec_test"
os.environ["SITE_BASE_URL"] = "https://forum.example"

import app as gf  # noqa: E402

SECRET = b"whsec_test"
BROWSER = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
           "Accept": "text/html", "Accept-Language": "en"}


def body_of(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class PaymentTests(unittest.TestCase):
    def setUp(self):
        fd, self.dbp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        gf.app.config["DATABASE"] = self.dbp
        gf.app.config["TESTING"] = True
        gf.FIROGATE_API_KEY = "fg_test_key"
        gf.FIROGATE_WEBHOOK_SECRET = "whsec_test"
        gf.FIROGATE_VERIFY_AMOUNT = 2.0
        for store in (gf._rl_page, gf._rl_post, gf._rl_webhook, gf._rl_pay, gf._rl_status):
            store.clear()
        gf._DbSessionInterface._ensure_table(gf.app)
        with gf.app.app_context():
            gf.init_db()
            db = gf.get_db()
            self.tok_id = uuid.uuid4().hex
            db.execute("INSERT INTO tokens (id,label,token_hash,created) VALUES (?,?,?,?)",
                       (self.tok_id, "t", hashlib.sha256(b"secret-token").hexdigest(), "2026-01-01"))
            db.commit()
        self.c = gf.app.test_client()
        self.c.set_cookie("dn_token", "secret-token")
        self.calls = []
        self._orig = gf._firogate_request

    def tearDown(self):
        gf._firogate_request = self._orig
        os.remove(self.dbp)

    def q(self, sql, *a):
        with gf.app.app_context():
            return gf.get_db().execute(sql, a).fetchone()

    def add_payment(self, status="pending", fg_id="fgpay-1", expires=None, order="VERIFY-1"):
        with gf.app.app_context():
            db = gf.get_db()
            db.execute(
                "INSERT INTO firo_payments (id,token_id,order_id,fg_payment_id,amount_firo,status,checkout_url,expires_at,created) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, self.tok_id, order, fg_id, 2.0, status,
                 "https://pay.example/invoice/" + fg_id, expires or "", "2026-01-01 00:00:00"))
            db.commit()

    def hook(self, event, extra=None, ts=None, nonce=None, secret=SECRET, sig=None):
        payload = {"event": event, "payment_id": "fgpay-1", "order_id": "VERIFY-1",
                   "amount_firo": 2.0, "amount_received": 2.0, "txid": "ab" * 32,
                   "nonce": nonce or uuid.uuid4().hex, "timestamp": ts or int(time.time())}
        payload.update(extra or {})
        raw = body_of(payload)
        signature = sig or hmac.new(secret, raw, hashlib.sha256).hexdigest()
        return self.c.post("/webhook/firogate", data=raw, content_type="application/json", headers={
            "X-FiroGate-Event": event, "X-FiroGate-Signature": signature,
            "X-FiroGate-Nonce": payload["nonce"], "X-FiroGate-Timestamp": str(payload["timestamp"])})

    def verified(self):
        return self.q("SELECT verified FROM tokens WHERE id=?", self.tok_id)["verified"]

    def test_webhook_confirms_and_grants(self):
        self.add_payment()
        self.assertEqual(self.hook("payment.confirmed").status_code, 200)
        self.assertEqual(self.verified(), 1)
        row = self.q("SELECT status, txid FROM firo_payments WHERE order_id='VERIFY-1'")
        self.assertEqual(row["status"], "confirmed")
        self.assertEqual(row["txid"], "ab" * 32)

    def test_bad_signature_rejected(self):
        self.add_payment()
        self.assertEqual(self.hook("payment.confirmed", secret=b"wrong").status_code, 403)
        self.assertEqual(self.verified(), 0)

    def test_stale_timestamp_rejected(self):
        self.add_payment()
        self.assertEqual(self.hook("payment.confirmed", ts=int(time.time()) - 3600).status_code, 403)
        self.assertEqual(self.verified(), 0)

    def test_replayed_nonce_ignored(self):
        self.add_payment()
        self.hook("payment.expired", nonce="n1")
        self.assertEqual(self.q("SELECT status FROM firo_payments")["status"], "expired")
        with gf.app.app_context():
            gf.get_db().execute("UPDATE firo_payments SET status='pending'")
            gf.get_db().commit()
        self.hook("payment.expired", nonce="n1")
        self.assertEqual(self.q("SELECT status FROM firo_payments")["status"], "pending")

    def test_underpaid_not_granted(self):
        self.add_payment()
        self.hook("payment.confirmed", extra={"amount_received": 1.0})
        self.assertEqual(self.verified(), 0)
        self.assertEqual(self.q("SELECT status FROM firo_payments")["status"], "underpaid")

    def test_other_payment_id_not_granted(self):
        self.add_payment()
        self.hook("payment.confirmed", extra={"payment_id": "someone-else"})
        self.assertEqual(self.verified(), 0)

    def test_refund_removes_badge(self):
        self.add_payment()
        self.hook("payment.confirmed")
        self.hook("payment.refunded")
        self.assertEqual(self.verified(), 0)
        self.assertEqual(self.q("SELECT status FROM firo_payments")["status"], "refunded")

    def test_no_secret_rejects(self):
        self.add_payment()
        gf.FIROGATE_WEBHOOK_SECRET = ""
        self.assertNotEqual(self.hook("payment.confirmed").status_code, 200)
        self.assertEqual(self.verified(), 0)

    def test_status_poll_uses_gateway_payment_id(self):
        self.add_payment()

        def fake(endpoint, payload=None, method="POST"):
            self.calls.append((method, endpoint))
            return {"payment_id": "fgpay-1", "order_id": "VERIFY-1", "status": "confirmed",
                    "amount_received": 2.0, "txid": "cd" * 32}
        gf._firogate_request = fake
        r = self.c.get("/verify/status", headers=BROWSER)
        self.assertEqual(r.get_json()["verified"], True)
        self.assertEqual(self.calls, [("GET", "/api/payments/fgpay-1")])
        self.assertEqual(self.verified(), 1)

    def test_status_poll_pending_not_granted(self):
        self.add_payment()
        gf._firogate_request = lambda e, p=None, method="POST": {"payment_id": "fgpay-1", "status": "pending"}
        self.assertEqual(self.c.get("/verify/status", headers=BROWSER).get_json()["verified"], False)
        self.assertEqual(self.verified(), 0)

    def _csrf(self):
        self.c.get("/contribute", headers=BROWSER)
        with self.c.session_transaction() as s:
            s["csrf"] = "c" * 64
        return "c" * 64

    def test_pay_stores_gateway_id_and_reuses_open_checkout(self):
        def fake(endpoint, payload=None, method="POST"):
            self.calls.append(endpoint)
            return {"payment_id": "fgpay-new", "checkout_url": "https://pay.example/invoice/fgpay-new?t=x",
                    "expires_at": (datetime.now() + timedelta(minutes=20)).isoformat()}
        gf._firogate_request = fake
        tok = self._csrf()
        r1 = self.c.post("/verify/pay", data={"_csrf": tok}, headers=BROWSER)
        self.assertEqual(r1.status_code, 302)
        self.assertEqual(self.q("SELECT fg_payment_id FROM firo_payments")["fg_payment_id"], "fgpay-new")
        self.c.post("/verify/pay", data={"_csrf": tok}, headers=BROWSER)
        self.assertEqual(len(self.calls), 1)

    def test_pay_skips_expired_checkout(self):
        self.add_payment(expires=(datetime.now() - timedelta(minutes=1)).isoformat())
        gf._firogate_request = lambda e, p=None, method="POST": {
            "payment_id": "fgpay-2", "checkout_url": "https://pay.example/invoice/fgpay-2"}
        tok = self._csrf()
        r = self.c.post("/verify/pay", data={"_csrf": tok}, headers=BROWSER)
        self.assertIn("fgpay-2", r.headers["Location"])

    def test_gateway_error_not_shown(self):
        def boom(*a, **k):
            raise gf.GatewayError("HTTP 500 internal secret detail")
        gf._firogate_request = boom
        tok = self._csrf()
        r = self.c.post("/verify/pay", data={"_csrf": tok}, headers=BROWSER)
        self.assertEqual(r.status_code, 503)
        self.assertNotIn(b"secret detail", r.data)

    def test_error_responses_not_cached(self):
        r = self.c.get("/static/css/style.css", headers={"User-Agent": "curl/8"})
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("max-age", r.headers.get("Cache-Control", ""))


if __name__ == "__main__":
    unittest.main()
