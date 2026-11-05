"""Tests de la liste d'attente : python3 -m unittest -v (depuis waitlist/)."""
import json
import tempfile
import threading
import unittest
import urllib.request
from datetime import timedelta
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path

import server

SENT = []


def fake_mailer(msg):
    SENT.append(msg)
    return "test"


def token_from_last_mail():
    body = SENT[-1].get_content()
    return body.split("?t=")[1].split()[0]


def payload(**kw):
    d = {"prenom": "Anne", "email": "anne@example.be", "cp": "4000", "maisons": False, "rgpd": True, "site": ""}
    d.update(kw)
    return d


class WaitlistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        SENT.clear()
        self.wl = server.Waitlist(db_path=Path(self.tmp.name) / "t.db", salt=b"sel", mailer=fake_mailer)

    def tearDown(self):
        self.tmp.cleanup()

    def test_inscription_puis_confirmation(self):
        code, r = self.wl.signup(payload(), "1.2.3.4")
        self.assertEqual((code, r["status"]), (200, "ok"))
        self.assertEqual(len(SENT), 1)
        code, r = self.wl.confirm(token_from_last_mail())
        self.assertEqual(r["status"], "confirmed")
        self.assertEqual(r["rang"], 1)
        self.assertIn("?ref=", r["lien"])
        self.assertEqual(self.wl.stats()[1]["confirmes"], 1)

    def test_validation(self):
        code, r = self.wl.signup(payload(email="pas-un-mail", cp="abc", rgpd=False, prenom=""), "1.2.3.4")
        self.assertEqual(code, 400)
        self.assertEqual(set(r["errors"]), {"email", "cp", "rgpd", "prenom"})
        self.assertEqual(SENT, [])

    def test_honeypot(self):
        code, r = self.wl.signup(payload(site="spam.example"), "1.2.3.4")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(SENT, [])
        self.assertEqual(self.wl.stats()[1]["confirmes"], 0)

    def test_doublon(self):
        self.wl.signup(payload(), "1.1.1.1")
        code, r = self.wl.signup(payload(email="ANNE@example.be"), "1.1.1.2")
        self.assertEqual(r["status"], "already")  # non confirmé : nouveau lien envoyé
        self.assertEqual(len(SENT), 2)
        self.wl.confirm(token_from_last_mail())
        code, r = self.wl.signup(payload(), "1.1.1.3")
        self.assertEqual(r["status"], "already")
        self.assertEqual(len(SENT), 2)  # confirmé : plus de mail

    def test_limite_par_ip(self):
        for i in range(5):
            self.assertEqual(self.wl.signup(payload(email=f"p{i}@example.be"), "9.9.9.9")[0], 200)
        code, r = self.wl.signup(payload(email="p6@example.be"), "9.9.9.9")
        self.assertEqual((code, r["status"]), (429, "rate_limited"))
        self.assertEqual(self.wl.signup(payload(email="autre@example.be"), "8.8.8.8")[0], 200)

    def test_lien_expire(self):
        self.wl.signup(payload(), "1.2.3.4")
        tok = token_from_last_mail()
        conn = server.connect(self.wl.db_path)
        conn.execute("UPDATE waitlist SET token_sent_at=?", (server.iso(server.now() - timedelta(days=8)),))
        conn.close()
        self.assertEqual(self.wl.confirm(tok), (410, {"status": "expired"}))
        self.assertEqual(self.wl.confirm("pas-un-token")[1]["status"], "invalid")
        self.assertEqual(self.wl.confirm("00000000-0000-0000-0000-000000000000")[1]["status"], "invalid")

    def test_parrainage_fait_monter(self):
        # 60 familles confirmées, puis la 61e parraine un ami → 61 − 50 = 11
        for i in range(60):
            self.wl.signup(payload(email=f"f{i}@example.be"), f"10.0.{i}.1")
            self.wl.confirm(token_from_last_mail())
        self.wl.signup(payload(email="parrain@example.be"), "10.1.0.1")
        r = self.wl.confirm(token_from_last_mail())[1]
        self.assertEqual(r["rang"], 61)
        ref = r["lien"].split("ref=")[1]
        self.wl.signup(payload(email="ami@example.be", ref=ref), "10.2.0.1")
        self.wl.confirm(token_from_last_mail())
        conn = server.connect(self.wl.db_path)
        row = conn.execute("SELECT * FROM waitlist WHERE email='parrain@example.be'").fetchone()
        self.assertEqual(server.rank(conn, row), (11, 1))
        conn.close()

    def test_pas_d_ip_en_clair(self):
        self.wl.signup(payload(), "203.0.113.7")
        conn = server.connect(self.wl.db_path)
        dump = "\n".join(conn.iterdump())
        conn.close()
        self.assertNotIn("203.0.113.7", dump)


class HttpTests(unittest.TestCase):
    """Le vrai serveur HTTP, sur un port local éphémère."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        site = Path(cls.tmp.name) / "site"
        site.mkdir()
        (site / "index.html").write_text("<h1>ok</h1>")
        (site / "presentation.html").write_text("source")
        server.Handler.wl = server.Waitlist(db_path=Path(cls.tmp.name) / "h.db", salt=b"s", mailer=fake_mailer)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), partial(server.Handler, directory=str(site)))
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def req(self, path, data=None):
        r = urllib.request.Request(self.base + path, data=json.dumps(data).encode() if data is not None else None,
                                   headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_parcours_http(self):
        code, body = self.req("/api/inscription", payload(email="http@example.be"))
        self.assertEqual((code, json.loads(body)["status"]), (200, "ok"))
        code, body = self.req("/api/confirmer?t=" + token_from_last_mail())
        self.assertEqual(json.loads(body)["status"], "confirmed")
        self.assertEqual(self.req("/")[0], 200)
        self.assertEqual(self.req("/presentation.html")[0], 404)

    def test_json_invalide(self):
        r = urllib.request.Request(self.base + "/api/inscription", data=b"{pas du json", headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        self.assertEqual(cm.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
