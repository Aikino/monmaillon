#!/usr/bin/env python3
"""Mon Maillon — liste d'attente (version locale, SQLite).

Reprend la logique du prompt P03 (Supabase + Brevo) pour tourner sur cette machine :
- POST /api/inscription  : inscription (honeypot, validation, 5 essais/heure/IP, doublons)
- GET  /api/confirmer?t= : confirmation double opt-in (lien valable 7 jours) -> rang + lien de parrainage
- GET  /api/stats        : nombre de familles confirmées (le site ne l'affiche qu'à partir de 100)
- tout le reste           : fichiers statiques de ../site

E-mails : si SMTP_HOST est défini, envoi réel via SMTP (ex. smtp-relay.brevo.com:587).
Sinon, le mail est écrit dans outbox/ et le lien de confirmation est affiché dans le journal.

Lancer :  python3 server.py --bind 0.0.0.0 --port 8080
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

HERE = Path(__file__).resolve().parent
SITE_DIR = Path(os.environ.get("SITE_DIR", HERE.parent / "site"))
DB_PATH = Path(os.environ.get("WAITLIST_DB", HERE / "waitlist.db"))
OUTBOX = Path(os.environ.get("OUTBOX_DIR", HERE / "outbox"))
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8080").rstrip("/")
CONSENT_VERSION = "2026-11-v1"
TOKEN_DAYS = 7
RATE_LIMIT_PER_HOUR = 5
REFERRAL_BONUS = 50
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # sans 0/O, 1/I/L
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
CP_RE = re.compile(r"^\d{4,5}$")
MAX_BODY = 4096

SCHEMA = """
CREATE TABLE IF NOT EXISTS waitlist (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
  first_name      TEXT NOT NULL,
  postal_code     TEXT NOT NULL,
  two_homes       INTEGER NOT NULL DEFAULT 0,
  pain            TEXT,
  referral_code   TEXT NOT NULL UNIQUE,
  referred_by     TEXT,
  confirm_token   TEXT NOT NULL UNIQUE,
  token_sent_at   TEXT NOT NULL,
  confirmed_at    TEXT,
  created_at      TEXT NOT NULL,
  ip_hash         TEXT,
  consent_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS waitlist_referred_by ON waitlist(referred_by);
CREATE INDEX IF NOT EXISTS waitlist_confirmed_at ON waitlist(confirmed_at);
CREATE TABLE IF NOT EXISTS signup_attempts (
  ip_hash TEXT NOT NULL,
  at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS signup_attempts_ip ON signup_attempts(ip_hash, at);
"""


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="microseconds")


def load_salt():
    env = os.environ.get("IP_SALT")
    if env:
        return env.encode()
    path = HERE / ".ip_salt"
    if not path.exists():
        path.write_text(secrets.token_hex(32))
        path.chmod(0o600)
    return path.read_text().strip().encode()


def connect(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def new_code(conn):
    while True:
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
        if not conn.execute("SELECT 1 FROM waitlist WHERE referral_code=?", (code,)).fetchone():
            return code


def rank(conn, row):
    """Rang = ordre de confirmation − 50 × filleuls confirmés (minimum 1)."""
    pos = conn.execute(
        "SELECT COUNT(*) FROM waitlist WHERE confirmed_at IS NOT NULL AND (confirmed_at < ? OR (confirmed_at = ? AND created_at <= ?))",
        (row["confirmed_at"], row["confirmed_at"], row["created_at"]),
    ).fetchone()[0]
    filleuls = conn.execute(
        "SELECT COUNT(*) FROM waitlist WHERE referred_by=? AND confirmed_at IS NOT NULL",
        (row["referral_code"],),
    ).fetchone()[0]
    return max(1, pos - REFERRAL_BONUS * filleuls), filleuls


# ---------- e-mails ----------

def confirmation_email(to, prenom, link):
    msg = EmailMessage()
    msg["Subject"] = "Confirme ta place 🔗"
    msg["From"] = os.environ.get("MAIL_FROM", "Mon Maillon <bonjour@monmaillon.be>")
    msg["To"] = to
    msg.set_content(
        f"Bonjour {prenom},\n\n"
        "Plus qu'un clic et ta place est réservée !\n\n"
        f"Je confirme ma place : {link}\n\n"
        "Ensuite, on te dira ta place dans la liste… et comment la faire grimper.\n\n"
        "À très vite,\nHervé — Mon Maillon\n\n"
        "Tu n'as rien demandé ? Ignore simplement ce message, tu ne recevras rien d'autre.\n"
    )
    return msg


def send_mail(msg):
    host = os.environ.get("SMTP_HOST")
    if host:
        port = int(os.environ.get("SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.starttls()
            user = os.environ.get("SMTP_USER")
            if user:
                s.login(user, os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
        return "smtp"
    OUTBOX.mkdir(exist_ok=True)
    name = f"{now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}.eml"
    (OUTBOX / name).write_bytes(bytes(msg))
    return f"outbox/{name}"


# ---------- logique ----------

class Waitlist:
    def __init__(self, db_path=None, salt=None, mailer=send_mail):
        self.db_path = db_path or DB_PATH
        self.salt = salt or load_salt()
        self.mailer = mailer
        connect(self.db_path).close()

    def ip_hash(self, ip):
        return hmac.new(self.salt, (ip or "").encode(), hashlib.sha256).hexdigest()[:32]

    def signup(self, data, ip):
        """Retourne (status_http, payload)."""
        if not isinstance(data, dict):
            return 400, {"status": "invalid", "errors": {"_": "format"}}
        if str(data.get("site") or "").strip():  # honeypot : on fait semblant que tout va bien
            return 200, {"status": "ok"}

        prenom = str(data.get("prenom") or "").strip()[:60]
        email = str(data.get("email") or "").strip().lower()[:254]
        cp = str(data.get("cp") or "").strip()
        errors = {}
        if not prenom:
            errors["prenom"] = "missing"
        if not email:
            errors["email"] = "missing"
        elif not EMAIL_RE.match(email):
            errors["email"] = "invalid"
        if not cp:
            errors["cp"] = "missing"
        elif not CP_RE.match(cp):
            errors["cp"] = "invalid"
        if data.get("rgpd") is not True:
            errors["rgpd"] = "required"
        if errors:
            return 400, {"status": "invalid", "errors": errors}

        two_homes = 1 if data.get("maisons") is True else 0
        ref = str(data.get("ref") or "").strip().upper()[:8] or None
        iph = self.ip_hash(ip)
        t = now()

        conn = connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM signup_attempts WHERE at < ?", (iso(t - timedelta(hours=1)),))
            n = conn.execute("SELECT COUNT(*) FROM signup_attempts WHERE ip_hash=?", (iph,)).fetchone()[0]
            if n >= RATE_LIMIT_PER_HOUR:
                conn.execute("COMMIT")
                return 429, {"status": "rate_limited"}
            conn.execute("INSERT INTO signup_attempts(ip_hash, at) VALUES (?, ?)", (iph, iso(t)))

            row = conn.execute("SELECT * FROM waitlist WHERE email=?", (email,)).fetchone()
            if row and row["confirmed_at"]:
                conn.execute("COMMIT")
                return 200, {"status": "already"}

            if ref and not conn.execute("SELECT 1 FROM waitlist WHERE referral_code=?", (ref,)).fetchone():
                ref = None
            token = str(uuid.uuid4())
            if row:
                conn.execute(
                    "UPDATE waitlist SET first_name=?, postal_code=?, two_homes=?, confirm_token=?, token_sent_at=?, "
                    "referred_by=COALESCE(referred_by, ?), ip_hash=?, consent_version=? WHERE id=?",
                    (prenom, cp, two_homes, token, iso(t), ref if ref != row["referral_code"] else None, iph, CONSENT_VERSION, row["id"]),
                )
                status = "already"  # « On t'a renvoyé le lien de confirmation »
            else:
                conn.execute(
                    "INSERT INTO waitlist(id, email, first_name, postal_code, two_homes, referral_code, referred_by, "
                    "confirm_token, token_sent_at, created_at, ip_hash, consent_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), email, prenom, cp, two_homes, new_code(conn), ref, token, iso(t), iso(t), iph, CONSENT_VERSION),
                )
                status = "ok"
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

        link = f"{PUBLIC_URL}/confirmer.html?t={token}"
        where = self.mailer(confirmation_email(email, prenom, link))
        log(f"inscription {status} — e-mail de confirmation → {where} — lien : {link}")
        return 200, {"status": status}

    def confirm(self, token):
        try:
            uuid.UUID(str(token))
        except (ValueError, TypeError):
            return 400, {"status": "invalid"}
        conn = connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM waitlist WHERE confirm_token=?", (token,)).fetchone()
            if not row:
                conn.execute("COMMIT")
                return 404, {"status": "invalid"}
            if not row["confirmed_at"]:
                sent = datetime.fromisoformat(row["token_sent_at"])
                if now() - sent > timedelta(days=TOKEN_DAYS):
                    conn.execute("COMMIT")
                    return 410, {"status": "expired"}
                conn.execute("UPDATE waitlist SET confirmed_at=? WHERE id=?", (iso(now()), row["id"]))
                row = conn.execute("SELECT * FROM waitlist WHERE id=?", (row["id"],)).fetchone()
            conn.execute("COMMIT")
            r, filleuls = rank(conn, row)
        finally:
            conn.close()
        return 200, {
            "status": "confirmed",
            "prenom": row["first_name"],
            "rang": r,
            "filleuls": filleuls,
            "lien": f"{PUBLIC_URL}/?ref={row['referral_code']}",
        }

    def stats(self):
        conn = connect(self.db_path)
        try:
            n = conn.execute("SELECT COUNT(*) FROM waitlist WHERE confirmed_at IS NOT NULL").fetchone()[0]
        finally:
            conn.close()
        return 200, {"confirmes": n}


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# ---------- HTTP ----------

class Handler(SimpleHTTPRequestHandler):
    wl: Waitlist = None

    def log_message(self, fmt, *args):  # pas d'IP en clair dans les journaux
        log(f"{self.command} {urlparse(self.path).path} → {args[1] if len(args) > 1 else ''}")

    def client_ip(self):
        # Derrière un proxy de confiance uniquement : TRUST_PROXY=1
        if os.environ.get("TRUST_PROXY") == "1":
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[0].strip()
        return self.client_address[0]

    def send_json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        super().end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/inscription":
            return self.send_json(404, {"status": "not_found"})
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self.send_json(415, {"status": "invalid"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self.send_json(413, {"status": "invalid"})
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self.send_json(400, {"status": "invalid"})
        try:
            code, payload = self.wl.signup(data, self.client_ip())
        except Exception as e:  # noqa: BLE001
            log(f"erreur inscription : {type(e).__name__}: {e}")
            code, payload = 500, {"status": "error"}
        self.send_json(code, payload)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/confirmer":
            t = parse_qs(u.query).get("t", [""])[0]
            return self.send_json(*self.wl.confirm(t))
        if u.path == "/api/stats":
            return self.send_json(*self.wl.stats())
        if u.path.startswith("/api/"):
            return self.send_json(404, {"status": "not_found"})
        if u.path.endswith(("presentation.html",)) or "/." in u.path:
            self.send_error(404)
            return
        return super().do_GET()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    Handler.wl = Waitlist()
    handler = partial(Handler, directory=str(SITE_DIR))
    srv = ThreadingHTTPServer((args.bind, args.port), handler)
    log(f"Mon Maillon — site {SITE_DIR} — base {DB_PATH} — http://{args.bind}:{args.port}  (e-mails : {'SMTP ' + os.environ['SMTP_HOST'] if os.environ.get('SMTP_HOST') else 'outbox/'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
