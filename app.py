import os
import re
import threading
import uuid
import asyncio
import secrets
import string
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse, parse_qs, unquote

import numpy as np
import cv2
import pyotp
import libsql_client
from email import policy
from email.parser import BytesParser

from flask import (
    Flask,
    abort,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
    session,
    flash,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# DIRECT CONFIG (NO ENV)
# ============================================================

TURSO_DB_URL = "https://test-tolaramstudent.aws-ap-south-1.turso.io"
TURSO_AUTH_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3Njk4NzI0NTQsImlkIjoiMzE5ZmZkZDktYmJlZC00NzUzLThjNDgtY2NhZmU0MWI1NmQ1IiwicmlkIjoiZjM3NDlmY2UtODY4NC00NDY4LWE4ZDgtOTExMzIzYzg4ZWRlIn0.f1jDCYidUaBotL0TxC_BwKdZjDE_GXa68FQkGhzdLkQuZu0agUmFbcOK_rJXpSDX9U3dJTMs36uMsRNOL-yzDw"  # <-- আপনার Turso JWT

INGEST_TOKEN = "CHANGE_THIS_TO_LONG_RANDOM_SECRET"  # <-- Worker -> Backend shared secret

EMAIL_DOMAIN = "xneko.xyz"  # <-- আপনার Cloudflare domain (example.com)

MAILBOX_REGEX = r"^[a-z0-9]{6,20}$"  # local-part random হবে
MAILBOX_RANDOM_LEN = 10

# One-time password policy
GENERATED_PASSWORD_LEN = 18  # strong

FLASK_SECRET_KEY = "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_VALUE"
ALLOW_SIGNUP = True

# Optional: mailbox message cap (0=off)
MAX_MESSAGES_PER_MAILBOX = 0


# ============================================================
# Async executor (libsql-client needs running event loop)
# ============================================================

class AsyncExecutor:
    def __init__(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro, timeout=30):
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)

EXEC = AsyncExecutor()

async def _init_client():
    return libsql_client.create_client(url=TURSO_DB_URL, auth_token=TURSO_AUTH_TOKEN)

CLIENT = EXEC.run(_init_client())


# ============================================================
# DB schema
# ============================================================

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mailboxes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  local_part TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- gmail linked account (the "virtual email" record)
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  gmail TEXT NOT NULL,
  mailbox_id TEXT NOT NULL UNIQUE,
  local_part TEXT NOT NULL UNIQUE,
  generated_password TEXT NOT NULL,
  created_at TEXT NOT NULL,

  totp_secret TEXT,
  totp_issuer TEXT,
  totp_label TEXT,

  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  mailbox_id TEXT NOT NULL,
  envelope_from TEXT NOT NULL,
  envelope_to TEXT NOT NULL,
  subject TEXT,
  received_at TEXT NOT NULL,
  raw_size INTEGER NOT NULL,
  raw_eml BLOB NOT NULL,
  parsed_from TEXT,
  parsed_to TEXT,
  parsed_date TEXT,
  FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id)
);

CREATE INDEX IF NOT EXISTS idx_mailboxes_user ON mailboxes(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_received ON messages(mailbox_id, received_at DESC);
"""

async def _db_init():
    for stmt in [s.strip() for s in SCHEMA_SQL.split(";")]:
        if stmt:
            await CLIENT.execute(stmt + ";")

EXEC.run(_db_init())


# ============================================================
# Flask app
# ============================================================

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY


# ============================================================
# Helpers
# ============================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def bearer_token(req) -> str:
    auth = req.headers.get("authorization", "") or ""
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return ""

def normalize_user_email(email: str) -> str:
    e = (email or "").strip().lower()
    if not e or "@" not in e or len(e) > 200:
        abort(400, description="Invalid email")
    return e

def normalize_gmail(email: str) -> str:
    e = normalize_user_email(email)
    # optional: enforce gmail
    # if not (e.endswith("@gmail.com") or e.endswith("@googlemail.com")):
    #     abort(400, description="Only Gmail allowed")
    return e

def current_user_id() -> str | None:
    return session.get("uid")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

async def _db_execute(sql: str, args=()):
    return await CLIENT.execute(sql, args)

def db_execute(sql: str, args=()):
    return EXEC.run(_db_execute(sql, args))

def db_query(sql: str, args=()):
    return EXEC.run(_db_execute(sql, args))

def to_bytes(x):
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, memoryview):
        return x.tobytes()
    return bytes(x)

def parse_received_at(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return now_iso()
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return now_iso()

def maybe_parse_headers(raw_eml: bytes):
    parsed_from = None
    parsed_to = None
    parsed_date = None
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_eml)
        parsed_from = str(msg.get("from")) if msg.get("from") else None
        parsed_to = str(msg.get("to")) if msg.get("to") else None
        parsed_date = str(msg.get("date")) if msg.get("date") else None
    except Exception:
        pass
    return parsed_from, parsed_to, parsed_date


# ============================================================
# Random generators
# ============================================================

def random_local_part(length: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def strong_password(length: int) -> str:
    # strong: mix of sets, guaranteed at least 1 from each
    if length < 12:
        length = 12

    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.?/"

    # ensure each category at least once
    core = [
        secrets.choice(lowers),
        secrets.choice(uppers),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    all_chars = lowers + uppers + digits + symbols
    core += [secrets.choice(all_chars) for _ in range(length - len(core))]
    secrets.SystemRandom().shuffle(core)
    return "".join(core)


# ============================================================
# QR / TOTP parsing
# ============================================================

def parse_otpauth_uri(uri: str) -> dict:
    """
    Returns dict: {secret, issuer, label}
    """
    u = uri.strip()
    if not u.lower().startswith("otpauth://"):
        raise ValueError("Not an otpauth URI")

    parsed = urlparse(u)
    if parsed.scheme.lower() != "otpauth":
        raise ValueError("Invalid otpauth scheme")

    # otpauth://totp/LABEL?secret=...&issuer=...
    label = unquote(parsed.path.lstrip("/")) if parsed.path else ""
    qs = parse_qs(parsed.query)

    secret = (qs.get("secret") or [""])[0].strip().replace(" ", "")
    issuer = (qs.get("issuer") or [""])[0].strip()

    if not secret:
        raise ValueError("Missing secret in otpauth")

    return {"secret": secret, "issuer": issuer or None, "label": label or None}

def decode_qr_from_image_bytes(image_bytes: bytes) -> str | None:
    """
    Tries to detect & decode QR in image (even if there are other objects).
    Returns decoded text or None.
    """
    if not image_bytes:
        return None

    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        return None

    det = cv2.QRCodeDetector()

    # try multi first
    ok, decoded_infos, points, _ = det.detectAndDecodeMulti(img)
    if ok and decoded_infos:
        for s in decoded_infos:
            if s and s.strip():
                return s.strip()

    # fallback single
    s, pts, _ = det.detectAndDecode(img)
    if s and s.strip():
        return s.strip()

    return None

def totp_now_and_remaining(secret: str) -> tuple[str, int]:
    # pyotp expects base32 secret
    totp = pyotp.TOTP(secret)
    code = totp.now()
    remaining = totp.interval - (datetime.now(timezone.utc).timestamp() % totp.interval)
    return code, int(remaining)


# ============================================================
# Auth Routes
# ============================================================

@app.get("/signup")
def signup():
    if not ALLOW_SIGNUP:
        abort(403)
    if current_user_id():
        return redirect(url_for("dashboard"))
    return render_template("auth_signup.html")

@app.post("/signup")
def signup_post():
    if not ALLOW_SIGNUP:
        abort(403)
    if current_user_id():
        return redirect(url_for("dashboard"))

    email = normalize_user_email(request.form.get("email", ""))
    password = (request.form.get("password", "") or "").strip()
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("signup"))

    user_id = str(uuid.uuid4())
    pw_hash = generate_password_hash(password)

    try:
        db_execute(
            "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (user_id, email, pw_hash, now_iso()),
        )
    except Exception:
        flash("Email already exists.", "error")
        return redirect(url_for("signup"))

    session["uid"] = user_id
    session["email"] = email
    return redirect(url_for("dashboard"))

@app.get("/login")
def login():
    if current_user_id():
        return redirect(url_for("dashboard"))
    return render_template("auth_login.html")

@app.post("/login")
def login_post():
    if current_user_id():
        return redirect(url_for("dashboard"))

    email = normalize_user_email(request.form.get("email", ""))
    password = (request.form.get("password", "") or "").strip()

    rs = db_query("SELECT id, password_hash FROM users WHERE email = ? LIMIT 1", (email,))
    if not rs.rows:
        flash("Invalid credentials.", "error")
        return redirect(url_for("login"))

    uid, pw_hash = rs.rows[0][0], rs.rows[0][1]
    if not check_password_hash(pw_hash, password):
        flash("Invalid credentials.", "error")
        return redirect(url_for("login"))

    session["uid"] = uid
    session["email"] = email
    return redirect(url_for("dashboard"))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# Dashboard + Account creation
# ============================================================

@app.get("/")
def root():
    if current_user_id():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.get("/dashboard")
@login_required
def dashboard():
    uid = current_user_id()
    rs = db_query(
        """
        SELECT a.id, a.gmail, a.local_part, a.generated_password, a.created_at,
               a.totp_secret,
               (SELECT COUNT(*) FROM messages m WHERE m.mailbox_id = a.mailbox_id) AS msg_count,
               (SELECT MAX(received_at) FROM messages m WHERE m.mailbox_id = a.mailbox_id) AS last_received
        FROM accounts a
        WHERE a.user_id = ?
        ORDER BY a.created_at DESC
        """,
        (uid,),
    )

    accounts = []
    for r in (rs.rows or []):
        accounts.append({
            "id": r[0],
            "gmail": r[1],
            "email": f"{r[2]}@{EMAIL_DOMAIN}",
            "local_part": r[2],
            "generated_password": r[3],
            "created_at": r[4],
            "has_totp": bool(r[5]),
            "msg_count": int(r[6] or 0),
            "last_received": r[7],
        })

    return render_template("dashboard.html", accounts=accounts, domain=EMAIL_DOMAIN)

@app.post("/accounts/create")
@login_required
def create_account():
    uid = current_user_id()
    gmail = normalize_gmail(request.form.get("gmail", ""))

    # create mailbox + account with unique local_part
    gen_pass = strong_password(GENERATED_PASSWORD_LEN)

    for _ in range(30):
        local = random_local_part(MAILBOX_RANDOM_LEN)
        if not re.match(MAILBOX_REGEX, local):
            continue

        mailbox_id = str(uuid.uuid4())
        account_id = str(uuid.uuid4())

        try:
            db_execute(
                "INSERT INTO mailboxes (id, user_id, local_part, created_at) VALUES (?, ?, ?, ?)",
                (mailbox_id, uid, local, now_iso()),
            )
            db_execute(
                """
                INSERT INTO accounts
                (id, user_id, gmail, mailbox_id, local_part, generated_password, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (account_id, uid, gmail, mailbox_id, local, gen_pass, now_iso()),
            )
            flash("New email created successfully. Copy the details from the account page.", "ok")
            return redirect(url_for("account_view", account_id=account_id))
        except Exception:
            # collision: local_part unique
            # try again with new random
            continue

    flash("Failed to create new email. Try again.", "error")
    return redirect(url_for("dashboard"))


# ============================================================
# Account detail + Authenticator setup
# ============================================================

def get_account_owned(uid: str, account_id: str) -> dict:
    rs = db_query(
        """
        SELECT id, user_id, gmail, mailbox_id, local_part, generated_password, created_at,
               totp_secret, totp_issuer, totp_label
        FROM accounts
        WHERE id = ? AND user_id = ?
        LIMIT 1
        """,
        (account_id, uid),
    )
    if not rs.rows:
        abort(404)
    r = rs.rows[0]
    return {
        "id": r[0],
        "user_id": r[1],
        "gmail": r[2],
        "mailbox_id": r[3],
        "local_part": r[4],
        "email": f"{r[4]}@{EMAIL_DOMAIN}",
        "generated_password": r[5],
        "created_at": r[6],
        "totp_secret": r[7],
        "totp_issuer": r[8],
        "totp_label": r[9],
    }

@app.get("/accounts/<account_id>")
@login_required
def account_view(account_id: str):
    uid = current_user_id()
    acct = get_account_owned(uid, account_id)

    # initial code (server render)
    code = None
    remaining = None
    if acct["totp_secret"]:
        try:
            code, remaining = totp_now_and_remaining(acct["totp_secret"])
        except Exception:
            code, remaining = None, None

    return render_template(
        "account.html",
        account=acct,
        code=code,
        remaining=remaining,
    )

@app.post("/accounts/<account_id>/authenticator")
@login_required
def account_set_authenticator(account_id: str):
    uid = current_user_id()
    acct = get_account_owned(uid, account_id)

    secret_input = (request.form.get("secret") or "").strip().replace(" ", "")
    file = request.files.get("qr_image")

    extracted = None
    issuer = None
    label = None

    if file and file.filename:
        img_bytes = file.read()
        decoded = decode_qr_from_image_bytes(img_bytes)
        if not decoded:
            flash("QR code not detected in the image. Try a clearer screenshot.", "error")
            return redirect(url_for("account_view", account_id=account_id))

        # decoded could be otpauth URI or plain secret
        try:
            data = parse_otpauth_uri(decoded)
            extracted = data["secret"]
            issuer = data["issuer"]
            label = data["label"]
        except Exception:
            # fallback: treat as secret
            extracted = decoded.strip().replace(" ", "")

    elif secret_input:
        extracted = secret_input

    else:
        flash("Please upload a QR image or paste a secret.", "error")
        return redirect(url_for("account_view", account_id=account_id))

    # validate secret by attempting to generate code
    try:
        _ = pyotp.TOTP(extracted).now()
    except Exception:
        flash("Invalid TOTP secret. Please try again.", "error")
        return redirect(url_for("account_view", account_id=account_id))

    db_execute(
        """
        UPDATE accounts
        SET totp_secret = ?, totp_issuer = ?, totp_label = ?
        WHERE id = ? AND user_id = ?
        """,
        (extracted, issuer, label, account_id, uid),
    )

    flash("Authenticator set successfully. Current code will update in real-time.", "ok")
    return redirect(url_for("account_view", account_id=account_id))

@app.get("/accounts/<account_id>/totp.json")
@login_required
def account_totp_json(account_id: str):
    uid = current_user_id()
    acct = get_account_owned(uid, account_id)

    if not acct["totp_secret"]:
        return jsonify({"ok": True, "enabled": False})

    try:
        code, remaining = totp_now_and_remaining(acct["totp_secret"])
        return jsonify({"ok": True, "enabled": True, "code": code, "remaining": remaining})
    except Exception:
        return jsonify({"ok": False, "enabled": True, "error": "totp_error"}), 500

@app.post("/accounts/<account_id>/delete")
@login_required
def account_delete(account_id: str):
    uid = current_user_id()
    acct = get_account_owned(uid, account_id)

    # delete messages -> account -> mailbox
    db_execute("DELETE FROM messages WHERE mailbox_id = ?", (acct["mailbox_id"],))
    db_execute("DELETE FROM accounts WHERE id = ? AND user_id = ?", (account_id, uid))
    db_execute("DELETE FROM mailboxes WHERE id = ?", (acct["mailbox_id"],))

    flash("Account deleted.", "ok")
    return redirect(url_for("dashboard"))


# ============================================================
# Inbox views (messages per mailbox)
# ============================================================

@app.get("/mailboxes/<mailbox_id>")
@login_required
def view_mailbox(mailbox_id: str):
    uid = current_user_id()
    limit = min(max(int(request.args.get("limit", "50")), 1), 200)
    offset = max(int(request.args.get("offset", "0")), 0)

    # ownership via accounts join
    ars = db_query(
        """
        SELECT a.id, a.local_part
        FROM accounts a
        WHERE a.mailbox_id = ? AND a.user_id = ?
        LIMIT 1
        """,
        (mailbox_id, uid),
    )
    if not ars.rows:
        abort(404)

    account_id = ars.rows[0][0]
    local_part = ars.rows[0][1]

    total_rs = db_query("SELECT COUNT(*) FROM messages WHERE mailbox_id = ?", (mailbox_id,))
    total = int(total_rs.rows[0][0]) if total_rs.rows else 0

    rs = db_query(
        """
        SELECT id, envelope_from, subject, received_at, raw_size
        FROM messages
        WHERE mailbox_id = ?
        ORDER BY received_at DESC
        LIMIT ? OFFSET ?
        """,
        (mailbox_id, limit, offset),
    )

    messages = []
    for r in (rs.rows or []):
        messages.append({
            "id": r[0],
            "envelope_from": r[1],
            "subject": r[2],
            "received_at": r[3],
            "raw_size": r[4],
        })

    mailbox = {
        "id": mailbox_id,
        "address": f"{local_part}@{EMAIL_DOMAIN}",
        "account_id": account_id,
    }

    return render_template(
        "mailbox.html",
        mailbox=mailbox,
        messages=messages,
        total=total,
        limit=limit,
        offset=offset,
    )

@app.get("/messages/<msg_id>")
@login_required
def view_message(msg_id: str):
    uid = current_user_id()

    rs = db_query(
        """
        SELECT msg.id, msg.mailbox_id, msg.envelope_from, msg.envelope_to, msg.subject, msg.received_at,
               msg.raw_size, msg.parsed_from, msg.parsed_to, msg.parsed_date,
               a.local_part, a.id AS account_id
        FROM messages msg
        JOIN accounts a ON a.mailbox_id = msg.mailbox_id
        WHERE msg.id = ? AND a.user_id = ?
        LIMIT 1
        """,
        (msg_id, uid),
    )
    if not rs.rows:
        abort(404)

    r = rs.rows[0]
    msg = {
        "id": r[0],
        "mailbox_id": r[1],
        "envelope_from": r[2],
        "envelope_to": r[3],
        "subject": r[4],
        "received_at": r[5],
        "raw_size": r[6],
        "parsed_from": r[7],
        "parsed_to": r[8],
        "parsed_date": r[9],
        "mailbox_address": f"{r[10]}@{EMAIL_DOMAIN}",
        "account_id": r[11],
    }

    return render_template("message.html", msg=msg)

@app.get("/messages/<msg_id>/raw.eml")
@login_required
def download_raw(msg_id: str):
    uid = current_user_id()

    rs = db_query(
        """
        SELECT a.local_part, msg.raw_eml
        FROM messages msg
        JOIN accounts a ON a.mailbox_id = msg.mailbox_id
        WHERE msg.id = ? AND a.user_id = ?
        LIMIT 1
        """,
        (msg_id, uid),
    )
    if not rs.rows:
        abort(404)

    local_part = rs.rows[0][0]
    raw_eml = to_bytes(rs.rows[0][1])

    resp = make_response(raw_eml)
    resp.headers["content-type"] = "message/rfc822"
    resp.headers["content-disposition"] = f'attachment; filename="{local_part}_{msg_id}.eml"'
    resp.headers["cache-control"] = "no-store"
    return resp

@app.post("/messages/<msg_id>/delete")
@login_required
def delete_message(msg_id: str):
    uid = current_user_id()

    rs = db_query(
        """
        SELECT msg.mailbox_id
        FROM messages msg
        JOIN accounts a ON a.mailbox_id = msg.mailbox_id
        WHERE msg.id = ? AND a.user_id = ?
        LIMIT 1
        """,
        (msg_id, uid),
    )
    if not rs.rows:
        abort(404)
    mailbox_id = rs.rows[0][0]

    db_execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    flash("Message deleted.", "ok")
    return redirect(url_for("view_mailbox", mailbox_id=mailbox_id))


# ============================================================
# Ingest endpoint (Cloudflare Worker -> POST raw EML here)
# ============================================================

@app.post("/ingest")
def ingest():
    if bearer_token(request) != INGEST_TOKEN:
        abort(401)

    mailbox_local = (request.headers.get("x-mailbox", "") or "").strip().lower()
    if not mailbox_local:
        return {"ok": True, "stored": False, "reason": "missing_mailbox"}

    envelope_from = (request.headers.get("x-envelope-from") or "").strip() or "unknown"
    envelope_to = (request.headers.get("x-envelope-to") or "").strip() or "unknown"
    subject = (request.headers.get("x-subject") or "").strip() or None
    received_at = parse_received_at(request.headers.get("x-received-at") or "")

    raw_size = int(request.headers.get("x-raw-size") or request.headers.get("x-message-raw-size") or "0")
    raw_eml = request.get_data(cache=False, as_text=False) or b""
    if not raw_size:
        raw_size = len(raw_eml)

    # Only store if mailbox exists (created by user)
    mrs = db_query("SELECT mailbox_id FROM accounts WHERE local_part = ? LIMIT 1", (mailbox_local,))
    if not mrs.rows:
        return {"ok": True, "stored": False, "reason": "mailbox_not_found"}

    mailbox_id = mrs.rows[0][0]
    parsed_from, parsed_to, parsed_date = maybe_parse_headers(raw_eml)

    msg_id = str(uuid.uuid4())
    db_execute(
        """
        INSERT INTO messages
        (id, mailbox_id, envelope_from, envelope_to, subject, received_at, raw_size, raw_eml, parsed_from, parsed_to, parsed_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            msg_id,
            mailbox_id,
            envelope_from,
            envelope_to,
            subject,
            received_at,
            raw_size,
            raw_eml,
            parsed_from,
            parsed_to,
            parsed_date,
        ),
    )

    if MAX_MESSAGES_PER_MAILBOX and MAX_MESSAGES_PER_MAILBOX > 0:
        crs = db_query("SELECT COUNT(*) FROM messages WHERE mailbox_id = ?", (mailbox_id,))
        total = int(crs.rows[0][0]) if crs.rows else 0
        if total > MAX_MESSAGES_PER_MAILBOX:
            over = total - MAX_MESSAGES_PER_MAILBOX
            old = db_query(
                "SELECT id FROM messages WHERE mailbox_id = ? ORDER BY received_at ASC LIMIT ?",
                (mailbox_id, over),
            )
            for r in (old.rows or []):
                db_execute("DELETE FROM messages WHERE id = ?", (r[0],))

    return {"ok": True, "stored": True, "id": msg_id}

@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
