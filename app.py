import os
import re
import threading
import uuid
import asyncio
import secrets
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from functools import wraps

import libsql_client
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
)
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# DIRECT CONFIG (NO ENV) — সবকিছু সরাসরি
# ============================================================

# Turso DB
TURSO_DB_URL = "https://test-tolaramstudent.aws-ap-south-1.turso.io"
TURSO_AUTH_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3Njk4Njg2MTcsImlkIjoiNjdiNjgwYjItNmY4NC00ZmRjLTgxZjItMmNkYWQzMmQ2OGVlIiwicmlkIjoiYTc4MTBmNGItNDk1Yy00MDRhLTg0ZTAtOGExZTZhNmRlZjE5In0.5FaYEiGbAUt0EmND11WUfhRFIUvkC3WMoakpRT4RqCkrOIty3SwkiesX-WTDYxmT0nQIr9RHBubQaWb5xZquCg"  # <-- আপনার Turso JWT token বসান

# Worker -> Backend shared secret
INGEST_TOKEN = "CHANGE_THIS_TO_LONG_RANDOM_SECRET"

# Your email domain (UI তে দেখানোর জন্য)
EMAIL_DOMAIN = "xneko.xyz"  # <-- আপনার Cloudflare domain দিন (example: example.com)

# Mailbox local-part format
MAILBOX_REGEX = r"^[a-zA-Z0-9._+-]{1,64}$"

# Random mailbox settings
MAILBOX_RANDOM_LEN = 10  # 10 chars random local part

# Flask session secret (direct, no env)
# production এ এটা change করা ভাল; কিন্তু আপনি বলেছেন direct থাকবে
FLASK_SECRET_KEY = "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_VALUE"

# Optional: if you want to disable signup later
ALLOW_SIGNUP = True

# Optional: cap messages for a mailbox (0=off)
MAX_MESSAGES_PER_MAILBOX = 0


# ============================================================
# Async runner (Turso libsql-client needs running event loop)
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
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_received ON messages(mailbox_id, received_at DESC);
"""

async def _db_init():
    # libsql-client supports executing multiple statements one by one; safest:
    for stmt in [s.strip() for s in SCHEMA_SQL.split(";")]:
        if stmt:
            await CLIENT.execute(stmt + ";")

EXEC.run(_db_init())


# ============================================================
# App
# ============================================================

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

SESSION_COOKIE = "session"


# ============================================================
# Helpers
# ============================================================

def bearer_token(req) -> str:
    auth = req.headers.get("authorization", "") or ""
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return ""

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def validate_mailbox_local(local_part: str) -> str:
    local = (local_part or "").strip().lower()
    if not local:
        abort(400, description="Missing mailbox")
    if not re.match(MAILBOX_REGEX, local):
        abort(400, description="Invalid mailbox")
    return local

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

def current_user_id() -> str | None:
    return session.get("uid")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def normalize_user_email(email: str) -> str:
    e = (email or "").strip().lower()
    if not e or "@" not in e or len(e) > 200:
        abort(400, description="Invalid email")
    return e


# ============================================================
# Auth
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
# UI
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
        SELECT m.id, m.local_part, m.created_at,
               (SELECT COUNT(*) FROM messages msg WHERE msg.mailbox_id = m.id) AS msg_count,
               (SELECT MAX(received_at) FROM messages msg WHERE msg.mailbox_id = m.id) AS last_received
        FROM mailboxes m
        WHERE m.user_id = ?
        ORDER BY m.created_at DESC
        """,
        (uid,),
    )

    mailboxes = []
    for r in (rs.rows or []):
        mailboxes.append({
            "id": r[0],
            "local_part": r[1],
            "address": f"{r[1]}@{EMAIL_DOMAIN}",
            "created_at": r[2],
            "msg_count": int(r[3] or 0),
            "last_received": r[4],
        })

    return render_template("dashboard.html", mailboxes=mailboxes, user_email=session.get("email"))

def _random_local_part(n: int) -> str:
    # URL-safe base32-ish (letters+digits), then trim
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))

@app.post("/mailboxes/create")
@login_required
def create_mailbox():
    uid = current_user_id()

    # generate unique random local part
    for _ in range(20):
        local = _random_local_part(MAILBOX_RANDOM_LEN)
        try:
            db_execute(
                "INSERT INTO mailboxes (id, user_id, local_part, created_at) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), uid, local, now_iso()),
            )
            flash(f"Created: {local}@{EMAIL_DOMAIN}", "ok")
            return redirect(url_for("dashboard"))
        except Exception:
            continue

    flash("Failed to create mailbox. Try again.", "error")
    return redirect(url_for("dashboard"))

@app.post("/mailboxes/<mailbox_id>/delete")
@login_required
def delete_mailbox(mailbox_id: str):
    uid = current_user_id()

    # Ensure ownership
    rs = db_query("SELECT id FROM mailboxes WHERE id = ? AND user_id = ? LIMIT 1", (mailbox_id, uid))
    if not rs.rows:
        abort(404)

    # delete messages first
    db_execute("DELETE FROM messages WHERE mailbox_id = ?", (mailbox_id,))
    db_execute("DELETE FROM mailboxes WHERE id = ?", (mailbox_id,))
    flash("Mailbox deleted.", "ok")
    return redirect(url_for("dashboard"))

@app.get("/mailboxes/<mailbox_id>")
@login_required
def view_mailbox(mailbox_id: str):
    uid = current_user_id()
    limit = min(max(int(request.args.get("limit", "50")), 1), 200)
    offset = max(int(request.args.get("offset", "0")), 0)

    mrs = db_query(
        "SELECT id, local_part, created_at FROM mailboxes WHERE id = ? AND user_id = ? LIMIT 1",
        (mailbox_id, uid),
    )
    if not mrs.rows:
        abort(404)

    mailbox = {
        "id": mrs.rows[0][0],
        "local_part": mrs.rows[0][1],
        "address": f"{mrs.rows[0][1]}@{EMAIL_DOMAIN}",
        "created_at": mrs.rows[0][2],
    }

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
               m.local_part
        FROM messages msg
        JOIN mailboxes m ON m.id = msg.mailbox_id
        WHERE msg.id = ? AND m.user_id = ?
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
    }

    return render_template("message.html", msg=msg)

@app.get("/messages/<msg_id>/raw.eml")
@login_required
def download_raw(msg_id: str):
    uid = current_user_id()

    rs = db_query(
        """
        SELECT m.local_part, msg.raw_eml
        FROM messages msg
        JOIN mailboxes m ON m.id = msg.mailbox_id
        WHERE msg.id = ? AND m.user_id = ?
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
        JOIN mailboxes m ON m.id = msg.mailbox_id
        WHERE msg.id = ? AND m.user_id = ?
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
# Ingest (Cloudflare Worker -> POST raw EML here)
# ============================================================

@app.post("/ingest")
def ingest():
    # Protect endpoint
    if bearer_token(request) != INGEST_TOKEN:
        abort(401)

    # Worker sends local-part in X-Mailbox
    mailbox_local = validate_mailbox_local(request.headers.get("x-mailbox", ""))
    envelope_from = (request.headers.get("x-envelope-from") or "").strip() or "unknown"
    envelope_to = (request.headers.get("x-envelope-to") or "").strip() or "unknown"
    subject = (request.headers.get("x-subject") or "").strip() or None
    received_at = parse_received_at(request.headers.get("x-received-at") or "")

    raw_size = int(request.headers.get("x-raw-size") or request.headers.get("x-message-raw-size") or "0")
    raw_eml = request.get_data(cache=False, as_text=False) or b""
    if not raw_size:
        raw_size = len(raw_eml)

    # Only store if mailbox exists
    mrs = db_query("SELECT id FROM mailboxes WHERE local_part = ? LIMIT 1", (mailbox_local,))
    if not mrs.rows:
        # mailbox not created by any user => ignore (you can change to 404/400 if you want)
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

    # Optional cap per mailbox
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
