import base64
import os
import re
import threading
import uuid
import asyncio
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser

import libsql_client
from flask import (
    Flask,
    abort,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

# ============================================================
# DIRECT CONFIG (NO ENV) — আপনি বলেছেন সবকিছু সরাসরি হবে
# ============================================================

# Turso DB
TURSO_DB_URL = "https://test-tolaramstudent.aws-ap-south-1.turso.io"
TURSO_AUTH_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3Njk4Njg2MTcsImlkIjoiNjdiNjgwYjItNmY4NC00ZmRjLTgxZjItMmNkYWQzMmQ2OGVlIiwicmlkIjoiYTc4MTBmNGItNDk1Yy00MDRhLTg0ZTAtOGExZTZhNmRlZjE5In0.5FaYEiGbAUt0EmND11WUfhRFIUvkC3WMoakpRT4RqCkrOIty3SwkiesX-WTDYxmT0nQIr9RHBubQaWb5xZquCg"  # <-- এখানে আপনার JWT টোকেন বসান

# Ingest Security (Worker -> Railway)
# Worker যেই token দিয়ে Authorization header পাঠায়, একই token এখানে বসান
INGEST_TOKEN = "CHANGE_THIS_TO_LONG_RANDOM_SECRET"

# Optional UI protection (login ছাড়াই)
# ফাঁকা রাখলে UI ওপেন থাকবে
UI_TOKEN = ""  # e.g. "my-ui-secret"

# Mailbox validation
MAILBOX_REGEX = r"^[a-zA-Z0-9._+-]{1,100}$"

# Optional: DB বড় হয়ে গেলে পুরোনো msg delete (0 = off)
MAX_MESSAGES = 0


# ============================================================
# Async runner (Flask sync হলেও DB calls async)
# ============================================================

class AsyncExecutor:
    def __init__(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro):
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=30)

EXEC = AsyncExecutor()

# Single client per process (Gunicorn worker)
CLIENT = EXEC.run(libsql_client.create_client(url=TURSO_DB_URL, auth_token=TURSO_AUTH_TOKEN))

# ============================================================
# DB Schema init
# ============================================================

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  mailbox TEXT NOT NULL,
  envelope_from TEXT NOT NULL,
  envelope_to TEXT NOT NULL,
  subject TEXT,
  received_at TEXT NOT NULL,
  raw_size INTEGER NOT NULL,
  raw_eml BLOB NOT NULL,
  parsed_from TEXT,
  parsed_to TEXT,
  parsed_date TEXT
);
"""

CREATE_INDEX_1 = "CREATE INDEX IF NOT EXISTS idx_messages_mailbox_received ON messages(mailbox, received_at DESC);"
CREATE_INDEX_2 = "CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at DESC);"


def db_init():
    EXEC.run(CLIENT.execute(CREATE_TABLE_SQL))
    EXEC.run(CLIENT.execute(CREATE_INDEX_1))
    EXEC.run(CLIENT.execute(CREATE_INDEX_2))


db_init()


# ============================================================
# Helpers
# ============================================================

app = Flask(__name__)
SESSION_COOKIE = "inbox_ui_ok"


def bearer_token(req) -> str:
    auth = req.headers.get("authorization", "") or ""
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return ""


def validate_mailbox(mailbox: str) -> str:
    mailbox = (mailbox or "").strip().lower()
    if not mailbox:
        abort(400, description="Missing mailbox")
    if not re.match(MAILBOX_REGEX, mailbox):
        abort(400, description="Invalid mailbox")
    return mailbox


def parse_received_at(value: str) -> str:
    # DB stores ISO8601 string (text)
    v = (value or "").strip()
    if not v:
        return datetime.now(timezone.utc).isoformat()
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


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


def db_execute(sql: str, args=None):
    if args is None:
        args = ()
    return EXEC.run(CLIENT.execute(sql, args))


def db_query(sql: str, args=None):
    if args is None:
        args = ()
    return EXEC.run(CLIENT.execute(sql, args))


def bytes_to_blob(b: bytes) -> bytes:
    # libsql_client supports passing bytes for BLOB
    return b


# ============================================================
# UI protection (optional)
# ============================================================

@app.before_request
def protect_ui():
    if not UI_TOKEN:
        return

    if request.path in ("/health", "/ingest"):
        return

    if request.cookies.get(SESSION_COOKIE) == "1":
        return

    provided = (request.args.get("ui_token") or "").strip()
    if provided and provided == UI_TOKEN:
        resp = redirect(request.path)
        resp.set_cookie(SESSION_COOKIE, "1", httponly=True, secure=True, samesite="Lax")
        return resp

    abort(401, description="UI token required. Open any page with ?ui_token=YOUR_UI_TOKEN once.")


# ============================================================
# Routes
# ============================================================

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return redirect(url_for("mailboxes"))


# -------------------------
# Ingest endpoint
# -------------------------
@app.post("/ingest")
def ingest():
    if bearer_token(request) != INGEST_TOKEN:
        abort(401)

    mailbox = validate_mailbox(request.headers.get("x-mailbox", ""))

    envelope_from = (request.headers.get("x-envelope-from") or "").strip() or "unknown"
    envelope_to = (request.headers.get("x-envelope-to") or "").strip() or "unknown"
    subject = (request.headers.get("x-subject") or "").strip() or None

    raw_size = int(request.headers.get("x-raw-size") or request.headers.get("x-message-raw-size") or "0")
    received_at = parse_received_at(request.headers.get("x-received-at") or "")

    raw_eml = request.get_data(cache=False, as_text=False) or b""
    if not raw_size:
        raw_size = len(raw_eml)

    parsed_from, parsed_to, parsed_date = maybe_parse_headers(raw_eml)

    msg_id = str(uuid.uuid4())

    db_execute(
        """
        INSERT INTO messages
        (id, mailbox, envelope_from, envelope_to, subject, received_at, raw_size, raw_eml, parsed_from, parsed_to, parsed_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            msg_id,
            mailbox,
            envelope_from,
            envelope_to,
            subject,
            received_at,
            raw_size,
            bytes_to_blob(raw_eml),
            parsed_from,
            parsed_to,
            parsed_date,
        ),
    )

    if MAX_MESSAGES and MAX_MESSAGES > 0:
        rs = db_query("SELECT COUNT(*) AS c FROM messages")
        total = rs.rows[0][0] if rs.rows else 0
        if total > MAX_MESSAGES:
            over = total - MAX_MESSAGES
            old = db_query("SELECT id FROM messages ORDER BY received_at ASC LIMIT ?", (over,))
            old_ids = [r[0] for r in old.rows] if old.rows else []
            for oid in old_ids:
                db_execute("DELETE FROM messages WHERE id = ?", (oid,))

    return {"ok": True, "id": msg_id}


# -------------------------
# UI pages
# -------------------------
@app.get("/mailboxes")
def mailboxes():
    rs = db_query(
        """
        SELECT mailbox,
               COUNT(*) AS count,
               MAX(received_at) AS last_received_at
        FROM messages
        GROUP BY mailbox
        ORDER BY last_received_at DESC
        """
    )
    mailboxes_list = [
        {"mailbox": r[0], "count": r[1], "last_received_at": r[2]}
        for r in (rs.rows or [])
    ]
    return render_template("mailboxes.html", mailboxes=mailboxes_list)


@app.get("/mailbox/<mailbox>")
def mailbox_messages(mailbox: str):
    mailbox = validate_mailbox(mailbox)

    limit = min(max(int(request.args.get("limit", "50")), 1), 200)
    offset = max(int(request.args.get("offset", "0")), 0)

    total_rs = db_query("SELECT COUNT(*) FROM messages WHERE mailbox = ?", (mailbox,))
    total = total_rs.rows[0][0] if total_rs.rows else 0

    rs = db_query(
        """
        SELECT id, mailbox, envelope_from, subject, received_at, raw_size
        FROM messages
        WHERE mailbox = ?
        ORDER BY received_at DESC
        LIMIT ? OFFSET ?
        """,
        (mailbox, limit, offset),
    )

    messages = [
        {
            "id": r[0],
            "mailbox": r[1],
            "envelope_from": r[2],
            "subject": r[3],
            "received_at": r[4],
            "raw_size": r[5],
        }
        for r in (rs.rows or [])
    ]

    return render_template(
        "messages.html",
        mailbox=mailbox,
        messages=messages,
        limit=limit,
        offset=offset,
        total=_toggle_int(total),
    )


def _toggle_int(v):
    try:
        return int(v)
    except Exception:
        return 0


@app.get("/message/<msg_id>")
def message_view(msg_id: str):
    rs = db_query(
        """
        SELECT id, mailbox, envelope_from, envelope_to, subject, received_at, raw_size,
               parsed_from, parsed_to, parsed_date
        FROM messages
        WHERE id = ?
        """,
        (msg_id,),
    )
    if not rs.rows:
        abort(404)

    r = rs.rows[0]
    msg = {
        "id": r[0],
        "mailbox": r[1],
        "envelope_from": r[2],
        "envelope_to": r[3],
        "subject": r[4],
        "received_at": r[5],
        "raw_size": r[6],
        "parsed_from": r[7],
        "parsed_to": r[8],
        "parsed_date": r[9],
    }
    return render_template("message.html", msg=msg)


@app.get("/message/<msg_id>/raw.eml")
def message_raw(msg_id: str):
    rs = db_query("SELECT mailbox, raw_eml FROM messages WHERE id = ?", (msg_id,))
    if not rs.rows:
        abort(404)

    mailbox, raw_eml = rs.rows[0][0], rs.rows[0][1]
    # raw_eml comes as bytes
    if isinstance(raw_eml, memoryview):
        raw_eml = raw_eml.tobytes()

    resp = make_response(raw_eml)
    resp.headers["content-type"] = "message/rfc822"
    resp.headers["content-disposition"] = f'attachment; filename="{mailbox}_{msg_id}.eml"'
    resp.headers["cache-control"] = "no-store"
    return resp


@app.post("/message/<msg_id>/delete")
def message_delete(msg_id: str):
    # find mailbox for redirect
    rs = db_query("SELECT mailbox FROM messages WHERE id = ?", (msg_id,))
    if not rs.rows:
        abort(404)
    mailbox = rs.rows[0][0]

    db_execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    return redirect(url_for("mailbox_messages", mailbox=mailbox))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
