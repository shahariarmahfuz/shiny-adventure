import os
import re
import uuid
from datetime import datetime, timezone
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
)
from sqlalchemy import (
    LargeBinary,
    String,
    Text,
    Integer,
    DateTime,
    create_engine,
    select,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session


# -------------------------
# Config
# -------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "switchyard.proxy.rlwy.net").strip()
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "CHANGE_THIS_TO_LONG_RANDOM_SECRET").strip()

# Optional: protect UI with token (no login system)
UI_TOKEN = os.environ.get("UI_TOKEN", "").strip()
SESSION_COOKIE = "inbox_ui_ok"

MAILBOX_REGEX = os.environ.get("MAILBOX_REGEX", r"^[a-zA-Z0-9._+-]{1,100}$")

# Optional: cap DB size (delete oldest if too many)
MAX_MESSAGES = int(os.environ.get("MAX_MESSAGES", "0") or "0")  # 0 = disabled


if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL environment variable")
if not INGEST_TOKEN:
    raise RuntimeError("Missing INGEST_TOKEN environment variable")


# -------------------------
# DB
# -------------------------
class Base(DeclarativeBase):
    pass


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox: Mapped[str] = mapped_column(String(120), index=True, nullable=False)

    envelope_from: Mapped[str] = mapped_column(String(320), nullable=False)
    envelope_to: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)

    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    raw_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    raw_eml: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    parsed_from: Mapped[str | None] = mapped_column(Text, nullable=True)
    parsed_to: Mapped[str | None] = mapped_column(Text, nullable=True)
    parsed_date: Mapped[str | None] = mapped_column(Text, nullable=True)


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

# Auto-create table on first boot
Base.metadata.create_all(engine)


# -------------------------
# App
# -------------------------
app = Flask(__name__)


def bearer_token(req) -> str:
    auth = req.headers.get("authorization", "") or ""
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip()
    return ""


def validate_mailbox(mailbox: str) -> str:
    mailbox = (mailbox or "").strip().lower()
    if not mailbox:
        abort(400, description="Missing mailbox")
    if not re.match(MAILBOX_REGEX, mailbox):
        abort(400, description="Invalid mailbox")
    return mailbox


@app.before_request
def protect_ui():
    # Only protects UI routes. /ingest stays protected by INGEST_TOKEN
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


@app.get("/health")
def health():
    return {"status": "ok"}


# -------------------------
# Ingest endpoint (Cloudflare Worker POSTs here)
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
    received_at_hdr = (request.headers.get("x-received-at") or "").strip()

    try:
        received_at = datetime.fromisoformat(received_at_hdr.replace("Z", "+00:00"))
        if received_at.tzinfo is None:
            received_at = received_at.replace(tzinfo=timezone.utc)
    except Exception:
        received_at = datetime.now(timezone.utc)

    raw_eml = request.get_data(cache=False, as_text=False) or b""
    if not raw_size:
        raw_size = len(raw_eml)

    # Parse some friendly headers (optional)
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

    msg_id = str(uuid.uuid4())

    row = Message(
        id=msg_id,
        mailbox=mailbox,
        envelope_from=envelope_from,
        envelope_to=envelope_to,
        subject=subject,
        received_at=received_at,
        raw_size=raw_size,
        raw_eml=raw_eml,
        parsed_from=parsed_from,
        parsed_to=parsed_to,
        parsed_date=parsed_date,
    )

    with Session(engine) as s:
        s.add(row)
        s.commit()

        # Optional: cap DB size by deleting oldest rows
        if MAX_MESSAGES > 0:
            total = s.execute(select(func.count(Message.id))).scalar_one()
            if total > MAX_MESSAGES:
                over = total - MAX_MESSAGES
                old_ids = s.execute(
                    select(Message.id).order_by(Message.received_at.asc()).limit(over)
                ).scalars().all()
                if old_ids:
                    s.query(Message).filter(Message.id.in_(old_ids)).delete(synchronize_session=False)
                    s.commit()

    return {"ok": True, "id": msg_id}


# -------------------------
# UI
# -------------------------
@app.get("/")
def root():
    return redirect(url_for("mailboxes"))


@app.get("/mailboxes")
def mailboxes():
    with Session(engine) as s:
        rows = s.execute(
            select(
                Message.mailbox.label("mailbox"),
                func.count(Message.id).label("count"),
                func.max(Message.received_at).label("last_received_at"),
            )
            .group_by(Message.mailbox)
            .order_by(func.max(Message.received_at).desc())
        ).all()

    mailboxes_list = [
        {"mailbox": r.mailbox, "count": r.count, "last_received_at": r.last_received_at}
        for r in rows
    ]
    return render_template("mailboxes.html", mailboxes=mailboxes_list)


@app.get("/mailbox/<mailbox>")
def mailbox_messages(mailbox: str):
    mailbox = validate_mailbox(mailbox)
    limit = min(max(int(request.args.get("limit", "50")), 1), 200)
    offset = max(int(request.args.get("offset", "0")), 0)

    with Session(engine) as s:
        total = s.execute(
            select(func.count(Message.id)).where(Message.mailbox == mailbox)
        ).scalar_one()

        rows = s.execute(
            select(Message)
            .where(Message.mailbox == mailbox)
            .order_by(Message.received_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    return render_template(
        "messages.html",
        mailbox=mailbox,
        messages=rows,
        limit=limit,
        offset=offset,
        total=total,
    )


@app.get("/message/<msg_id>")
def message_view(msg_id: str):
    with Session(engine) as s:
        row = s.get(Message, msg_id)
    if not row:
        abort(404)
    return render_template("message.html", msg=row)


@app.get("/message/<msg_id>/raw.eml")
def message_raw(msg_id: str):
    with Session(engine) as s:
        row = s.get(Message, msg_id)
    if not row:
        abort(404)

    resp = make_response(row.raw_eml)
    resp.headers["content-type"] = "message/rfc822"
    resp.headers["content-disposition"] = f'attachment; filename="{row.mailbox}_{row.id}.eml"'
    resp.headers["cache-control"] = "no-store"
    return resp


@app.post("/message/<msg_id>/delete")
def message_delete(msg_id: str):
    with Session(engine) as s:
        row = s.get(Message, msg_id)
        if not row:
            abort(404)
        mailbox = row.mailbox
        s.delete(row)
        s.commit()
    return redirect(url_for("mailbox_messages", mailbox=mailbox))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
