# app_feedback.py
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime
from flask import Flask, g, request, jsonify, abort

app = Flask(__name__)
app.config.setdefault("FEEDBACK_DB_PATH", os.environ.get("FEEDBACK_DB_PATH", "feedback.db"))

# ---------- SQLite helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["FEEDBACK_DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS feedback_reports (
          id            TEXT PRIMARY KEY,         -- e.g. fbk_20240903_abc123
          created_at    TEXT NOT NULL,            -- ISO8601
          audit_id      TEXT NOT NULL,
          tool          TEXT NOT NULL,            -- 'vc_audit' | 'qr_verifier'
          audit_version TEXT NOT NULL,
          issuer_did    TEXT,
          verifier_endpoint TEXT,
          vc_fingerprint   TEXT,                  -- 'sha256:...'
          result_summary   TEXT,                  -- JSON string
          error_type    TEXT NOT NULL,            -- enum-ish
          comment       TEXT,
          email_opt_in  INTEGER NOT NULL DEFAULT 0,
          email         TEXT,
          user_agent    TEXT,
          locale        TEXT,
          country       TEXT,
          ip_hash       TEXT,
          status        TEXT NOT NULL DEFAULT 'new',  -- 'new'|'triaged'|'in_progress'|'resolved'|'wont_fix'
          triage_notes  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback_reports(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_feedback_error_type  ON feedback_reports(error_type);
        CREATE INDEX IF NOT EXISTS idx_feedback_status      ON feedback_reports(status);
        CREATE INDEX IF NOT EXISTS idx_feedback_fingerprint ON feedback_reports(vc_fingerprint);
        """
    )
    db.commit()

with app.app_context():
    init_db()

# ---------- Utilities ----------
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

ALLOWED_ERROR_TYPES = {
    "DID_RESOLUTION",
    "SIGNATURE_VALIDATION",
    "SCHEMA_MISMATCH",
    "REVOCATION_STATUS",
    "POLICY_CHECK",
    "OTHER",
}

def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()

def ip_hash(ip: str | None) -> str | None:
    if not ip:
        return None
    return "sha256:" + sha256_hex(ip.encode("utf-8"))

def canonicalize_json(obj) -> str:
    """
    Deterministic JSON string for hashing (minified, keys sorted).
    Good enough for a fingerprint (not full RFC 8785).
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

def make_id() -> str:
    # Simple unique id: fbk_<yyyymmdd>_<8 hex>
    rnd = os.urandom(4).hex()
    return f"fbk_{datetime.utcnow().strftime('%Y%m%d')}_{rnd}"

# ---------- API ----------
@app.post("/api/feedback")
def post_feedback():
    """
    Accepts JSON like:
    {
      "audit_id": "uuid-or-id",
      "tool": "vc_audit",
      "audit_version": "1.4.2",
      "issuer_did": "did:web:example.edu",
      "verifier_endpoint": "https://verifier.example.com",
      "vc_fingerprint": "sha256:abc...",     # preferred (no raw VC)
      "result_summary": {...},               # optional
      "error_type": "DID_RESOLUTION",
      "comment": "text...",                  # optional
      "email_opt_in": true,
      "email": "alice@example.org",
      "client": {"user_agent":"...", "locale":"en", "country":"FR"}  # optional
    }
    """
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        abort(400, description="invalid_json")

    # --- basic validation ---
    required = ("audit_id", "tool", "audit_version", "error_type")
    if any(k not in data for k in required):
        abort(400, description="missing_required_fields")

    tool = data["tool"]
    if tool not in ("vc_audit", "qr_verifier"):
        abort(400, description="invalid_tool")

    error_type = data["error_type"]
    if error_type not in ALLOWED_ERROR_TYPES:
        abort(400, description="invalid_error_type")

    email_opt_in = bool(data.get("email_opt_in", False))
    email = data.get("email")
    if email_opt_in:
        if not email or not EMAIL_RE.match(email):
            abort(400, description="invalid_email")

    # Ensure we never store raw VC; prefer a caller-supplied fingerprint.
    vc_fingerprint = data.get("vc_fingerprint")
    if vc_fingerprint and not vc_fingerprint.startswith("sha256:"):
        abort(400, description="invalid_vc_fingerprint")

    result_summary = data.get("result_summary") or {}
    if isinstance(result_summary, (dict, list)):
        result_summary_json = json.dumps(result_summary, separators=(",", ":"), ensure_ascii=False)
    else:
        # Allow stringified JSON too
        try:
            json.loads(result_summary)
            result_summary_json = str(result_summary)
        except Exception:
            result_summary_json = "{}"

    # dedupe: same audit_id + fingerprint + error_type + email (if provided) within 24h
    db = get_db()
    params = {
        "audit_id": data["audit_id"],
        "vc_fingerprint": vc_fingerprint or "",
        "error_type": error_type,
        "email": (email if email_opt_in else ""),
    }
    row = db.execute(
        """
        SELECT id FROM feedback_reports
        WHERE audit_id = :audit_id
          AND IFNULL(vc_fingerprint,'') = :vc_fingerprint
          AND error_type = :error_type
          AND IFNULL(email,'') = :email
          AND datetime(created_at) > datetime('now', '-1 day')
        ORDER BY created_at DESC
        LIMIT 1
        """,
        params,
    ).fetchone()
    if row:
        return jsonify({"id": row["id"], "status": "received", "public_url": f"/feedback/{row['id']}"}), 200

    # Insert
    rid = make_id()
    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    ua = (data.get("client") or {}).get("user_agent") or request.headers.get("User-Agent", "")
    locale = (data.get("client") or {}).get("locale")
    country = (data.get("client") or {}).get("country")
    hashed_ip = ip_hash(request.headers.get("X-Forwarded-For", request.remote_addr))

    db.execute(
        """
        INSERT INTO feedback_reports
          (id, created_at, audit_id, tool, audit_version, issuer_did, verifier_endpoint,
           vc_fingerprint, result_summary, error_type, comment, email_opt_in, email,
           user_agent, locale, country, ip_hash, status)
        VALUES
          (:id, :created_at, :audit_id, :tool, :audit_version, :issuer_did, :verifier_endpoint,
           :vc_fingerprint, :result_summary, :error_type, :comment, :email_opt_in, :email,
           :user_agent, :locale, :country, :ip_hash, 'new')
        """,
        {
            "id": rid,
            "created_at": created_at,
            "audit_id": data["audit_id"],
            "tool": tool,
            "audit_version": data["audit_version"],
            "issuer_did": data.get("issuer_did"),
            "verifier_endpoint": data.get("verifier_endpoint"),
            "vc_fingerprint": vc_fingerprint,
            "result_summary": result_summary_json,
            "error_type": error_type,
            "comment": (data.get("comment") or "")[:2000],
            "email_opt_in": 1 if email_opt_in else 0,
            "email": email if email_opt_in else None,
            "user_agent": ua,
            "locale": locale,
            "country": country,
            "ip_hash": hashed_ip,
        },
    )
    db.commit()

    return jsonify({"id": rid, "status": "received", "public_url": f"/feedback/{rid}"}), 201


# (Optional) Very simple internal list to verify things work
@app.get("/internal/feedback")
def list_feedback():
    db = get_db()
    rows = db.execute(
        "SELECT created_at, id, error_type, tool, audit_version, issuer_did, email_opt_in, email FROM feedback_reports ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    items = [
        dict(row)
        for row in rows
    ]
    return jsonify(items)
