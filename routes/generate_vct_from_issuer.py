# generate_vct_from_issuer.py
# -----------------------------------------------------------------------------
# Async API to bulk-import SD-JWT VC configurations from one or more OIDC4VCI
# issuers, build VCTs using *only* vct_builder_from_issuer, and upload them
# to the VCT Registry. The work happens in Celery; the HTTP call returns 202
# immediately with task ids that can be polled.
#
# Design notes
# - We DO NOT invent builder logic: we call your tested builder functions.
# - We add an import log to prevent duplicate uploads for the same issuer+config.
# - We use your LLM helper to produce a 2–3 word "name" and ~30-word "description"
#   when the builder output doesn't provide an English name.
# - Uploads are done *programmatically* (same fields as /vct/registry/api/upload).
# - A special "robot" user is the owner of generated VCT rows.
#
# Requires:
#   - Redis up (e.g., redis://localhost:6379/0)
#   - Celery worker running with your app context
#   - db_model.VCTImportLog (see db_model.py)
#   - “robot” user seeded (see db_model.py)
# -----------------------------------------------------------------------------

from __future__ import annotations

import os
import json
import hashlib
import base64
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import logging

import requests
from flask import Blueprint, current_app, jsonify, request
from celery import Celery  # <-- Option A: lightweight producer client (no circular import)

from db_model import db, User, VCTRegistry, VCTImportLog
from vct_builder_from_issuer import (
    generate_vc_type_metadata_from_issuer,
    _wk_issuer_metadata_url,
    _is_sdjwt,
)

# Reuse LLM helpers and keys from your registry module to keep behavior consistent
import routes.vct_registry as registry_mod

# -----------------------------------------------------------------------------
# Celery "producer" for the WEB process
# We do NOT import celery_app or the Celery instance to avoid any circular imports.
# We just publish messages by task name to the same broker/backend as the worker.
# -----------------------------------------------------------------------------
_CELERY_PRODUCER = Celery(
    "web-producer",
    broker=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    backend=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
)
TASK_NAME = "routes.generate_vct_from_issuer.bulk_generate_task"

# -----------------------------------------------------------------------------
# Small utilities
# -----------------------------------------------------------------------------

try:
    with open("keys.json", "r") as f:
        KEYS = json.load(f)
except Exception:
    KEYS = {}

def _auth_ok(req) -> bool:
    """Check X-API-Key header."""
    expected = KEYS["generate_vct_from_issuer_key"]
    got = (req.headers.get("X-API-Key") or "").strip()
    # If no expected key is configured, deny by default (safer).
    return bool(expected) and (got == expected)

def _sri_sha256(raw_bytes: bytes) -> str:
    """Same integrity format as /vct/registry/api/upload."""
    digest = hashlib.sha256(raw_bytes).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")

def _as_list(x) -> List[str]:
    if not x:
        return []
    return [s for s in (x if isinstance(x, list) else [x]) if s]


def _schema_hash(schema_obj) -> str:
    """
    Canonical hash of a schema dict. Uses sorted, compact JSON so
    key order/whitespace don't change the hash.
    """
    if not isinstance(schema_obj, dict):
        return ""
    s = json.dumps(schema_obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    d = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")

def _issuer_metadata(issuer_url: str) -> Dict[str, Any]:
    """Fetch issuer metadata (try .well-known; fall back to raw URL)."""
    url = _wk_issuer_metadata_url(issuer_url)
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        r = requests.get(issuer_url, timeout=10)
        r.raise_for_status()
        return r.json()

def _enumerate_sdjwt_configs(meta: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Return [(config_id, cfg_dict), ...] filtered to SD-JWT VC configs.
    Works across drafts: dict or list containers.
    """
    raw = (
        meta.get("credential_configurations_supported")
        or meta.get("credentials_supported")
        or {}
    )
    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, list):
        # Normalize list → dict keyed by id/type/vct or index
        norm = {}
        for i, cfg in enumerate(raw):
            if not isinstance(cfg, dict):
                continue
            key = str(cfg.get("id") or cfg.get("type") or cfg.get("vct") or i)
            norm[key] = cfg
        items = list(norm.items())
    else:
        items = []

    sd = []
    for cid, cfg in items:
        if isinstance(cfg, dict) and _is_sdjwt(cfg):
            sd.append((str(cid), cfg))
    return sd

def _preferred_en_name(vct_json: Dict[str, Any]) -> Optional[str]:
    """Extract an English-ish display name if present."""
    disp = vct_json.get("display") or []
    if isinstance(disp, dict):
        disp = [disp]
    # prefer en-*, then any
    preferred = []
    for d in disp:
        if not isinstance(d, dict):
            continue
        lang = str(d.get("lang") or d.get("language") or d.get("locale") or "").lower()
        label = d.get("label") or d.get("name") or d.get("title")
        if not label:
            continue
        if lang.startswith("en"):
            preferred.append(label)
    if preferred:
        return str(preferred[0]).strip()
    # fallback: any label
    for d in disp:
        label = (d or {}).get("label") or (d or {}).get("name") or (d or {}).get("title")
        if label:
            return str(label).strip()
    return None

def _extract_languages_supported_from_vct(vct_json: Dict[str, Any]) -> List[str]:
    """Copy of registry logic to record language hints on the row."""
    langs: List[str] = []
    seen = set()

    def push(val: Optional[str]):
        if not val:
            return
        s = str(val).strip().lower().replace("_", "-")
        base = s.split("-")[0] if s else ""
        if base and len(base) >= 2:
            base = base[:2]
        code = base or s[:2]
        if code and code not in seen:
            seen.add(code)
            langs.append(code)

    display = vct_json.get("display") or []
    if isinstance(display, dict):
        display = [display]
    for d in display:
        if not isinstance(d, dict):
            continue
        push((d or {}).get("language"))
        push((d or {}).get("lang"))
        push((d or {}).get("locale"))
    return langs

def _extract_keywords(vct_json: Dict[str, Any]) -> List[str]:
    """Lightweight keyword expansion; mirrors registry behavior."""
    kws: List[str] = []
    def add(x: Optional[str]):
        if not x:
            return
        for token in str(x).replace("/", " ").replace("_", " ").replace("-", " ").split():
            t = token.strip().lower()
            if len(t) >= 3 and t not in kws:
                kws.append(t)
    add(vct_json.get("vct"))
    add(vct_json.get("description"))
    for d in vct_json.get("display", []) or []:
        add((d or {}).get("name")); add((d or {}).get("description"))
    schema = vct_json.get("schema") or {}
    for k in (schema or {}).get("properties", {}).keys():
        add(k)
    for c in vct_json.get("claims", []) or []:
        for seg in (c or {}).get("path") or []:
            if seg != "[]": add(seg)
    for t in (vct_json.get("tags") or []): add(t)
    for t in (vct_json.get("keywords") or []): add(t)
    return kws

def _build_search_text(vct_json: Dict[str, Any]) -> str:
    """Concatenate text we want in the search index."""
    parts: List[str] = []
    parts.append(vct_json.get("vct") or "")
    parts.append(vct_json.get("name") or "")
    parts.append(vct_json.get("description") or "")
    disp = vct_json.get("display") or []
    if isinstance(disp, dict): disp = [disp]
    for d in disp:
        parts.append((d or {}).get("name") or (d or {}).get("label") or "")
        parts.append((d or {}).get("description") or "")
    return " ".join(p for p in parts if p).strip()

# -----------------------------------------------------------------------------
# LLM: one call per VCT to get missing name/description (OpenAI via registry_mod)
# -----------------------------------------------------------------------------

def _llm_name_desc(vct_json: Dict[str, Any], *, have_name: bool) -> Tuple[Optional[str], Optional[str]]:
    """
    Ask the LLM for a concise 2–3 word name (if needed) and a ~30-word description.
    Uses the same client/config as vct_registry. If the registry JSON helper fails,
    we fall back to a raw OpenAI call, FORCE JSON, and LOG the raw content.
    """
    client = registry_mod._ensure_llm(registry_mod.LLMConfig(), use_llm=True, phase="auto-name-desc")
    if client is None:
        logging.warning("LLM disabled/unavailable")
        return (None, None)

    system_text = (
        "You create concise product names and technical descriptions for VC Type metadata.\n"
        "Rules:\n"
        "  1) If a name is requested, make it 2 or 3 words, Title Case.\n"
        "  2) The description should be ~30 words, one sentence, plain English.\n"
        "  3) Use the JSON provided to understand the credential purpose.\n"
        "OUTPUT FORMAT:\n"
        '  Return ONLY a minified JSON object, no prose, no code fences, exactly with keys:\n'
        '  {\"name\": string|null, \"description\": string}\n'
        "If a name is not requested, set \"name\" to null."
    )
    want_name = not have_name
    payload = {"need_name": bool(want_name), "need_description": True, "vct": vct_json}

    # 1) Try your existing JSON helper (same key/model as vct_registry)
    try:
        out = registry_mod._invoke_llm_json(client, system_text, payload, phase="auto-name-desc")
        if not isinstance(out, dict):
            raise ValueError("Helper did not return a dict")
        # Optional: dump what we got at DEBUG
        logging.info("LLM JSON (helper): %r", out)
    except Exception as e:
        logging.warning("LLM auto-name-desc invocation failed via helper: %s", e)

        # 2) Fallback: call the OpenAI client directly, force JSON, and LOG RAW CONTENT
        try:
            # Works with the OpenAI python client v1.x interface used in your project
            resp = client.chat.completions.create(
                model=getattr(registry_mod, "OPENAI_MODEL", None) or "gpt-4o-mini",
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_text},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                ],
            )
            raw = (resp.choices[0].message.content or "").strip()
            logging.warning("LLM RAW content (auto-name-desc): %s", raw if raw else "<EMPTY>")  # <-- shows in console
            out = json.loads(raw) if raw else {}
        except Exception as e2:
            logging.warning("LLM raw call failed or non-JSON: %s", e2)
            return (None, None)

    # 3) Extract fields
    name = (out.get("name") if want_name else None) or out.get("short_name") or out.get("title")
    desc = out.get("description") or out.get("short_description")
    if isinstance(name, str):
        name = " ".join(name.split())[:60]
    if isinstance(desc, str):
        desc = " ".join(desc.split())
    return (name, desc)


# -----------------------------------------------------------------------------
# Programmatic upload (robot user), identical to /vct/registry/api/upload
# -----------------------------------------------------------------------------

def _ensure_robot_user() -> User:
    """Find-or-create the 'robot' user (owner of these generated VCTs)."""
    email = "thierry.thevenet@talao.io"
    u = User.query.filter_by(email=email).first()
    if u:
        return u
    u = User(email=email, name="ronot", role="user", registration="seed",
             created_at=datetime.now(timezone.utc))
    db.session.add(u)
    db.session.commit()
    return u

def _sri_sha256(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")

def _upload_vct_json(vct_json: Dict[str, Any], *, publish: bool, owner: User) -> Dict[str, Any]:
    """Insert a VCT row like the UI upload. Return minimal fields for the UI."""
    
    # 0) Schema de-dup
    sch = vct_json.get("schema")
    schema_hash = _schema_hash(sch) if sch else ""
    #if schema_hash:
    #    existing = VCTRegistry.query.filter_by(schema_hash=schema_hash).first()
    #    if existing:
    #       return {"ok": False, "error": "duplicate_schema", "existing_id": existing.id}
        
    raw = json.dumps(vct_json, ensure_ascii=False).encode("utf-8")
    integrity = _sri_sha256(raw)
    if VCTRegistry.query.filter_by(integrity=integrity).first():
        return {"ok": False, "error": "duplicate_integrity"}
    name = vct_json.get("name") or "vc_type"
    base = name; n = 2
    while VCTRegistry.query.filter_by(name=name).first() is not None:
        name = f"{base}-{n}"; n += 1
    langs = _extract_languages_supported_from_vct(vct_json)
    keywords = ",".join(_extract_keywords(vct_json))
    search_text = _build_search_text(vct_json)
    row = VCTRegistry(
        user_id=owner.id,
        vct=vct_json.get("vct"),
        vct_urn=vct_json.get("vct_urn"),
        integrity=integrity,
        name=name,
        description=vct_json.get("description") or "",
        languages_supported=json.dumps(langs),
        vct_data=json.dumps(vct_json, ensure_ascii=False),
        schema_hash=schema_hash,
        is_public=bool(publish),
        keywords=keywords,
        search_text=search_text,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.session.add(row); db.session.commit()
    return {"ok": True, "id": row.id, "integrity": integrity, "name": name,
            "is_public": row.is_public, "vct": row.vct, "vct_urn": row.vct_urn}

# -----------------------------------------------------------------------------
# Celery task helpers
# -----------------------------------------------------------------------------

def _ensure_mode_server() -> str:
    """Read the public base URL from app MODE config (used in your upload route)."""
    mode = current_app.config.get("MODE") or type("M", (), {"server": "/"})
    server = getattr(mode, "server", "/")
    if not server.endswith("/"):
        server += "/"
    return server

def _vct_publish_url(urn: str) -> str:
    return f"{_ensure_mode_server()}vct/registry/publish/{urn}"

def _hash_to_urn(s: str) -> str:
    d = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")

def _config_content_hash(cfg: Dict[str, Any]) -> str:
    s = json.dumps(cfg, sort_keys=True, ensure_ascii=False)
    d = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")

def _save_import_log(**kw) -> VCTImportLog:
    log = VCTImportLog(**kw); db.session.add(log); db.session.commit(); return log

def _mark_log(log: VCTImportLog, **updates) -> None:
    for k, v in updates.items(): setattr(log, k, v)
    log.updated_at = datetime.now(timezone.utc); db.session.commit()

def _process_one_config(issuer_url: str, cid: str, cfg: Dict[str, Any], *, publish_default: bool, llm_on: bool) -> Dict[str, Any]:
    """Build + upload one VCT for a given SD-JWT config."""
        
    content_hash = _config_content_hash(cfg)
    existing = VCTImportLog.query.filter_by(issuer_url=issuer_url, config_id=cid, config_hash=content_hash, status="success").first()
    if existing:
        return {"status": "skipped", "reason": "same_content_hash", "issuer": issuer_url, "config_id": cid}

    log = _save_import_log(
        issuer_url=issuer_url, config_id=cid, config_vct=str(cfg.get("vct") or ""),
        config_hash=content_hash, raw_snapshot=json.dumps(cfg, ensure_ascii=False),
        status="pending", error_message=None, imported_vct_urn=None,
        imported_integrity=None, imported_row_id=None,
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )

    try:
        vct = generate_vc_type_metadata_from_issuer(
            issuer=issuer_url,
            vct=str(cfg.get("vct") or cfg.get("type") or cid),
            on_remote_vct="extends",
            config_id=cid,
            vct_match=cfg.get("vct"),
        )
        name = _preferred_en_name(vct)
        desc = vct.get("description")
        if not name or not desc:
            llm_name, llm_desc = _llm_name_desc(vct, have_name=bool(name)) if llm_on else (None, None)
            if not name and llm_name: name = llm_name
            if not desc and llm_desc: desc = llm_desc
        if not name:
            name = (str(vct.get("vct") or "VC Type").split("/")[-1].replace("_", " ").replace("-", " ").title())[:60]
        if not desc:
            desc = "Verifiable Credential Type derived from issuer metadata."
        vct["name"] = name; vct["description"] = desc

        source_vct_id = str(vct.get("vct") or cid)
        vct_urn = _hash_to_urn(source_vct_id)
        vct["vct_urn"] = vct_urn
        vct["vct"] = _vct_publish_url(vct_urn)

        owner = _ensure_robot_user()
        res = _upload_vct_json(vct, publish=publish_default, owner=owner)
        if not res.get("ok"):
            _mark_log(log, status="skipped", error_message=res.get("error") or "upload_failed")
            return {"status": "skipped", "reason": res.get("error") or "upload_failed", "issuer": issuer_url, "config_id": cid}

        _mark_log(log, status="success", imported_vct_urn=vct_urn, imported_integrity=res.get("integrity"), imported_row_id=res.get("id"))
        return {"status": "created", "issuer": issuer_url, "config_id": cid, "vct_urn": vct_urn, "row_id": res.get("id")}
    except Exception as e:
        _mark_log(log, status="error", error_message=str(e))
        return {"status": "error", "issuer": issuer_url, "config_id": cid, "error": str(e)}

# -----------------------------------------------------------------------------
# Flask routes + Celery task
# -----------------------------------------------------------------------------

bp = Blueprint("vct_bulk", __name__)

def init_app(app):
    """
    Register the HTTP API endpoints on the Flask app.

    POST /vct/registry/api/generate_from_issuer
      Body: {"issuer": "..."} or {"issuers": ["...", "..."]}, optional {"publish": true|false, "llm": true|false}
    GET  /vct/registry/api/generate_from_issuer/<task_id>
      Poll task status.
    """
    app.register_blueprint(bp)

@bp.route("/vct/registry/api/generate_from_issuer", methods=["POST"])
def api_generate_from_issuer():
    # Auth via X-API-Key
    if not _auth_ok(request):
        return jsonify({"error": "unauthorized"}), 401

    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    issuers = _as_list(data.get("issuer")) + _as_list(data.get("issuers"))
    issuers = [s.strip() for s in issuers if isinstance(s, str) and s.strip()]
    if not issuers:
        return jsonify({"error": "missing_issuer"}), 400

    publish_default = bool(data.get("publish", True))  # public by default
    llm_on = bool(data.get("llm", True))

    # Enqueue one Celery task per issuer *by task name* (no Celery instance imported here)
    tasks = []
    for issuer in issuers:
        r = _CELERY_PRODUCER.send_task(TASK_NAME, args=[issuer, publish_default, llm_on])
        tasks.append({"issuer": issuer, "task_id": r.id})
    return jsonify({"ok": True, "tasks": tasks}), 202

@bp.route("/vct/registry/api/generate_from_issuer/<task_id>", methods=["GET"])
def api_generate_status(task_id: str):
    if not _auth_ok(request):
        return jsonify({"error": "unauthorized"}), 401
    r = _CELERY_PRODUCER.AsyncResult(task_id)
    out = {"task_id": task_id, "state": r.state}
    if r.info:
        out["meta"] = r.info
    return jsonify(out), 200
@bp.route("/attestation/api/propose-name-desc", methods=["POST"])
def api_propose_name_desc():
    """
    Accepts: {"issuer_url": "...", "config_id": "...", "vct_match": "..."}
    Builds a draft VCT JSON for that config and returns {"name": "...", "description": "..."}
    Uses _llm_name_desc() for proposals with safe fallbacks.
    """
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    issuer_url = (data.get("issuer_url") or "").strip()
    config_id = str(data.get("config_id") or "").strip()
    vct_match = (data.get("vct_match") or "").strip() or None
    if not issuer_url or not config_id:
        return jsonify({"error": "missing_params"}), 400

    try:
        # Fetch issuer metadata and locate the desired config
        meta = _issuer_metadata(issuer_url)
        sd = _enumerate_sdjwt_configs(meta)
        cfg = None
        for cid, c in sd:
            if str(cid) == config_id:
                cfg = c
                break
        if cfg is None:
            return jsonify({"error": "config_not_found"}), 404

        # Build a draft VCT for that configuration
        vct = generate_vc_type_metadata_from_issuer(
            issuer=issuer_url,
            vct=str(cfg.get("vct") or cfg.get("type") or config_id),
            on_remote_vct="extends",
            config_id=config_id,
            vct_match=vct_match or cfg.get("vct"),
        )

        # Prefer any embedded English display first
        name = _preferred_en_name(vct)
        desc = (vct.get("description") or "").strip() or None

        # Call LLM only for missing fields
        need_llm = (not name) or (not desc)
        if need_llm:
            llm_name, llm_desc = _llm_name_desc(vct, have_name=bool(name))
            if not name and llm_name: name = llm_name
            if not desc and llm_desc: desc = llm_desc

        # Final fallbacks
        if not name:
            base = str(vct.get("vct") or "VC Type").split("/")[-1].replace("_", " ").replace("-", " ").title()
            name = base[:60]
        if not desc:
            sch = vct.get("schema") or {}
            desc = sch.get("description") or sch.get("title") or "Verifiable Credential Type derived from issuer metadata."

        return jsonify({"name": name, "description": desc})
    except Exception as e:
        return jsonify({"error": "server_error", "detail": str(e)}), 500



# -----------------------------------------------------------------------------
# Celery task registration for the WORKER process
# We keep the late-binding decorator so the worker can register the task with
# its own Celery instance (see celery_app.register_tasks_on).
# -----------------------------------------------------------------------------

def _shared_task(*dargs, **dkw):
    def wrap(fn):
        def register(celery):
            return celery.task(*dargs, **dkw)(fn)
        fn._register_with_celery = register
        return fn
    return wrap

@_shared_task(bind=True)
def bulk_generate_task(self, issuer_url: str, publish_default: bool, llm_on: bool):
    """Celery task run per issuer."""
    summary = {"issuer": issuer_url, "created": 0, "skipped": 0, "errors": 0, "items": []}
    try:
        meta = _issuer_metadata(issuer_url)
        sd = _enumerate_sdjwt_configs(meta)
        if not sd:
            summary["message"] = "no_sdjwt_config_found"
            self.update_state(state="SUCCESS", meta=summary)
            return summary
        for cid, cfg in sd:
            res = _process_one_config(issuer_url, cid, cfg, publish_default=publish_default, llm_on=llm_on)
            summary["items"].append(res)
            if res["status"] == "created": summary["created"] += 1
            elif res["status"] == "skipped": summary["skipped"] += 1
            else: summary["errors"] += 1
            self.update_state(state="PROGRESS", meta=summary)
        self.update_state(state="SUCCESS", meta=summary)
        return summary
    except Exception as e:
        summary["errors"] += 1
        summary["message"] = f"fatal:{e}"
        self.update_state(state="SUCCESS", meta=summary)
        return summary

def register_tasks_on(celery):
    """Called by celery_app.py in the worker process to register tasks."""
    for fn in [bulk_generate_task]:
        reg = getattr(fn, "_register_with_celery", None)
        if reg:
            reg(celery)
