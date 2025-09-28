from __future__ import annotations

import base64
import requests
import hashlib
import json
import os
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import secrets
from flask import current_app, jsonify, render_template, request, Response
from flask_login import login_required, current_user

from db_model import db, VCTRegistry, VCTRating

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
logger = logging.getLogger("vct_registry")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# ----------------------------------------------------------------------------
# Optional LLM plumbing (used only by /api/ai_search; runs even if libs are absent)
# ----------------------------------------------------------------------------
try:
    from langchain_openai import ChatOpenAI  # type: ignore
except Exception:
    ChatOpenAI = None  # type: ignore
try:
    from langchain_google_genai import ChatGoogleGenerativeAI  # type: ignore
except Exception:
    ChatGoogleGenerativeAI = None  # type: ignore
try:
    from langchain_core.messages import SystemMessage, HumanMessage  # type: ignore
except Exception:
    SystemMessage = None  # type: ignore
    HumanMessage = None  # type: ignore

try:
    with open("keys.json", "r") as f:
        KEYS = json.load(f)
except Exception:
    KEYS = {}

@dataclass
class LLMConfig:
    provider: str = os.environ.get("LLM_PROVIDER", "openai")   # "openai" | "gemini"
    model: str = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    temperature: float = 0.1

def _build_llm_client(cfg: Optional[LLMConfig]):
    if cfg is None:
        return None
    if cfg.provider == "openai":
        if ChatOpenAI is None:
            return None
        api_key = KEYS.get("openai") or os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")
        if not api_key:
            return None
        return ChatOpenAI(api_key=api_key, model=cfg.model, temperature=cfg.temperature)
    """
    if cfg.provider == "gemini":
        if ChatGoogleGenerativeAI is None:
            return None
        api_key = KEYS.get("gemini") or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return None
        return ChatGoogleGenerativeAI(google_api_key=api_key, model=cfg.model, temperature=cfg.temperature)
    return None
    """

def _ensure_llm(cfg: Optional[LLMConfig], *, use_llm: bool, phase: str):
    if not use_llm:
        return None
    try:
        return _build_llm_client(cfg or LLMConfig())
    except Exception as e:
        logger.warning("LLM unavailable for %s: %s", phase, e)
        return None

def _invoke_llm_json(client: Any, system_text: str, user_payload: Any, *, phase: str):
    if client is None:
        return None
    content = json.dumps(user_payload, ensure_ascii=False) if not isinstance(user_payload, str) else user_payload
    try:
        if SystemMessage is not None and HumanMessage is not None:
            messages = [SystemMessage(content=system_text), HumanMessage(content=content)]
            resp = client.invoke(messages)
        else:
            resp = client.invoke([["system", system_text], ["user", content]])
        text = getattr(resp, "content", resp)
        # handle possible markdown fences
        s = str(text).strip().strip("`")
        if s.startswith("json"):
            s = s[4:].strip()
        return json.loads(s)
    except Exception as e:
        logger.warning("LLM %s invocation failed: %s", phase, e)
        return None

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _sri_sha256(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def _sri_sha256_from_url(uri: str) -> str:
    """Same integrity format as /vct/registry/api/upload.
    data:image/png;base64,iVBORw0KGgoAAAANSUhEUg...
    """
    if uri.startswith("http"):
        data_image = _image_url_to_data_uri(uri)
    elif uri.startswith("data:image"):
        data_image = uri
    else:
        return
    if data_image:
        digest = hashlib.sha256(data_image.encode()).digest()
        return "sha256-" + base64.b64encode(digest).decode("ascii")
    else:
        return ""

def _extract_languages_supported_from_vct(vct_json: Dict[str, Any]) -> List[str]:
    """Collect languages from vct.display[*].{language|lang|locale} and normalize to two-letter lowercase codes."""
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


def _image_url_to_data_uri(url: str, *, timeout: float = 15.0) -> str:
    """
    Fetch an image and return a data: URI string like 'data:image/png;base64,....'
    Raises requests.HTTPError on non-2xx responses.
    """
    headers = {"User-Agent": "img-fetch/1.0"}
    try:
        r = requests.get(url, timeout=timeout, headers=headers, stream=True)
        r.raise_for_status()
    except Exception:
        return ""
    # Try to get the MIME type from the server; default to octet-stream.
    mime = r.headers.get("Content-Type", "application/octet-stream").split(";")[0].strip()
    # Read the bytes (since we set stream=True, call r.content to load them)
    data = r.content
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{b64}"

def _extract_keywords(vct_json: Dict[str, Any]) -> List[str]:
    kws: List[str] = []
    def add(x: Optional[str]):
        if not x: return
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
            # ✅ only add real strings; skip "[]"
            if isinstance(seg, str) and seg != "[]":
                add(seg)
    for t in (vct_json.get("tags") or []): add(t)
    for t in (vct_json.get("keywords") or []): add(t)
    for _l in _extract_languages_supported_from_vct(vct_json):
        if _l not in kws:
            kws.append(_l)
    return kws


def _build_search_text(vct_json: Dict[str, Any]) -> str:
    chunks: List[str] = []
    def add(x: Any):
        if x is None: return
        chunks.append(str(x))
    add(vct_json.get("vct")); add(vct_json.get("description"))
    for d in vct_json.get("display", []) or []:
        add((d or {}).get("name")); add((d or {}).get("description"))
    schema = vct_json.get("schema") or {}
    add(schema.get("title"))
    add(" ".join(list((schema or {}).get("properties", {}).keys())))
    for c in vct_json.get("claims", []) or []:
        p = (c or {}).get("path") or []
        # ✅ keep only real strings and drop "[]"
        parts = [seg for seg in p if isinstance(seg, str) and seg != "[]"]
        if parts:
            add("/".join(parts))
    # add languages
    langs = _extract_languages_supported_from_vct(vct_json)
    add(" ".join(langs))
    return (" ".join(chunks)).lower()


def _schema_hash(schema_obj) -> str:
    """Canonical hash of a schema dict (sorted, compact JSON)."""
    if not isinstance(schema_obj, dict):
        return ""
    s = json.dumps(schema_obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    d = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")

def _bump_calls(row: VCTRegistry) -> None:
    try:
        row.calls_count = int(row.calls_count or 0) + 1
        row.updated_at = datetime.now(timezone.utc)
        db.session.commit()
    except Exception:
        db.session.rollback()

def _rating_payload_public(row: VCTRegistry, *, user_id: Optional[int]) -> Dict[str, Any]:
    your = None
    try:
        if user_id:
            r = VCTRating.query.filter_by(vct_id=row.id, user_id=user_id).first()
            if r: your = r.stars
    except Exception:
        pass
    return {
        "avg_rating": float(row.avg_rating or 0.0),
        "ratings_count": int(row.ratings_count or 0),
        "calls_count": int(row.calls_count or 0),
        "your_rating": your,
    }

def _rating_payload_full(row: VCTRegistry, *, user_id: Optional[int]) -> Dict[str, Any]:
    """Compute aggregates on the fly to be safe; used by list/ai_search responses."""
    agg = db.session.query(
        db.func.count(VCTRating.id),
        db.func.coalesce(db.func.sum(VCTRating.stars), 0)
    ).filter_by(vct_id=row.id).first()
    rc = int(agg[0] or 0)
    rs = int(agg[1] or 0)
    avg = (rs / rc) if rc else 0.0
    your = None
    if user_id:
        rr = VCTRating.query.filter_by(vct_id=row.id, user_id=user_id).first()
        if rr:
            your = rr.stars
    return {
        "avg_rating": float(avg),
        "ratings_count": int(rc),
        "calls_count": int(row.calls_count or 0),
        "your_rating": your,
    }

# ----------------------------------------------------------------------------
# Route registration
# ----------------------------------------------------------------------------

def init_app(app):
    # UI pages
    # app.add_url_rule("/vct/registry", view_func=vct_registry_page, methods=["GET"])   # legacy (not used)
    app.add_url_rule("/vct/registry/manage", view_func=vct_registry_manage, methods=["GET"])   # private
    app.add_url_rule("/vct/registry/import", view_func=vct_registry_import, methods=["GET"])   # private
    app.add_url_rule("/vct/registry/browse", view_func=vct_registry_browse, methods=["GET"])   # public

    # Public resolver (stable URL)
    app.add_url_rule("/vct/registry/publish/<vct_urn>", view_func=vct_publish, methods=["GET"])
    app.add_url_rule("/.well-known/vct/<vct_urn>", view_func=vct_publish, methods=["GET"])

    # APIs (JSON)
    app.add_url_rule("/vct/registry/api/list", view_func=api_vct_list, methods=["GET"])                  # list & filtered search
    app.add_url_rule("/vct/registry/api/ai_search", view_func=api_vct_ai_search, methods=["POST"])       # LLM search
    app.add_url_rule("/vct/registry/api/upload", view_func=api_vct_upload, methods=["POST"])             # upload file
    app.add_url_rule("/vct/registry/api/delete/<int:row_id>", view_func=api_vct_delete, methods=["POST"])# delete
    app.add_url_rule("/vct/registry/api/visibility/<int:row_id>", view_func=api_vct_visibility, methods=["POST"])  # publish/unpublish
    app.add_url_rule("/vct/registry/api/download/<int:row_id>", view_func=api_vct_download, methods=["GET"])       # full doc
    app.add_url_rule("/vct/registry/api/download_schema/<int:row_id>", view_func=api_vct_download_schema, methods=["GET"])  # schema-only
    app.add_url_rule("/vct/registry/api/rate/<int:row_id>", view_func=api_vct_rate, methods=["POST"])    # stars

# ----------------------------------------------------------------------------
# UI pages
# ----------------------------------------------------------------------------


# To be removed later
def sri_sha256(b: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(b).digest()).decode("ascii")


@login_required
def vct_registry_manage():
    return render_template("manage_registry.html", user=current_user)

@login_required
def vct_registry_import():
    """
    for row in VCTRegistry.query.all():
        payload = row.vct_data if isinstance(row.vct_data, str) else row.vct_data.decode("utf-8", "replace")
        new_integrity = sri_sha256(payload.encode("utf-8"))
        if row.integrity != new_integrity:
            row.integrity = new_integrity
    db.session.commit()
    """
    return render_template("import_vct.html", user=current_user)

def vct_registry_browse():
    # public page; template uses read-only stars
    return render_template("vct_registry_browse.html", user=current_user)

# ----------------------------------------------------------------------------
# Public resolver by VCT URN (stable URL)
# ----------------------------------------------------------------------------

def vct_publish(vct_urn: str):
    """
    Resolve a public VCT by its URN-like key and return the full JSON.
    Also bumps calls_count unless ?preview=1 is provided.
    """
    mode = current_app.config["MODE"]
    preview = (request.args.get("preview") or "").strip()
    legacy_vct_url = mode.server + "vct/registry/publish/" + vct_urn

    row = (
        VCTRegistry.query
        .filter((VCTRegistry.vct == legacy_vct_url) | (VCTRegistry.vct_urn == vct_urn))
        .filter_by(is_public=True)
        .order_by(VCTRegistry.updated_at.desc())
        .first()
    )
    if row is None:
        # Cache 404 very briefly at CDN to avoid thundering herd
        resp = jsonify({"error": "VCT not found or not public"})
        resp.status_code = 404
        resp.headers["Cache-Control"] = "public, max-age=60"  # 1 minute
        return resp

    # Parse stored JSON
    try:
        data = json.loads(row.vct_data) if isinstance(row.vct_data, str) else row.vct_data
    except Exception:
        data = row.vct_data

    # Do not count preview fetches; CDN can cache preview separately if needed
    if not preview:
        _bump_calls(row)

    
    # Parse only if you need to bump calls etc., but SERVE stored bytes
    payload = row.vct_data if isinstance(row.vct_data, str) else row.vct_data.decode("utf-8", "replace")

    # Do not re-serialize; return the stored bytes exactly
    resp = Response(payload, mimetype="application/json; charset=utf-8")


    # Core headers for CDN & clients
    integrity = row.integrity or ""                  # e.g., "sha256-…"
    last_mod = row.updated_at or row.created_at    # datetime or None
    etag = integrity or (row.vct_urn or "")

    # Normal requests: long-lived, immutable cache
    if not preview:
        # JSON documents are immutable once published (new content => new integrity/URN)
        #resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"  # 1 year
        pass
    else:
        # Preview must not be cached
        resp.headers["Cache-Control"] = "private, no-store"

    # Helpful metadata
    if etag:
        resp.headers["ETag"] = etag
    if last_mod:
        # RFC1123 format
        resp.headers["Last-Modified"] = last_mod.strftime("%a, %d %b %Y %H:%M:%S GMT")

    # Existing custom headers
    resp.headers["X-VCT"] = row.vct or ""            # stable public URL
    resp.headers["X-Integrity"] = integrity

    # CORS (allow embedding/fetching across sites)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Vary"] = "Accept-Encoding, Origin"

    return resp


# ----------------------------------------------------------------------------
# API: list / search (NO DB migration; extra filters & sorting)
# ----------------------------------------------------------------------------

def api_vct_list():
    """
    GET with optional filters:
    scope: public|my|all|private
    q: text
    languages: comma-separated (matches languages_supported JSON string)
    prop: substring to match in search_text (schema properties etc.)
    claim: substring to match in search_text (claim paths etc.)
    min_rating: float
    min_calls: int
    has_schema: 1|true|yes
    sort: pop|rating|calls|newest|name  (default: newest if no q; DB order if q)
    """
    requested_scope = (request.args.get("scope") or "public").lower()
    q = (request.args.get("q") or "").strip()
    is_auth = getattr(current_user, "is_authenticated", False)
    scope = requested_scope if is_auth else "public"

    is_admin = getattr(current_user, "is_admin", False) or getattr(current_user, "role", "") == "admin"
    user_id = getattr(current_user, "id", None)

    query = VCTRegistry.query
    if scope == "public":
        query = query.filter_by(is_public=True)
    elif scope == "private":
        if is_admin:
            query = query.filter_by(is_public=False)
        else:
            query = query.filter_by(user_id=user_id, is_public=False)
    elif scope == "my":
        query = query.filter_by(user_id=user_id)
    elif scope == "all":
        if not is_admin:
            query = query.filter((VCTRegistry.is_public == True) | (VCTRegistry.user_id == user_id))

    # Text search
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            (VCTRegistry.search_text.ilike(like)) |
            (VCTRegistry.name.ilike(like)) |
            (VCTRegistry.vct.ilike(like)) |
            (VCTRegistry.keywords.ilike(like))
        )

    # Extra filters
    langs = [x.strip().lower() for x in (request.args.get("languages") or "").split(",") if x.strip()]
    prop = (request.args.get("prop") or "").strip().lower()
    claim = (request.args.get("claim") or "").strip().lower()
    min_rating = request.args.get("min_rating")
    min_calls = request.args.get("min_calls")
    has_schema = (request.args.get("has_schema") or "0").lower() in ("1", "true", "yes")

    if langs:
        lang_cond = None
        for l in langs:
            like_lang = f'%"{l}"%'
            lang_cond = (VCTRegistry.languages_supported.ilike(like_lang)) if lang_cond is None else (lang_cond | VCTRegistry.languages_supported.ilike(like_lang))
        query = query.filter(lang_cond)

    if prop:
        query = query.filter(VCTRegistry.search_text.ilike(f"%{prop}%"))

    if claim:
        query = query.filter(VCTRegistry.search_text.ilike(f"%{claim}%"))

    if min_rating:
        try:
            query = query.filter(VCTRegistry.avg_rating >= float(min_rating))
        except Exception:
            pass

    if min_calls:
        try:
            query = query.filter(VCTRegistry.calls_count >= int(min_calls))
        except Exception:
            pass

    if has_schema:
        query = query.filter((VCTRegistry.schema_hash.isnot(None)) & (VCTRegistry.schema_hash != ""))
    
    def _pop_score(r: VCTRegistry) -> float:
        rating = float(r.avg_rating or 0.0) / 5.0
        max_calls = max([rr.calls_count or 0 for rr in rows] or [1])
        calls = float(r.calls_count or 0)
        pop = (calls / max_calls) if max_calls else 0.0
        return round(0.6 * rating + 0.4 * pop, 4)
    
    # Sorting
    sort = (request.args.get("sort") or "").lower()
    if sort == "rating":
        query = query.order_by(VCTRegistry.avg_rating.desc(), VCTRegistry.ratings_count.desc())
    elif sort == "calls":
        query = query.order_by(VCTRegistry.calls_count.desc())
    elif sort == "newest":
        query = query.order_by(VCTRegistry.created_at.desc())
    elif sort == "name":
        query = query.order_by(VCTRegistry.name.asc())
    else:
        if not q:
            query = query.order_by(VCTRegistry.created_at.desc())

    rows = query.limit(500).all()
    # If popularity is requested, sort in Python using computed score (rating+calls)
    if sort == "pop":
        rows = sorted(rows, key=_pop_score, reverse=True)

    is_owner_id = getattr(current_user, "id", None) if is_auth else None
    def row_json(r: VCTRegistry):
        try:
            langs_json = json.loads(r.languages_supported or "[]")
        except Exception:
            langs_json = []
            
        try:
            doc = json.loads(r.vct_data) if isinstance(r.vct_data, str) else (r.vct_data or {})
            schema_props_count = len((doc.get("claims") or {}))
        except Exception:
            doc = {}
            schema_props_count = 0
            
        is_owner = (is_owner_id is not None and r.user_id == is_owner_id)
        can_modify = bool(is_admin or is_owner)
        #white_text_color = "#ffffff" # White
        #grey_background_color = "#D6D9DD" # Grey
        try:
            rendering_simple = json.loads(r.vct_data)["display"][0]["rendering"]["simple"]
            text_color = rendering_simple.get("text_color", "")
            background_color = rendering_simple.get("background_color", "")
            background_image_uri = rendering_simple.get("background_image", {}).get("uri", "")
            logo_uri = rendering_simple.get("logo", {}).get("uri", "")
            logo_alt_text = rendering_simple.get("logo", {}).get("alt_text", "")
            background_image_alt_text = rendering_simple.get("background_image", {}).get("alt_text", "")
        except Exception:
            logging.warning("there is no rendering simple data")
            text_color = ""
            background_color = ""
            logo_uri = ""
            background_image_uri = ""
            logo_alt_text = ""
            background_image_alt_text = ""
        
        claim_paths = []
        for claim in doc.get("claims", []):
            path = claim.get("path", [])
            try:
                claim_paths.append(".".join(path))
            except Exception:
                pass
            
        
        base = {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "languages_supported": langs_json,
            "vct": r.vct,
            "vct_urn": getattr(r, "vct_urn", None),
            "integrity": r.integrity,
            "is_public": r.is_public,
            "created_at": (r.created_at.isoformat() if r.created_at else None),
            "updated_at": (r.updated_at.isoformat() if r.updated_at else None),
            "is_owner": is_owner,
            "can_modify": can_modify,
            "schema_props_count": schema_props_count,
            "text_color": text_color,
            "background_color": background_color,
            "logo_uri": logo_uri,
            "background_image_uri": background_image_uri,
            "logo_alt_text": logo_alt_text,
            "background_image_alt_text": background_image_alt_text,
            "claim_paths": claim_paths,
            "claims": claim_paths,
            "claims_count": len(claim_paths)
            
        }
        base.update(_rating_payload_full(r, user_id=(current_user.id if is_auth else None)))
        base.update({"score": _pop_score(r)})  # popularity-only score
        return base

    return jsonify([row_json(r) for r in rows])

# ----------------------------------------------------------------------------
# API: upload / delete / visibility / download / download_schema / rate
# ----------------------------------------------------------------------------

@login_required
def api_vct_upload():
    """Accept a multipart/form-data with 'file' JSON. Optional: 'publish' (true/false)."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    raw = f.read()
    if not raw:
        return jsonify({"error": "Empty file"}), 400

    publish_flag = (request.form.get("publish") or "false").lower() in ("1", "true", "yes", "on")

    # load file
    try:
        vct_json = json.loads(raw)
    except Exception as e:
        return jsonify({"error": f"Invalid JSON: {e}"}), 400

    #vct_urn_orig = (vct_json.get("vct") or "").strip()
    #if not vct_urn_orig:
    #    return jsonify({"error": "Missing 'vct' in the JSON document"}), 400
    vct_urn = secrets.token_hex(32)

    # build vct_url for publishing and update vct in the registry (stable public URL)
    mode = current_app.config["MODE"]
    vct_url = mode.server + "vct/registry/publish/" + vct_urn
    vct_json["vct"] = vct_url
    
    #recompute uri#integrity for display background_image and logo
    display_list = vct_json.get("display")
    for display in display_list:
        if uri := display.get("rendering", {}).get("simple", {}).get("background_image", {}).get("uri"):
            uri_integrity = _sri_sha256_from_url(uri)
            if uri_integrity:
                display["rendering"]["simple"]["background_image"]["uri#integrity"] = uri_integrity
            else:
                logging.warning("This url is not available: %s", uri)
        if uri := display.get("rendering", {}).get("simple", {}).get("logo", {}).get("uri"):
            uri_integrity = _sri_sha256_from_url(uri)
            if uri_integrity:
                display["rendering"]["simple"]["background_image"]["uri#integrity"] = uri_integrity
            else:
                logging.warning("This url is not available: %s", uri)
    
    # Compute vct#integrity on the FINAL bytes
    payload = json.dumps(vct_json, ensure_ascii=False, separators=(",", ":"))
    payload_bytes = payload.encode("utf-8")
    integrity = _sri_sha256(payload_bytes)
    #logging.info("VCT uploaded -> %s", json.dumps(vct_json, indent=2))
            
    name = vct_json.get("name")
    description = vct_json.get("description")
    langs = _extract_languages_supported_from_vct(vct_json)

    if VCTRegistry.query.filter_by(integrity=integrity).first():
        return jsonify({"error": "An entry with the same integrity already exists."}), 409

    #removed with draft 12
    #schema_hash = _schema_hash(vct_json.get("schema")) if vct_json.get("schema") else ""
    schema_hash = ""
    
    base_name = name
    suffix = 2
    while VCTRegistry.query.filter_by(name=name).first() is not None:
        name = f"{base_name}-{suffix}"
        suffix += 1

    row = VCTRegistry(
        user_id=current_user.id,
        vct=vct_url,
        vct_urn=vct_urn,
        integrity=integrity,
        name=name,
        description=description,
        languages_supported=json.dumps(langs, ensure_ascii=False),
        vct_data=json.dumps(vct_json, ensure_ascii=False),
        schema_hash=schema_hash,
        is_public=publish_flag,
        keywords=",".join(_extract_keywords(vct_json)),
        search_text=_build_search_text(vct_json),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.session.add(row)
    db.session.commit()
    return jsonify({
        "ok": True,
        "id": row.id,
        "integrity": integrity,
        "vct": row.vct,
        "vct_urn": row.vct_urn,
        "name": name,
        "is_public": row.is_public
    })

@login_required
def api_vct_delete(row_id: int):
    is_admin = getattr(current_user, "is_admin", False) or getattr(current_user, "role", "") == "admin"
    if is_admin:
        row = VCTRegistry.query.filter_by(id=row_id).first()
    else:
        row = VCTRegistry.query.filter_by(id=row_id, user_id=current_user.id).first()
    if not row:
        return jsonify({"error": "Not found or not permitted"}), 404
    db.session.delete(row)
    db.session.commit()
    return jsonify({"ok": True})

@login_required
def api_vct_visibility(row_id: int):
    is_admin = getattr(current_user, "is_admin", False) or getattr(current_user, "role", "") == "admin"
    if is_admin:
        row = VCTRegistry.query.filter_by(id=row_id).first()
    else:
        row = VCTRegistry.query.filter_by(id=row_id, user_id=current_user.id).first()
    if not row:
        return jsonify({"error": "Not found or not permitted"}), 404
    try:
        data = request.get_json(force=True)
    except Exception:
        data = {}
    row.is_public = bool(data.get("is_public"))
    row.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"ok": True, "is_public": row.is_public})

def api_vct_download(row_id: int):
    row = VCTRegistry.query.filter_by(id=row_id).first()
    if not row:
        return jsonify({"error": "Not found"}), 404
    if not row.is_public and (getattr(current_user, "id", None) != row.user_id):
        return jsonify({"error": "Forbidden"}), 403

    try:
        payload = row.vct_data if isinstance(row.vct_data, str) else row.vct_data.decode("utf-8")
    except Exception:
        payload = row.vct_data

    _bump_calls(row)

    resp = Response(payload, mimetype="application/json")
    resp.headers["Content-Disposition"] = f"attachment; filename={row.name or 'vct'}.json"
    resp.headers["X-VCT"] = row.vct or ""
    resp.headers["X-Integrity"] = row.integrity
    return resp

def api_vct_download_schema(row_id: int):
    row = VCTRegistry.query.filter_by(id=row_id).first()
    if not row:
        return jsonify({"error": "Not found"}), 404
    if not row.is_public and (getattr(current_user, "id", None) != row.user_id):
        return jsonify({"error": "Forbidden"}), 403

    try:
        doc = json.loads(row.vct_data) if isinstance(row.vct_data, str) else row.vct_data
    except Exception as e:
        return jsonify({"error": f"Corrupt JSON: {e}"}), 500

    schema = (doc or {}).get("schema") or {}
    if isinstance(schema, dict):
        schema = dict(schema)
    payload = json.dumps(schema, ensure_ascii=False, indent=2)

    _bump_calls(row)

    resp = Response(payload, mimetype="application/json")
    resp.headers["Content-Disposition"] = f"attachment; filename={row.name or 'schema'}.schema.json"
    resp.headers["X-VCT"] = row.vct or ""
    resp.headers["X-Integrity"] = row.integrity
    return resp

@login_required
def api_vct_rate(row_id: int):
    """
    Authenticated endpoint. The public browse page renders read-only stars and should NOT call this.
    """
    row = VCTRegistry.query.filter_by(id=row_id).first()
    if not row:
        return jsonify({"error": "Not found"}), 404
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
    stars = int(data.get("stars") or 0)
    if stars < 1 or stars > 5:
        return jsonify({"error": "Stars must be between 1 and 5"}), 400

    rating = VCTRating.query.filter_by(vct_id=row.id, user_id=current_user.id).first()
    if rating:
        rating.stars = stars
        rating.updated_at = datetime.now(timezone.utc)
    else:
        rating = VCTRating(vct_id=row.id, user_id=current_user.id, stars=stars, created_at=datetime.now(timezone.utc))
        db.session.add(rating)

    db.session.flush()
    agg = db.session.query(
        db.func.count(VCTRating.id),
        db.func.coalesce(db.func.sum(VCTRating.stars), 0)
    ).filter_by(vct_id=row.id).first()
    row.ratings_count = int(agg[0] or 0)
    row.ratings_sum = int(agg[1] or 0)
    row.avg_rating = (row.ratings_sum / row.ratings_count) if row.ratings_count else 0.0
    row.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    payload = _rating_payload_public(row, user_id=current_user.id)
    return jsonify({"ok": True, **payload})

# ----------------------------------------------------------------------------
# API: AI search (accepts same filters as /api/list; no DB migration)
# ----------------------------------------------------------------------------

def api_vct_ai_search():
    """
    JSON body accepts:
      q, scope, top_k, languages, prop, claim, min_rating, min_calls, has_schema, sort
    """
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        body = {}
    q = (body.get("q") or "").strip()
    requested_scope = (body.get("scope") or "public").lower()
    is_auth = getattr(current_user, "is_authenticated", False)
    scope = requested_scope if is_auth else "public"
    top_k = max(1, min(int(body.get("top_k") or 10), 50))

    is_admin = getattr(current_user, "is_admin", False) or getattr(current_user, "role", "") == "admin"
    user_id = getattr(current_user, "id", None)

    # Filters mirrored from api_vct_list
    langs = [x.strip().lower() for x in str(body.get("languages") or "").split(",") if x.strip()]
    prop = (body.get("prop") or "").strip().lower()
    claim = (body.get("claim") or "").strip().lower()
    min_rating = body.get("min_rating")
    min_calls = body.get("min_calls")
    has_schema = str(body.get("has_schema") or "0").lower() in ("1", "true", "yes")
    sort = (body.get("sort") or "").lower()

    query = VCTRegistry.query
    if scope == "public":
        query = query.filter_by(is_public=True)
    elif scope == "my":
        query = query.filter_by(user_id=user_id)
    elif scope == "private":
        if is_admin:
            query = query.filter_by(is_public=False)
        else:
            query = query.filter_by(user_id=user_id, is_public=False)
    elif scope == "all":
        if not is_admin:
            query = query.filter((VCTRegistry.is_public == True) | (VCTRegistry.user_id == user_id))
    else:
        query = query.filter((VCTRegistry.is_public == True) | (VCTRegistry.user_id == user_id))

    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            (VCTRegistry.search_text.ilike(like)) |
            (VCTRegistry.name.ilike(like)) |
            (VCTRegistry.vct.ilike(like)) |
            (VCTRegistry.keywords.ilike(like))
        )

    # Apply same filters as /api/list
    if langs:
        lang_cond = None
        for l in langs:
            like_lang = f'%"{l}"%'
            cond = VCTRegistry.languages_supported.ilike(like_lang)
            lang_cond = cond if lang_cond is None else (lang_cond | cond)
        query = query.filter(lang_cond)

    if prop:
        query = query.filter(VCTRegistry.search_text.ilike(f"%{prop}%"))

    if claim:
        query = query.filter(VCTRegistry.search_text.ilike(f"%{claim}%"))

    if min_rating:
        try:
            query = query.filter(VCTRegistry.avg_rating >= float(min_rating))
        except Exception:
            pass

    if min_calls:
        try:
            query = query.filter(VCTRegistry.calls_count >= int(min_calls))
        except Exception:
            pass

    if has_schema:
        query = query.filter((VCTRegistry.schema_hash.isnot(None)) & (VCTRegistry.schema_hash != ""))

    # Pre-sort candidate set (final order may be changed by LLM)
    if sort == "rating":
        query = query.order_by(VCTRegistry.avg_rating.desc(), VCTRegistry.ratings_count.desc())
    elif sort == "calls":
        query = query.order_by(VCTRegistry.calls_count.desc())
    elif sort == "newest":
        query = query.order_by(VCTRegistry.created_at.desc())
    elif sort == "name":
        query = query.order_by(VCTRegistry.name.asc())
    else:
        query = query.order_by(VCTRegistry.updated_at.desc())

    candidates: List[VCTRegistry] = query.limit(150).all()

    # Build small sidecar for the LLM
    items = []
    id2row: Dict[int, VCTRegistry] = {}
    for r in candidates:
        id2row[r.id] = r
        try:
            doc = json.loads(r.vct_data) if isinstance(r.vct_data, str) else (r.vct_data or {})
        except Exception:
            doc = {}
        schema_props = list(((doc.get("schema") or {}).get("properties") or {}).keys())[:30]
        claim_paths = []
        for c in (doc.get("claims") or [])[:30]:
            p = (c or {}).get("path") or []
            claim_paths.append("/".join([seg for seg in p if seg != "[]"]))
        items.append({
            "id": r.id,
            "name": r.name,
            "vct": r.vct,
            "keywords": (r.keywords or "").split(",") if r.keywords else [],
            "schema_props": schema_props,
            "claim_paths": claim_paths,
            "description": (doc.get("description") or "")[:300],
            "popularity": {"avg_rating": float(r.avg_rating or 0.0), "ratings_count": int(r.ratings_count or 0), "calls_count": int(r.calls_count or 0)},
        })

    client = _ensure_llm(LLMConfig(), use_llm=True, phase="ai_search")
    ranked_ids = None
    reasons: Dict[int, Dict[str, Any]] = {}
    if client and items and q:
        system = "Return ONLY JSON: [{id, score, reason}] sorted by best match first. score in [0,1], reason <= 200 chars."
        user = {
            "query": q,
            "instruction": (
                "Given the user query, pick the most relevant VC Types. "
                "Relevance: field/claim match, schema property names, described purpose, and popularity hints. "
                "Prefer exact matches to claim names (e.g., given_name, birthdate) and close synonyms."
            ),
            "items": items,
            "top_k": top_k,
        }
        out = _invoke_llm_json(client, system, user, phase="ai_search")
        if isinstance(out, list):
            ranked_ids = [int(x.get("id")) for x in out if isinstance(x, dict) and x.get("id") in id2row]
            for x in out:
                try:
                    rid = int(x.get("id"))
                    reasons[rid] = {"score": float(x.get("score") or 0.0), "reason": x.get("reason")}
                except Exception:
                    pass

    def _kw_pop_score(r: VCTRegistry) -> float:
        if not q:
            rating = float(r.avg_rating or 0.0) / 5.0
            calls = float(r.calls_count or 0)
            max_calls = max([c.calls_count for c in candidates] or [1])
            pop = (calls / max_calls) if max_calls else 0.0
            return 0.5 * rating + 0.5 * pop
        txt = (r.search_text or "") + " " + (r.name or "") + " " + (r.vct or "")
        tokens = [t for t in q.lower().split() if t]
        base = (sum(1 for t in tokens if t in txt) / len(tokens)) if tokens else 0.0
        rating = float(r.avg_rating or 0.0) / 5.0
        calls = float(r.calls_count or 0)
        max_calls = max([c.calls_count for c in candidates] or [1])
        pop = (calls / max_calls) if max_calls else 0.0
        return 0.6 * base + 0.25 * rating + 0.15 * pop

    if ranked_ids is None:
        # Fallback: simple keyword+popularity
        scored = sorted(candidates, key=lambda r: _kw_pop_score(r), reverse=True)[:top_k]
        ranked = scored
    else:
        seen = set()
        ranked = []
        for rid in ranked_ids:
            if rid in id2row and rid not in seen:
                ranked.append(id2row[rid])
                seen.add(rid)
            if len(ranked) >= top_k:
                break
        # pad with remaining best-scored
        if len(ranked) < top_k:
            rest = [r for r in candidates if r.id not in seen]
            rest_sorted = sorted(rest, key=lambda r: _kw_pop_score(r), reverse=True)
            ranked.extend(rest_sorted[: (top_k - len(ranked))])

    is_admin = getattr(current_user, "is_admin", False) or getattr(current_user, "role", "") == "admin"
    is_auth = getattr(current_user, "is_authenticated", False)
    user_id = getattr(current_user, "id", None)

    def row_json(r: VCTRegistry):
        try:
            langs = json.loads(r.languages_supported or "[]")
        except Exception:
            langs = []
            
        try:
            doc = json.loads(r.vct_data) if isinstance(r.vct_data, str) else (r.vct_data or {})
            schema_props_count = len(((doc.get("schema") or {}).get("properties") or {}))
        except Exception:
            doc = {}
            schema_props_count = 0
            
        is_owner = (user_id is not None and r.user_id == user_id)
        can_modify = bool(is_admin or is_owner)
        base = {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "languages_supported": langs,
            "vct": r.vct,
            "vct_urn": getattr(r, "vct_urn", None),
            "integrity": r.integrity,
            "is_public": r.is_public,
            "created_at": (r.created_at.isoformat() if r.created_at else None),
            "updated_at": (r.updated_at.isoformat() if r.updated_at else None),
            "is_owner": is_owner,
            "can_modify": can_modify,
            "schema_props_count": schema_props_count
        }
        base.update(_rating_payload_full(r, user_id=(current_user.id if is_auth else None)))
        if r.id in reasons:
            base.update({"score": reasons[r.id].get("score"), "reason": reasons[r.id].get("reason")})
        else:
            base.update({"score": round(_kw_pop_score(r), 4)})
        return base

    return jsonify([row_json(r) for r in ranked])
