from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import current_app, jsonify, render_template, request, Response
from flask_login import login_required, current_user

from db_model import db, VCTRegistry, VCTRating

# ----------------------------------------------------------------------------
# LLM management (aligned with vct_builder.py style)
# ----------------------------------------------------------------------------
import logging
logger = logging.getLogger("vct_registry")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

try:
    from langchain_openai import ChatOpenAI  # type: ignore
except Exception:
    ChatOpenAI = None
try:
    from langchain_google_genai import ChatGoogleGenerativeAI  # type: ignore
except Exception:
    ChatGoogleGenerativeAI = None
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
    provider: str = os.environ.get("LLM_PROVIDER", "openai")
    model: str = os.environ.get("LLM_MODEL", "gpt-5-mini")
    temperature: float = 0.0

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
        return json.loads(text)
    except Exception as e:
        logger.warning("LLM %s invocation failed: %s", phase, e)
        return None



# ----------------------------------------------------------------------------
# Page + API wiring
# ----------------------------------------------------------------------------

def init_app(app):
    # Page
    app.add_url_rule("/vct/registry", view_func=vct_registry_page, methods=["GET"])  # UI
    app.add_url_rule("/vct/registry/browse", view_func=vct_registry_browse, methods=["GET"])  # UI

    # APIs (JSON)
    app.add_url_rule("/vct/registry/api/list", view_func=api_vct_list, methods=["GET"])  # list & search
    app.add_url_rule("/vct/registry/api/upload", view_func=api_vct_upload, methods=["POST"])  # upload
    app.add_url_rule("/vct/registry/api/delete/<int:row_id>", view_func=api_vct_delete, methods=["POST"])  # delete
    app.add_url_rule("/vct/registry/api/visibility/<int:row_id>", view_func=api_vct_visibility, methods=["POST"])  # publish/unpublish
    app.add_url_rule("/vct/registry/api/download/<int:row_id>", view_func=api_vct_download, methods=["GET"])  # full VCT
    app.add_url_rule("/vct/registry/api/download_schema/<int:row_id>", view_func=api_vct_download_schema, methods=["GET"])  # schema-only
    app.add_url_rule("/vct/registry/api/rate/<int:row_id>", view_func=api_vct_rate, methods=["POST"])  # stars
    app.add_url_rule("/vct/registry/api/ai_search", view_func=api_vct_ai_search, methods=["POST"])  # LLM search

    # Public resolver (stable URL)
    app.add_url_rule("/vct/registry/publish/<vct_urn>", view_func=vct_publish, methods=["GET"])  # public fetch by URN


# ----------------------------------------------------------------------------
# UI page
# ----------------------------------------------------------------------------

@login_required
def vct_registry_page():
    return render_template("vct_registry.html", user=current_user)  # keep user available to the template  :contentReference[oaicite:2]{index=2}


def vct_registry_browse():
    return render_template("vct_registry_browse.html", user=current_user)  # keep user available to the template  :contentReference[oaicite:2]{index=2}

# ----------------------------------------------------------------------------
# Public resolver (by VCT URN)
# ----------------------------------------------------------------------------

def vct_publish(vct_urn):
    mode = current_app.config["MODE"]
    preview = request.args.get("preview")
    legacy_vct_url = mode.server + "vct/registry/publish/" + vct_urn

    row = (
        VCTRegistry.query
        .filter((VCTRegistry.vct == legacy_vct_url) | (VCTRegistry.vct_urn == vct_urn))
        .filter_by(is_public=True)
        .order_by(VCTRegistry.updated_at.desc())
        .first()
    )
    if row is None:
        return jsonify({"error": "VCT not found or not public"}), 404

    try:
        data = json.loads(row.vct_data) if isinstance(row.vct_data, str) else row.vct_data
    except Exception:
        data = row.vct_data

    if not preview:
        _bump_calls(row)

    resp = jsonify(data)
    resp.headers["X-VCT"] = row.vct or ""
    resp.headers["X-Integrity"] = row.integrity
    return resp


# ----- Helpers ------------------------------------------------------------

def _sri_sha256(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")

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
    for k in (schema or {}).get("properties", {}) .keys():
        add(k)
    for c in vct_json.get("claims", []) or []:
        for seg in (c or {}).get("path") or []:
            if seg != "[]": add(seg)
    for t in (vct_json.get("tags") or []): add(t)
    for t in (vct_json.get("keywords") or []): add(t)
    
    # languages from display
    for _l in _extract_languages_supported_from_vct(vct_json):
        if _l not in kws:
            kws.append(_l)
    return kws

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
        add("/".join([seg for seg in ((c or {}).get("path") or []) if seg != "[]"]))
    
    # add languages
    langs = _extract_languages_supported_from_vct(vct_json)
    add(" ".join(langs))
    return (" ".join(chunks)).lower()

def _bump_calls(row: VCTRegistry) -> None:
    try:
        row.calls_count = int(row.calls_count or 0) + 1
        row.updated_at = datetime.now(timezone.utc)
        db.session.commit()
    except Exception:
        db.session.rollback()

def _rating_payload(row: VCTRegistry, *, user_id: Optional[int]) -> Dict[str, Any]:
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

# ----- APIs ---------------------------------------------------------------
def api_vct_list():
    # optional filters via query params, matching ai_search semantics
    requested_scope = (request.args.get("scope") or "public").lower()  # public | my | all
    q = (request.args.get("q") or "").strip()
    is_auth = getattr(current_user, "is_authenticated", False)
    scope = requested_scope if is_auth else "public"


    # 1) define the base query
    query = VCTRegistry.query
    if scope == "public":
        query = query.filter_by(is_public=True)
    elif scope == "my":
        query = query.filter_by(user_id=current_user.id)
    else:
        # "all" = public OR mine
        query = query.filter((VCTRegistry.is_public == True) | (VCTRegistry.user_id == current_user.id))

    # 2) optional text search
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            (VCTRegistry.search_text.ilike(like)) |
            (VCTRegistry.name.ilike(like)) |
            (VCTRegistry.vct.ilike(like)) |
            (VCTRegistry.keywords.ilike(like))
        )

    # 3) fetch rows
    rows = query.order_by(VCTRegistry.created_at.desc()).all()

    def _pop_score(r: VCTRegistry) -> float:
        # popularity-only score for the plain list endpoint
        rating = float(r.avg_rating or 0.0) / 5.0
        max_calls = max([rr.calls_count or 0 for rr in rows] or [1])
        calls = float(r.calls_count or 0)
        pop = (calls / max_calls) if max_calls else 0.0
        return round(0.6 * rating + 0.4 * pop, 4)

    def row_json(r: VCTRegistry):
        try:
            langs = json.loads(r.languages_supported or "[]")
        except Exception:
            langs = []
        base = {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "languages_supported": langs,
            "vct": r.vct,
            "vct_urn": r.vct_urn,
            "integrity": r.integrity,
            "is_public": r.is_public,
            "created_at": (r.created_at.isoformat() if r.created_at else None),
            "updated_at": (r.updated_at.isoformat() if r.updated_at else None),
        }
        base.update(_rating_payload(r, user_id=(current_user.id if is_auth else None)))
        base.update({"score": _pop_score(r)})  # local popularity-only score
        return base

    return jsonify([row_json(r) for r in rows])


@login_required
def api_vct_upload():
    """Accept a multipart/form-data with 'file' JSON. Optional: 'publish'."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    raw = f.read()
    if not raw:
        return jsonify({"error": "Empty file"}), 400

    publish_flag = (request.form.get("publish") or "false").lower() in ("1", "true", "yes", "on")
    integrity = _sri_sha256(raw)

    # load file
    try:
        vct_json = json.loads(raw)
    except Exception as e:
        return jsonify({"error": f"Invalid JSON: {e}"}), 400

    # In the registry vct is built from the sha256 hash of the vct original value
    vct_urn = (vct_json.get("vct") or "").strip()
    if not vct_urn:
        return jsonify({"error": "Missing 'vct' in the JSON document"}), 400
    vct_urn_hashed = hashlib.sha256(vct_urn.encode()).digest()
    vct_urn = base64.urlsafe_b64encode(vct_urn_hashed).decode("ascii").rstrip('=')
    
    # build vct for publishing and update vct in the registry
    mode = current_app.config["MODE"]
    vct_url = mode.server + "vct/registry/publish/" + vct_urn
    vct_json["vct"] = vct_url

    name = vct_json.get("name")
    description = vct_json.get("description")
    langs = _extract_languages_supported_from_vct(vct_json)

    if VCTRegistry.query.filter_by(integrity=integrity).first():
        return jsonify({"error": "An entry with the same integrity already exists."}), 409

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
        languages_supported=json.dumps(langs),
        vct_data=json.dumps(vct_json),
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
    row = VCTRegistry.query.filter_by(id=row_id, user_id=current_user.id).first()
    if not row:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(row)
    db.session.commit()
    return jsonify({"ok": True})

@login_required
def api_vct_visibility(row_id: int):
    row = VCTRegistry.query.filter_by(id=row_id, user_id=current_user.id).first()
    if not row:
        return jsonify({"error": "Not found"}), 404
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
        #schema.setdefault("x_vct", row.vct)
        #schema.setdefault("x_integrity", row.integrity)
    payload = json.dumps(schema, ensure_ascii=False, indent=2)

    _bump_calls(row)

    resp = Response(payload, mimetype="application/json")
    resp.headers["Content-Disposition"] = f"attachment; filename={row.name or 'schema'}.schema.json"
    resp.headers["X-VCT"] = row.vct or ""
    resp.headers["X-Integrity"] = row.integrity
    return resp

@login_required
def api_vct_rate(row_id: int):
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

    payload = _rating_payload(row, user_id=current_user.id)
    return jsonify({"ok": True, **payload})

def api_vct_ai_search():
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        body = {}
    q = (body.get("q") or "").strip()
    requested_scope = (body.get("scope") or "public").lower()
    is_auth = getattr(current_user, "is_authenticated", False)
    scope = requested_scope if is_auth else "public"
    top_k = max(1, min(int(body.get("top_k") or 10), 50))

    query = VCTRegistry.query
    if scope == "public":
        query = query.filter_by(is_public=True)
    elif scope == "my":
        query = query.filter_by(user_id=current_user.id)
    else:
        query = query.filter((VCTRegistry.is_public == True) | (VCTRegistry.user_id == current_user.id))

    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            (VCTRegistry.search_text.ilike(like)) |
            (VCTRegistry.name.ilike(like)) |
            (VCTRegistry.vct.ilike(like)) |
            (VCTRegistry.keywords.ilike(like))
        )

    candidates: List[VCTRegistry] = query.order_by(VCTRegistry.updated_at.desc()).limit(150).all()

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
    if client and items:
        system = ("Return ONLY JSON: [{id, score, reason}] sorted by best match first. score in [0,1], reason <= 200 chars.")
        user = {
            "query": q,
            "instruction": (
                "Given the user query, pick the most relevant VC Types. "
                "Relevance criteria: field/claim match, schema property names, described purpose, and popularity hints. "
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
        candidates.sort(key=_kw_pop_score, reverse=True)
        ranked = candidates[:top_k]
    else:
        ranked_map = {rid: i for i, rid in enumerate(ranked_ids)}
        ranked = sorted(candidates, key=lambda r: ranked_map.get(r.id, 10**6))[:top_k]

        try:
            langs = json.loads(r.languages_supported or "[]")
        except Exception:
            langs = []

    def row_json(r: VCTRegistry):
        base = {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "languages_supported": langs,
            "vct": r.vct,
            "vct_urn": r.vct_urn,
            "integrity": r.integrity,  # keep available for copy button (not displayed)
            "is_public": r.is_public,
            "created_at": (r.created_at.isoformat() if r.created_at else None),
            "updated_at": (r.updated_at.isoformat() if r.updated_at else None),
        }
        base.update(_rating_payload(r, user_id=(current_user.id if is_auth else None)))
        if r.id in reasons:
            base.update({"score": reasons[r.id].get("score"), "reason": reasons[r.id].get("reason")})
        else:
            base.update({"score": round(_kw_pop_score(r), 4)})
        return base

    return jsonify([row_json(r) for r in ranked])
