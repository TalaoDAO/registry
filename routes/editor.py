# editor.py
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import jsonify, render_template, request
from flask_login import login_required, current_user

from db_model import db, VCTRegistry

# Reuse helpers from vct_registry
from routes.vct_registry import (
    _sri_sha256,
    _sri_sha256_from_url,
    _extract_languages_supported_from_vct,
    _extract_keywords,
    _build_search_text,
)

logger = logging.getLogger("vct_editor")

def init_app(app):
    app.add_url_rule("/vct/registry/editor/<int:row_id>", view_func=editor_page, methods=["GET"])
    app.add_url_rule("/vct/registry/api/update/<int:row_id>", view_func=api_vct_update, methods=["POST"])

@login_required
def editor_page(row_id: int):
    # Allow owner or admin
    is_admin = getattr(current_user, "is_admin", False) or getattr(current_user, "role", "") == "admin"
    if is_admin:
        row = VCTRegistry.query.filter_by(id=row_id).first()
    else:
        row = VCTRegistry.query.filter_by(id=row_id, user_id=current_user.id).first()
    if not row:
        # Keep the same tone as your APIs
        return render_template("error.html", message="Not found or not permitted"), 404
    return render_template("editor.html", user=current_user, row_id=row.id)

@login_required
def api_vct_update(row_id: int):
    """
    Update an existing VC Type in-place (same vct).
    Accepts: multipart/form-data with 'file' = JSON document (like /api/upload).
    """
    # Permission: owner or admin
    is_admin = getattr(current_user, "is_admin", False) or getattr(current_user, "role", "") == "admin"
    if is_admin:
        row = VCTRegistry.query.filter_by(id=row_id).first()
    else:
        row = VCTRegistry.query.filter_by(id=row_id, user_id=current_user.id).first()
    if not row:
        return jsonify({"error": "Not found or not permitted"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    raw = request.files["file"].read()
    if not raw:
        return jsonify({"error": "Empty file"}), 400

    # Parse edited JSON
    try:
        vct_json: Dict[str, Any] = json.loads(raw)
    except Exception as e:
        return jsonify({"error": f"Invalid JSON: {e}"}), 400

    # Keep the same VCT URL (stable public endpoint)
    vct_json["vct"] = row.vct

    # Recompute optional uri#integrity for assets (same logic as upload)
    try:
        display_list = vct_json.get("display") or []
        for display in (display_list if isinstance(display_list, list) else [display_list]):
            if not isinstance(display, dict):
                continue
            simple = (display.get("rendering") or {}).get("simple") or {}
            bg = (simple.get("background_image") or {})
            logo = (simple.get("logo") or {})
            if uri := bg.get("uri"):
                integ = _sri_sha256_from_url(uri)
                if integ:
                    bg["uri#integrity"] = integ
                    simple["background_image"] = bg
            if uri := logo.get("uri"):
                integ = _sri_sha256_from_url(uri)
                if integ:
                    logo["uri#integrity"] = integ
                    simple["logo"] = logo
            if simple:
                display.setdefault("rendering", {})["simple"] = simple
    except Exception:
        logger.warning("Failed to compute uri#integrity for assets", exc_info=True)

    # Move schema (if present) to DB extra, keep VCT 'schema' empty (same approach as upload)
    schema = {}
    try:
        if "schema" in vct_json and vct_json.get("schema"):
            schema = vct_json.pop("schema", {}) or {}
    except Exception:
        pass

    # Canonical payload and integrity
    payload = json.dumps(vct_json, ensure_ascii=False, separators=(",", ":"))
    integrity = _sri_sha256(payload.encode("utf-8"))

    # Avoid collision with another row having the same integrity
    #conflict = VCTRegistry.query.filter(VCTRegistry.integrity == integrity, VCTRegistry.id != row.id).first()
    #if conflict:
    #    return jsonify({"error": "Another entry with the same integrity already exists."}), 409

    # Update searchable fields & basics
    try:
        obj = vct_json
        row.name = obj.get("name") or row.name
        row.description = obj.get("description") or row.description
    except Exception:
        pass

    row.integrity = integrity
    row.languages_supported = json.dumps(_extract_languages_supported_from_vct(vct_json), ensure_ascii=False)
    row.keywords = ",".join(_extract_keywords(vct_json))
    row.search_text = _build_search_text(vct_json)
    row.vct_data = payload
    if schema:
        row.extra = json.dumps(schema, ensure_ascii=False)
    row.updated_at = datetime.now(timezone.utc)

    db.session.commit()

    return jsonify({
        "ok": True,
        "id": row.id,
        "integrity": row.integrity,
        "vct": row.vct,
        "vct_urn": getattr(row, "vct_urn", None),
        "name": row.name,
        "is_public": row.is_public
    })
