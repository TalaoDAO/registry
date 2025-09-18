from __future__ import annotations

import json
import uuid
from datetime import datetime
from flask import request, render_template, current_app, jsonify, redirect, url_for
from flask_login import login_required, current_user

import requests
import vct_builder as vct
import vct_builder_from_issuer


def init_app(app):
    # Keep the original routes (do not modify)
    app.add_url_rule('/attestation/generate', view_func=landing_page, methods=['GET'])
    app.add_url_rule('/attestation/generate/scratch', view_func=generate_from_scratch_page, methods=['GET'])
    app.add_url_rule('/attestation/generate/schema', view_func=generate_from_schema_page, methods=['GET'])
    app.add_url_rule('/attestation/generate/issuer', view_func=generate_from_issuer_page, methods=['GET'])
    # JSON APIs
    app.add_url_rule('/attestation/api/generate', view_func=api_generate_attestation, methods=['POST'])
    app.add_url_rule('/attestation/api/issuer-configs', view_func=api_list_issuer_configs, methods=['POST'])


@login_required
def landing_page():
    # Back-compat entry point
    return redirect(url_for('generate_from_scratch_page'))


@login_required
def generate_from_scratch_page():
    vct_uri = f"urn:uuid:{uuid.uuid4()}"
    return render_template('create_from_scratch.html', vct=vct_uri, name="", user=current_user)


@login_required
def generate_from_schema_page():
    vct_uri = f"urn:uuid:{uuid.uuid4()}"
    return render_template('create_from_schema.html', vct=vct_uri, name="", user=current_user)


@login_required
def generate_from_issuer_page():
    vct_uri = f"urn:uuid:{uuid.uuid4()}"
    return render_template('create_from_issuer.html', vct=vct_uri, name="", user=current_user)


@login_required
def api_generate_attestation():
    """
    JSON body:
      {
        "input_mode": "description" | "schema" | "issuer",
        "vct": "urn:... or https://...",
        "name": "...",                # optional
        "description": "...",         # required only for description mode
        "schema": {...},              # required only for schema mode
        "issuer_url": "https://...",  # required only for issuer mode
        "on_remote_vct": "extends" | "import",   # issuer mode option (default: extends)
        "config_id": "id-in-issuer-metadata",    # optional, issuer mode
        "vct_match": "exact-vct-value",          # optional, issuer mode
        "languages": ["en","fr"],
        "use_llm": false,
        "simple_rendering": { "background_color":"#...", "text_color":"#...", "logo_uri":"https://..." }
      }
    """
    try:
        payload = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    input_mode = str(payload.get('input_mode') or 'description').lower()
    vct_uri = payload.get('vct') or f"urn:uuid:{uuid.uuid4()}"
    name = (payload.get('name') or '').strip() or None
    description = (payload.get('description') or '').strip() or None
    languages = payload.get('languages') or ['en']
    if not isinstance(languages, list) or not languages:
        languages = ['en']
    languages = [str(l).strip().lower() for l in languages if str(l).strip()]
    if not languages:
        languages = ['en']

    simple = payload.get('simple_rendering') or None
    #use_llm = bool(payload.get('use_llm'))
    use_llm = True
    cfg = vct.LLMConfig() if use_llm and hasattr(vct, 'LLMConfig') else None

    try:
        if input_mode in ('description', 'scratch'):
            if not description:
                return jsonify({"error": "'description' is required for input_mode=description"}), 400
            result = vct.generate_vc_type_metadata(
                description=description,
                vct=vct_uri,
                issuer=None,
                cfg=cfg,
                use_llm=use_llm,
                require_llm=True,
                languages=languages,
                simple_rendering=simple,
            )
        elif input_mode == 'schema':
            schema = payload.get('schema')
            if schema is None:
                return jsonify({"error": "'schema' is required for input_mode=schema"}), 400
            # If schema is a JSON string, parse it
            if isinstance(schema, str):
                try:
                    schema = json.loads(schema)
                except Exception as e:
                    return jsonify({"error": f"Invalid schema JSON string: {e}"}), 400
            result = vct.generate_vc_type_metadata_from_schema(
                schema=schema,
                vct=vct_uri,
                cfg=cfg,
                use_llm=use_llm,
                require_llm=True,
                languages=languages,
                simple_rendering=simple,
            )
        elif input_mode == 'issuer':
            issuer_url = (payload.get('issuer_url') or '').strip()
            if not issuer_url:
                return jsonify({"error": "'issuer_url' is required for input_mode=issuer"}), 400
            on_remote_vct = str(payload.get('on_remote_vct') or 'extends').lower()
            if on_remote_vct not in ('extends','import'):
                on_remote_vct = 'extends'
            config_id = (payload.get('config_id') or '').strip() or None
            vct_match = (payload.get('vct_match') or '').strip() or None
            result = vct_builder_from_issuer.generate_vc_type_metadata_from_issuer(
                issuer=issuer_url,
                vct=vct_uri,
                on_remote_vct=on_remote_vct,
                languages=languages,
                simple_rendering=simple,
                config_id=config_id,
                vct_match=vct_match,
            )
        else:
            return jsonify({"error": f"Unknown input_mode '{input_mode}'"}), 400

    except Exception as e:
        return jsonify({"error": f"Failed to generate metadata: {e}"}), 500

    # Overlay optional top-level name/description
    if name:
        result['name'] = name
    if description and input_mode != 'schema':
        # Only keep description from request for description/issuer modes;
        # schema mode should rely on provided data or post-editing.
        result['description'] = description
    """
    result.setdefault('_generated', {
        'by': 'vc-registry',
        'user_id': getattr(current_user, 'id', None),
        'at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'mode': input_mode,
    })"""

    return current_app.response_class(
        response=json.dumps(result, ensure_ascii=False, indent=2),
        status=200,
        mimetype='application/json; charset=utf-8',
    )


@login_required
def api_list_issuer_configs():
    try:
        payload = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
    issuer_url = (payload.get('issuer_url') or '').strip()
    if not issuer_url:
        return jsonify({"error": "'issuer_url' is required"}), 400
    try:
        items = list_sdjwt_configs_from_issuer(issuer=issuer_url)
        print("items = ", items)
        return current_app.response_class(
            response=json.dumps(items, ensure_ascii=False, indent=2),
            status=200,
            mimetype='application/json; charset=utf-8',
        )
    except Exception as e:
        return jsonify({"error": f"Failed to fetch issuer configs: {e}"}), 500


def _wk_issuer_metadata_url(issuer: str) -> str:
    issuer = (issuer or "").strip()
    if not issuer:
        raise ValueError("issuer is required")
    if issuer.endswith('/'):
        issuer = issuer[:-1]
    return issuer + "/.well-known/openid-credential-issuer"

def _http_get_json(url: str, *, timeout: float = 8.0):
    resp = requests.get(url, timeout=timeout, headers={"accept": "application/json"})
    resp.raise_for_status()
    return resp.json()

def _objectify_credentials_supported(obj):
    if isinstance(obj, dict):
        return dict(obj)
    out = {}
    if isinstance(obj, list):
        for i, entry in enumerate(obj):
            if isinstance(entry, dict):
                cid = entry.get("id") or entry.get("type") or f"cred_{i}"
                out[str(cid)] = entry
    return out

_SDJWT_FORMATS = {"dc+sd-jwt", "vc+sd-jwt", "sd_jwt_vc"}

def _normalize_display(entries):
    out = []
    if not isinstance(entries, list):
        return out
    for it in entries:
        if not isinstance(it, dict):
            continue
        lang = (it.get("locale") or it.get("lang") or it.get("language") or "").lower() or None
        d = {}
        if lang:
            d["lang"] = lang
        if it.get("name"):
            d["name"] = it["name"]
        if it.get("description"):
            d["description"] = it["description"]
        logo = it.get("logo") or {}
        if isinstance(logo, dict):
            uri = logo.get("url") or logo.get("uri")
            if uri:
                d["logo"] = {"uri": uri}
        if d:
            out.append(d)
    # de-dup
    seen = set(); uniq = []
    for d in out:
        key = (d.get("lang"), d.get("name"), d.get("description"))
        if key in seen:
            continue
        seen.add(key); uniq.append(d)
    return uniq

def list_sdjwt_configs_from_issuer(issuer: str, *, timeout: float = 8.0):
    """Return a normalized list of SD‑JWT VC configs: [{id, format, vct, name, display}]"""
    meta_url = _wk_issuer_metadata_url(issuer)
    try:
        meta = _http_get_json(meta_url, timeout=timeout)
    except Exception:
        meta = _http_get_json(issuer, timeout=timeout)
    if not isinstance(meta, dict):
        raise ValueError("Issuer metadata is not a JSON object")
    if isinstance(meta.get("credential_configurations_supported"), dict):
        configs = dict(meta["credential_configurations_supported"])
    elif meta.get("credentials_supported") is not None:
        configs = _objectify_credentials_supported(meta["credentials_supported"])
    else:
        configs = {}
    out = []
    for cid, cfg in configs.items():
        if not isinstance(cfg, dict):
            continue
        fmt = (cfg.get("format") or "").lower()
        if fmt not in _SDJWT_FORMATS:
            continue
        disp = _normalize_display(cfg.get("display") or [])
        # choose a reasonable label name
        name = None
        if disp:
            for d in disp:
                if d.get("lang") == "en" and d.get("name"):
                    name = d["name"]; break
            if not name:
                for d in disp:
                    if d.get("name"):
                        name = d["name"]; break
        out.append({
            "id": str(cid),
            "format": fmt,
            "vct": cfg.get("vct"),
            "name": name,
            "display": disp,
        })
    return out
