# vct_builder_from_issuer.py
# -----------------------------------------------------------------------------
# Build a VC Type (VCT) metadata document from an OIDC4VCI issuer configuration.
#
# Focus of this revision:
# - Issuers often DO NOT expose a full JSON Schema in metadata (draft ≥15).
# - Properties should therefore be synthesized from `claims`, including when
#   claim paths are expressed as JSON Pointers (string pointers).
# - Fix bug where only the *first* property was added when claims were a list:
#   we now add a property for EVERY claim leaf, not just when `props` is empty.
# - No reliance on `credentialSubject` (kept out of the builder as requested).
#
# Draft compatibility:
# - Works across 11 → 18:
#   • supports both `credentials_supported` (older) and
#     `credential_configurations_supported` (newer) containers
#   • recognizes current SD-JWT VC format id `dc+sd-jwt` and legacy aliases
#   • NEW: honors `credential_metadata.display` and `credential_metadata.claims`
#           as fallbacks per draft-16/17+ when top-level keys are absent.
#
# Output:
# - Dict with at least: vct, display[], schema{type,properties,required?}, claims[].
#
# Public function:
#     generate_vc_type_metadata_from_issuer(...)
# -----------------------------------------------------------------------------

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, Tuple, Iterable
import base64
import requests
import hashlib


# -----------------------------------------------------------------------------
# SD-JWT VC format detection (current + legacy aliases)
# -----------------------------------------------------------------------------

_SDJWT_FORMATS = {
    # current (draft-15/16+)
    "dc+sd-jwt",
    # legacy seen in the wild / earlier drafts or samples
    "vc+sd-jwt", "vc+sdjwt",
    "sd-jwt-vc", "sdjwt-vc",
    "jwt-vc+sd-jwt", "jwt_vc+sd-jwt",
}


def _is_sdjwt(cfg: Mapping[str, Any]) -> bool:
    """
    Heuristics to recognize an SD-JWT VC configuration across drafts.
    """
    fmt = str(cfg.get("format") or "").strip().lower()
    if fmt in _SDJWT_FORMATS:
        return True
    # Some issuers omit/strip `format` but SD-JWT VC requires a `vct` identifier.
    # Treat presence of `vct` (and absence of mdoc/mDL `doctype`) as SD-JWT VC.
    if "vct" in cfg and "doctype" not in cfg:
        return True
    return False


# -----------------------------------------------------------------------------
# HTTP + metadata normalization
# -----------------------------------------------------------------------------

def _wk_issuer_metadata_url(issuer: str) -> str:
    """
    Resolve the well-known issuer metadata path per OIDC4VCI.
    Accept both base issuer and full metadata URL; don't over-normalize.
    """
    issuer = str(issuer).strip()
    if issuer.endswith("/.well-known/openid-credential-issuer"):
        return issuer
    if issuer.endswith("/"):
        return issuer + ".well-known/openid-credential-issuer"
    return issuer + "/.well-known/openid-credential-issuer"


def _http_get_json(url: str, *, timeout: float = 8.0) -> Any:
    try:
        r = requests.get(url, timeout=timeout) 
        r.raise_for_status()
        # Some issuers serve text/plain
        return json.loads(r.text)
    except:
        return {}


def _objectify_credentials_supported(lst: Iterable[Any]) -> Dict[str, Any]:
    """
    Older drafts allowed a list for credentials_supported; normalize to a dict.
    """
    out: Dict[str, Any] = {}
    for i, item in enumerate(lst or []):
        if isinstance(item, Mapping):
            key = str(item.get("id") or item.get("type") or item.get("vct") or i)
            out[key] = dict(item)
    return out


# -----------------------------------------------------------------------------
# JSON pointer utilities
# -----------------------------------------------------------------------------

def _pointer_to_path(ptr: str) -> List[str]:
    """
    Minimal JSON Pointer to array-of-segments. Supports "#/a/b" or "/a/b".
    """
    p = ptr[1:] if ptr.startswith("/") else (ptr[2:] if ptr.startswith("#/") else ptr)
    return [seg.replace("~1", "/").replace("~0", "~") for seg in p.split("/") if seg != ""]


# -----------------------------------------------------------------------------
# Schema expansion (best-effort)
# -----------------------------------------------------------------------------

def _expand_schema(schema_node: Any, cfg: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Best-effort schema expansion:
      - if it's a URL, try to fetch; if it's an object, try to read properties/required.
    Returns (properties, required[]).
    """
    props: Dict[str, Any] = {}
    required: List[str] = []
    if isinstance(schema_node, Mapping):
        props = dict(schema_node.get("properties") or {})
        rq = schema_node.get("required")
        if isinstance(rq, list):
            required = [str(x) for x in rq if isinstance(x, (str, int))]
    elif isinstance(schema_node, str) and schema_node.strip():
        try:
            s = _http_get_json(schema_node.strip())
            if isinstance(s, Mapping):
                props = dict(s.get("properties") or {})
                rq = s.get("required")
                if isinstance(rq, list):
                    required = [str(x) for x in rq if isinstance(x, (str, int))]
        except Exception:
            pass
    return props, required


def _merge_props(props: Dict[str, Any], more: Optional[Dict[str, Any]]) -> None:
    if not isinstance(more, Mapping):
        return
    for k, v in more.items():
        if k not in props and isinstance(v, Mapping):
            props[k] = {"type": str(v.get("type") or "string")}
        elif isinstance(v, Mapping):
            props[k].update(v)


# -----------------------------------------------------------------------------
# Claims helpers
# -----------------------------------------------------------------------------

DESCRIPTOR_KEYS = {"label", "name", "title", "description", "lang", "language", "locale", "display", "mandatory", "required", "svg_id", "format", "hint"}

def _claims_md_from_claims_map(claims_map: Mapping[str, Any], *, base_path: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Normalize "claims" in map form into claims_md[] (with display[] synthesized).
    """
    out: List[Dict[str, Any]] = []
    for key, desc in (claims_map or {}).items():
        if not isinstance(key, str):
            continue
        path = (base_path or []) + [key]
        disp: List[Dict[str, Any]] = []

        if isinstance(desc, Mapping):
            # Collect per-language labels/descriptions if present
            for lang_key in ("display", "labels", "display_metadata"):
                d = desc.get(lang_key)
                if isinstance(d, list):
                    for entry in d:
                        if not isinstance(entry, Mapping):
                            continue
                        entry = dict(entry)
                        lang = entry.get("lang") or entry.get("language") or entry.get("locale")
                        label = entry.get("label") or entry.get("name") or entry.get("title")
                        description = entry.get("description")
                        if lang:
                            entry["lang"] = str(lang)
                        if label:
                            entry["label"] = str(label)
                        if description:
                            entry["description"] = str(description)
                        # keep only normalized keys in entry
                        pruned = {}
                        for k in ("lang", "label", "description"):
                            if entry.get(k):
                                pruned[k] = entry[k]
                        if pruned:
                            disp.append(pruned)
                else:
                    label = desc.get("label") or desc.get("name") or desc.get("title")
                    if label:
                        disp.append({"label": str(label)})

            # Recurse into nested maps that are not descriptor keys
            for k, v in desc.items():
                if isinstance(v, Mapping) and k not in DESCRIPTOR_KEYS:
                    out.extend(_claims_md_from_claims_map(v, base_path=path))

        out.append({"path": path, "display": disp or [{"label": key}], "sd": "allowed"})

    return out



def _image_url_to_data_uri(url: str, *, timeout: float = 15.0) -> str:
    """
    Fetch an image and return a data: URI string like 'data:image/png;base64,....'
    Raises requests.HTTPError on non-2xx responses.
    """
    try:
        headers = {"User-Agent": "img-fetch/1.0"}
        r = requests.get(url, timeout=timeout, headers=headers, stream=True)
        r.raise_for_status()
    except:
        return ""
    # Try to get the MIME type from the server; default to octet-stream.
    mime = r.headers.get("Content-Type", "application/octet-stream").split(";")[0].strip()
    # Read the bytes (since we set stream=True, call r.content to load them)
    data = r.content
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{b64}"


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


def _schema_from_claims_descriptions(cds: List[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    Lightweight synthesis: if issuer provides claims_descriptions list,
    shape a JSON Schema-like object out of it.
    """
    props: Dict[str, Any] = {}
    required: List[str] = []
    for item in cds or []:
        if not isinstance(item, Mapping):
            continue
        name = item.get("name")
        if isinstance(name, str) and name:
            props.setdefault(name, {"type": "string"})
            if item.get("mandatory") or item.get("required"):
                required.append(name)
    out: Dict[str, Any] = {"type": "object", "properties": props}
    if required:
        out["required"] = list(dict.fromkeys(required))
    return out


# -----------------------------------------------------------------------------
# Schema + claims extraction (NO schema required; JSON Pointer-aware claims)
# -----------------------------------------------------------------------------

def _schema_and_claims_from_cfg(cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Produce (schema, claims_md[]) from a single credential configuration `cfg`,
    with priority:
      1) If cfg["schema"] exists (rare), expand it (best-effort)
      2) Always derive properties from cfg["claims"] (dict OR list),
         recognizing JSON Pointer claim paths (string pointers), and
         mark required if issuer flags mandatory/required.
      3) Else derive from cfg["claims_descriptions"].
      4) NEW: When 2/3 are absent, fall back to cfg["credential_metadata"].get("claims")
             per OIDC4VCI draft-16/17+.
    """
    props: Dict[str, Any] = {}
    required: List[str] = []
    claims_md: List[Dict[str, Any]] = []

    # 1) Optional schema (best-effort only; issuers often don't provide it)
    schema_node = cfg.get("schema")
    if isinstance(schema_node, (Mapping, str)):
        p, r = _expand_schema(schema_node, cfg)
        _merge_props(props, p)
        for x in r:
            if x not in required:
                required.append(x)

    # 2) Claims → claims_md and ALWAYS synthesize properties from each claim leaf
    meta = cfg.get("credential_metadata") or {}  # ### NEW: draft-16/17 fallback
    cl = cfg.get("claims")
    if cl is None:
        cl = meta.get("claims")  # ### NEW

    if isinstance(cl, dict):
        # map style, e.g. {"given_name": {...}}
        claims_md.extend(_claims_md_from_claims_map(cl))
        for name, desc in cl.items():
            if isinstance(name, str):
                props.setdefault(name, {"type": "string"})
                if isinstance(desc, Mapping) and (desc.get("mandatory") or desc.get("required")):
                    if name not in required:
                        required.append(name)

    elif isinstance(cl, list):
        for entry in cl:
            if not isinstance(entry, Mapping):
                continue
            # Normalize path (array segments OR JSON Pointer string)
            path = entry.get("path") or entry.get("json_pointer") or entry.get("pointer")
            norm_path: List[str] = []
            if isinstance(path, str) and (path.startswith("#/") or path.startswith("/")):
                norm_path = _pointer_to_path(path)
            elif isinstance(path, list):
                norm_path = [str(p) for p in path if isinstance(p, (str, int))]
            elif isinstance(path, str):
                norm_path = [path]
            else:
                continue

            # Display
            disp = entry.get("display")
            if not isinstance(disp, list):
                disp = [{"label": norm_path[-1] if norm_path else "claim"}]

            # SD hint + extra fields passthrough
            out_e = {"path": norm_path, "display": disp, "sd": entry.get("sd", "allowed")}
            for k in ("svg_id", "hint", "format"):
                if k in entry:
                    out_e[k] = entry[k]
            claims_md.append(out_e)

            # ALWAYS add leaf into properties
            if norm_path:
                leaf = str(norm_path[-1])
                if leaf not in props:
                    props[leaf] = {"type": "string"}
                if entry.get("mandatory") or entry.get("required"):
                    if leaf not in required:
                        required.append(leaf)

    # 3) claims_descriptions → synthesize remaining if still nothing
    cds = cfg.get("claims_descriptions")
    if not cds:
        # Some issuers expose "claims" array only under credential_metadata (issuer-metadata flavor)
        cds = meta.get("claims")  # ### NEW: treat as claims_descriptions if needed
    if isinstance(cds, list) and cds:
        sch2 = _schema_from_claims_descriptions(cds)
        _merge_props(props, sch2.get("properties"))
        for x in sch2.get("required", []) or []:
            if x not in required:
                required.append(x)

    # 4) If still no claims_md, synthesize trivial entries from properties
    if not claims_md and props:
        for name in props.keys():
            claims_md.append({"path": [name], "display": [{"label": name}], "sd": "allowed"})

    schema: Dict[str, Any] = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema, claims_md


# -----------------------------------------------------------------------------
# Main builder
# -----------------------------------------------------------------------------

def generate_vc_type_metadata_from_issuer(
    issuer: str,
    *,
    vct: str,
    on_remote_vct: str = "extends",  # "extends" | "import"
    languages: Optional[List[str]] = None,
    simple_rendering: Optional[Dict[str, Any]] = None,
    timeout: float = 8.0,
    config_id: Optional[str] = None,
    vct_match: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a VCT metadata document from an OIDC4VCI issuer configuration.
    """
    # 1) Load issuer metadata (try well-known first)
    meta_url = _wk_issuer_metadata_url(issuer)
    try:
        meta = _http_get_json(meta_url, timeout=timeout)
    except Exception:
        meta = _http_get_json(issuer, timeout=timeout)

    if not isinstance(meta, dict):
        raise ValueError("Issuer metadata is not a JSON object")

    # 2) Normalize supported configurations across drafts
    raw_cfgs = (
        meta.get("credential_configurations_supported")  # draft 13+
        or meta.get("credentials_supported")             # drafts 11/12
        or {}
    )
    if isinstance(raw_cfgs, dict):
        configs: Dict[str, Any] = dict(raw_cfgs)
    elif isinstance(raw_cfgs, list):
        configs = _objectify_credentials_supported(raw_cfgs)
    else:
        configs = {}

    if not configs:
        raise ValueError("Issuer metadata does not contain supported credential configurations")

    # 3) Choose an SD-JWT VC configuration
    chosen_id: Optional[str] = None
    chosen: Optional[Dict[str, Any]] = None

    if config_id:
        if config_id in configs and _is_sdjwt(configs[config_id]):
            chosen_id, chosen = str(config_id), configs[config_id]
        else:
            for cid, cfg in configs.items():
                if not isinstance(cfg, dict) or not _is_sdjwt(cfg):
                    continue
                cid_str = str(cid)
                meta_id = str(cfg.get("id") or "")
                meta_type = str(cfg.get("type") or "")
                meta_vct = str(cfg.get("vct") or "")
                if config_id in (cid_str, meta_id, meta_type, meta_vct):
                    chosen_id, chosen = cid_str, cfg
                    break

    if chosen is None and vct_match:
        for cid, cfg in configs.items():
            if not isinstance(cfg, dict) or not _is_sdjwt(cfg):
                continue
            if str(cfg.get("vct") or "") == vct_match:
                chosen_id, chosen = str(cid), cfg
                break

    if chosen is None:
        # fallback: first SD-JWT config
        for cid, cfg in configs.items():
            if isinstance(cfg, dict) and _is_sdjwt(cfg):
                chosen_id, chosen = str(cid), cfg
                break

    if chosen is None:
        advertised = sorted({str(c.get("format") or "").lower() for c in configs.values() if isinstance(c, dict)})
        raise ValueError(f"No SD-JWT VC configuration found; advertised formats: {advertised or 'none'}")

    # 4) Type identifier / display
    issuer_vct = chosen.get("vct") or chosen.get("type") or chosen_id or vct

    # ### NEW / CHANGED: prefer top-level display, fall back to credential_metadata.display
    cm = chosen.get("credential_metadata") or {}
    raw_display = chosen.get("display")
    if raw_display is None:
        raw_display = cm.get("display")  # draft-16/17 fallback

    display = _normalize_display(raw_display or [])
    if languages:
        langs_norm = {l.split("-")[0].lower() for l in languages}
        pref = [d for d in display if str(d.get("lang", "")).split("-")[0].lower() in langs_norm]
        others = [d for d in display if d not in pref]
        display = pref + others

    # 5) Schema + claims (schema optional; properties always from claims)
    schema, claims_md = _schema_and_claims_from_cfg(chosen)

    # 6) Remote VCT reference handling
    result: Dict[str, Any] = {
        "vct": issuer_vct,
        "display": display,
        #"schema": schema,
        "claims": claims_md,
    }

    remote_vct = chosen.get("vct_uri") or chosen.get("vct_url")
    if isinstance(remote_vct, str) and remote_vct.strip():
        if on_remote_vct == "extends":
            result["extends"] = remote_vct
        elif on_remote_vct == "import":
            try:
                remote_json = _http_get_json(remote_vct, timeout=timeout)
                if isinstance(remote_json, dict):
                    imported = dict(remote_json)
                    imported.update(result)  # prefer local fields over remote
                    result = imported
            except Exception:
                pass  # keep local result if import fails

    # 7) Optional rendering hints passthrough
    if simple_rendering:
        result["rendering"] = {"simple": dict(simple_rendering)}
    else:
        simple_rendering = ""
    return result


# -----------------------------------------------------------------------------
# Display normalization
# -----------------------------------------------------------------------------

def _normalize_display(raw: Any) -> List[Dict[str, Any]]:
    """
    Accepts list|dict|None and returns a list of {lang?, label/name?, description?}.
    Normalizes `language`/`locale`→`lang`, `name/title`→`label`.
    """
    if raw is None:
        return []
    if isinstance(raw, Mapping):
        raw = [raw]
    out: List[Dict[str, Any]] = []
    for d in raw or []:
        if not isinstance(d, Mapping):
            continue
        lang = d.get("lang") or d.get("language") or d.get("locale")
        label = d.get("label") or d.get("name") or d.get("title")
        desc = d.get("description")
        text_color = d.get("text_color")
        background_color = d.get("background_color")
        logo = d.get("logo")
        background_image = d.get("background_image")
        entry: Dict[str, Any] = {}
        if text_color or background_color or logo or background_image:
            entry["rendering"] = {"simple": {}}
            if text_color:
                entry["rendering"]["simple"].update(({"text_color": text_color}))
            if background_color:
                entry["rendering"]["simple"].update({"background_color": background_color})
            if logo:
                uri_integrity = _sri_sha256_from_url(logo.get("uri"))
                if uri_integrity:
                    logo.update({"uri#integrity" : uri_integrity})
                    entry["rendering"]["simple"].update({"logo": logo})
            if background_image:
                uri_integrity = _sri_sha256_from_url(background_image.get("uri"))
                if uri_integrity:
                    background_image.update({"uri#integrity" : uri_integrity})
                    entry["rendering"]["simple"].update({"background_image": background_image})
        if lang:
            entry["lang"] = str(lang)
        if label:
            entry["label"] = str(label)
        if desc:
            entry["description"] = str(desc)
        
        if entry:
            out.append(entry)
    return out
