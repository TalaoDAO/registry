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

import requests


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
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    # Some issuers serve text/plain
    return json.loads(r.text)


def _objectify_credentials_supported(raw: Any) -> Dict[str, Any]:
    """
    Normalize older list-shaped credentials_supported into a mapping.
    """
    if isinstance(raw, dict):
        return dict(raw)
    out: Dict[str, Any] = {}
    if isinstance(raw, list):
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                continue
            cid = str(
                item.get("id")
                or item.get("type")
                or item.get("vct")
                or item.get("format")
                or f"cfg-{i}"
            )
            out[cid] = item
    return out


def _normalize_display(display: Any) -> List[Dict[str, Any]]:
    """
    Normalize type-level display to [{lang?, name?, description?}, ...].
    """
    if not display:
        return []
    if isinstance(display, dict):
        display = [display]
    out: List[Dict[str, Any]] = []
    for d in display or []:
        if not isinstance(d, Mapping):
            continue
        lang = d.get("lang") or d.get("language") or d.get("locale")
        name = d.get("name") or d.get("title")
        desc = d.get("description") or d.get("desc")
        entry: Dict[str, Any] = {}
        if lang:
            entry["lang"] = str(lang)
        if name:
            entry["name"] = str(name)
        if desc:
            entry["description"] = str(desc)
        if entry:
            out.append(entry)
    return out


# -----------------------------------------------------------------------------
# JSON Pointer resolution (RFC 6901) and helpers (no credentialSubject logic)
# -----------------------------------------------------------------------------

def _json_pointer_get(doc: Any, pointer: str) -> Any:
    """
    Minimal RFC6901 resolver for local pointers (starting with '#/' or '/').
    Supports ~0 -> '~' and ~1 -> '/' unescaping. Returns None on miss.
    """
    if not isinstance(pointer, str):
        return None
    if pointer.startswith("#"):
        pointer = pointer[1:]
    if pointer == "":
        return doc
    if not pointer.startswith("/"):
        return None

    def _unescape(token: str) -> str:
        return token.replace("~1", "/").replace("~0", "~")

    cur = doc
    for raw in pointer.split("/")[1:]:
        key = _unescape(raw)
        if isinstance(cur, list):
            try:
                idx = int(key)
            except ValueError:
                return None
            if idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
        elif isinstance(cur, dict):
            if key not in cur:
                return None
            cur = cur[key]
        else:
            return None
    return cur


def _deref_local_ref(node: Any, root: Mapping[str, Any], *, max_depth: int = 12) -> Any:
    """
    If node is {'$ref': '#/...'}, return the referenced object.
    Follows up to max_depth to avoid cycles. Non-local or invalid refs are ignored.
    """
    cur = node
    depth = 0
    while isinstance(cur, dict) and "$ref" in cur and depth < max_depth:
        ref = cur.get("$ref")
        if not isinstance(ref, str) or not ref.startswith("#"):
            break
        target = _json_pointer_get(root, ref)
        if target is None:
            break
        cur = target
        depth += 1
    return cur


def _pointer_to_path(ptr: str) -> List[str]:
    """
    Convert a JSON Pointer into a list path (no special trimming).
    """
    if not isinstance(ptr, str):
        return []
    if ptr.startswith("#"):
        ptr = ptr[1:]
    if not ptr.startswith("/"):
        return []
    def _unescape(t: str) -> str:
        return t.replace("~1", "/").replace("~0", "~")
    return [_unescape(p) for p in ptr.split("/")[1:]]


def _merge_props(dst: Dict[str, Any], src: Any):
    """Shallow-merge JSON Schema properties into dst."""
    if isinstance(src, Mapping):
        for k, v in src.items():
            if isinstance(k, str):
                if isinstance(v, Mapping):
                    dst.setdefault(k, dict(v))
                else:
                    dst.setdefault(k, {"type": "string"})


def _expand_schema(node: Any, root: Mapping[str, Any], *, max_depth: int = 16) -> Tuple[Dict[str, Any], List[str]]:
    """
    Resolve a schema node into (properties, required) with local $ref and common combinators.
    Handles dict or string pointer node; $ref (local); allOf/oneOf/anyOf; properties/required.
    NOTE: Most issuers won't give us a schema (draft ≥15), so this is a best-effort
    for cases where they still do. It is NOT required for normal operation.
    """
    props: Dict[str, Any] = {}
    req: List[str] = []

    def walk(n: Any, depth: int = 0):
        if depth > max_depth or n is None:
            return
        # string pointer to a schema
        if isinstance(n, str):
            if n.startswith("#") or n.startswith("/"):
                t = _json_pointer_get(root, n)
                walk(t, depth + 1)
            return
        # follow local $ref
        if isinstance(n, Mapping) and "$ref" in n:
            t = _deref_local_ref(n, root)
            walk(t, depth + 1)
            return
        if not isinstance(n, Mapping):
            return

        # combinators
        for key in ("allOf", "oneOf", "anyOf"):
            if isinstance(n.get(key), list):
                for item in n[key]:
                    walk(item, depth + 1)

        # properties / required
        _merge_props(props, n.get("properties"))
        r = n.get("required")
        if isinstance(r, list):
            for x in r:
                if isinstance(x, str) and x not in req:
                    req.append(x)

        # arrays: bubble up item properties for discovery
        if n.get("type") == "array" and isinstance(n.get("items"), Mapping):
            items = n["items"]
            if "properties" in items or "required" in items or "$ref" in items:
                walk(items, depth + 1)

    walk(node, 0)
    return props, req


# -----------------------------------------------------------------------------
# Claims metadata helpers (no credentialSubject assumptions)
# -----------------------------------------------------------------------------

DESCRIPTOR_KEYS = {
    "description",
    "label",
    "display",
    "mandatory",
    "required",
    "locale",
    "lang",
    "language",
    "format",
    "type",
    "pattern",
    "enum",
    "title",
    "examples",
    "default",
}


def _claims_md_from_claims_map(desc_map: Mapping[str, Any], base_path: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Convert an issuer's nested claims map into flat claim metadata entries.
    Each output entry: {"path": [...], "display": [...], "sd": "allowed"}.
    """
    out: List[Dict[str, Any]] = []
    base_path = base_path or []

    for key, desc in (desc_map or {}).items():
        if not isinstance(key, str):
            continue
        path = base_path + [key]
        disp: List[Dict[str, Any]] = []

        if isinstance(desc, Mapping):
            if isinstance(desc.get("display"), list):
                for d in desc["display"]:
                    if not isinstance(d, Mapping):
                        continue
                    entry: Dict[str, Any] = {}
                    lang = d.get("lang") or d.get("language") or d.get("locale")
                    label = d.get("label") or d.get("name") or d.get("title")
                    description = d.get("description")
                    if lang:
                        entry["lang"] = str(lang)
                    if label:
                        entry["label"] = str(label)
                    if description:
                        entry["description"] = str(description)
                    if entry:
                        disp.append(entry)
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
    cl = cfg.get("claims")

    if isinstance(cl, dict):
        # map style, e.g. {"given_name": {...}}
        claims_md.extend(_claims_md_from_claims_map(cl))
        # ALWAYS merge keys from the map into properties (not only when props empty)
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

            # ALWAYS add leaf into properties (this fixes "only one property" bug)
            if norm_path:
                leaf = str(norm_path[-1])
                if leaf not in props:
                    props[leaf] = {"type": "string"}
                # Check mandatory/required flags on the entry
                if entry.get("mandatory") or entry.get("required"):
                    if leaf not in required:
                        required.append(leaf)

    # 3) claims_descriptions → synthesize remaining if still nothing
    cds = cfg.get("claims_descriptions")
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
    display = _normalize_display(chosen.get("display") or [])
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
        "schema": schema,
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

    return result


# -----------------------------------------------------------------------------
# CLI for quick testing
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse, sys

    p = argparse.ArgumentParser(description="Build VCT metadata from an issuer (OIDC4VCI, SD-JWT VC).")
    p.add_argument("issuer", help="Issuer base URL or issuer metadata URL")
    p.add_argument("--vct", default="urn:example:vct:unknown", help="Fallback VCT identifier")
    p.add_argument("--config-id", help="Explicit configuration id/name/type/vct to select")
    p.add_argument("--match-vct", help="Pick config whose vct equals this value")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--languages", nargs="*", help="Preferred display languages (e.g., en fr de)")
    p.add_argument("--remote-policy", choices=["extends", "import"], default="extends", help="If issuer references a remote VCT")
    args = p.parse_args()

    try:
        doc = generate_vc_type_metadata_from_issuer(
            args.issuer,
            vct=args.vct,
            on_remote_vct=args.remote_policy,
            languages=args.languages,
            timeout=args.timeout,
            config_id=args.config_id,
            vct_match=args.match_vct,
        )
        json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
        print()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
