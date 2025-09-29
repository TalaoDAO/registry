from __future__ import annotations
from typing import Any, Dict, List, Optional, Union

JSON = Dict[str, Any]
PathSeg = Union[str, int, None]

# Minimal SD-JWT VC core claims you may want in every VC
CORE_CLAIMS: JSON = {
    "vct":   {"type": "string"},
    "vct#integrity":   {"type": "string"},
    "iss":   {"type": "string"},
    "nbf":   {"type": "number"},
    "iat":   {"type": "number"},
    "exp":   {"type": "number"},
    "cnf":   {"type": "object"},
    "status":{"type": "object"},
}

def _ensure_object(node: JSON) -> None:
    """Force node to be an object with a properties map (no multi-type)."""
    node["type"] = "object"
    node.setdefault("properties", {})

def _ensure_array(node: JSON) -> None:
    """Force node to be an array with an items schema (no multi-type)."""
    node["type"] = "array"
    node.setdefault("items", {})

def _descend_by_path(root: JSON, path: List[PathSeg]) -> JSON:
    """
    Walk (and create) along a claim path:
      - str  -> object property
      - None -> array wildcard
      - int  -> array index (treated like wildcard at schema level)
    Returns the leaf node dict to assign a type to.
    """
    node = root
    for i, seg in enumerate(path):
        last = (i == len(path) - 1)

        if isinstance(seg, str):
            _ensure_object(node)
            props = node["properties"]
            child = props.get(seg)
            if child is None:
                child = {}
                props[seg] = child
            node = child

        elif seg is None or isinstance(seg, int):
            _ensure_array(node)
            if not isinstance(node["items"], dict):
                node["items"] = {}
            node = node["items"]

        # Prefer object shape on intermediate nodes so deeper keys can attach
        if not last and "type" not in node:
            node["type"] = "object"

    return node

def _type_schema_for_name(
    field_name: Optional[str],
    default_leaf_type: str,
    leaf_type_hints: Optional[Dict[str, Union[str, JSON]]],
) -> JSON:
    """
    Decide the leaf schema:
      - exact hint for the field name (string => {"type": x}, dict => merged as-is)
      - small built-in heuristics (email -> format: email)
      - fallback to {"type": default_leaf_type}
    """
    # explicit hints first
    if leaf_type_hints and field_name and field_name in leaf_type_hints:
        hint = leaf_type_hints[field_name]
        if isinstance(hint, str):
            return {"type": hint}
        if isinstance(hint, dict):
            # ensure no multi-type arrays sneak in
            t = hint.get("type")
            if isinstance(t, list) and t:
                hint = dict(hint)
                hint["type"] = t[0]
            return hint

    # lightweight heuristics (optional)
    if field_name:
        lname = field_name.lower()
        if lname in {"email", "e-mail", "mail"}:
            return {"type": "string", "format": "email"}
        if lname in {"url", "uri", "website"}:
            return {"type": "string", "format": "uri"}
        if lname in {"birthdate", "date_of_birth", "dob"}:
            return {"type": "string", "format": "date"}
        if lname in {"phone", "phone_number", "tel"}:
            return {"type": "string"}

    return {"type": default_leaf_type}

def generate_sd_jwt_vc_schema_from_claims(
    vct_meta: JSON,
    *,
    include_core_claims: bool = True,
    required_core: Optional[List[str]] = None,
    require_key_binding: bool = False,
    title: Optional[str] = None,
    additional_properties: Optional[bool] = None,
    # NEW: single-type defaults and hints
    default_leaf_type: str = "string",
    leaf_type_hints: Optional[Dict[str, Union[str, JSON]]] = None,
) -> JSON:
    """
    Build a JSON Schema (draft 2020-12) *only* from VCT `claims`, with single-type leaves.

    - Ignores VCT embedded schema entirely.
    - Never emits `"type": [...]` arrays — only single-type strings.
    - Arrays in the path (`None` or int) are modeled via `items`.
    - Leaves default to {"type": default_leaf_type} (default: "string"),
      optionally refined by `leaf_type_hints` or simple heuristics.

    Parameters of interest:
      default_leaf_type: fallback type used for leaf nodes (e.g. "string").
      leaf_type_hints:   map field-name -> type or full schema to override defaults.
    """
    schema: JSON = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {},
    }
    if title:
        schema["title"] = title
    elif vct_meta.get("name"):
        schema["title"] = vct_meta["name"]

    if vct_meta.get("description"):
        schema["description"] = vct_meta["description"]
        
    if include_core_claims:
        schema["properties"].update({k: dict(v) for k, v in CORE_CLAIMS.items()})

    claims = vct_meta.get("claims") or []
    for entry in claims:
        path = entry.get("path")
        if not isinstance(path, list) or not path:
            continue

        # normalize path: keep str/int/None; trim strings
        norm: List[PathSeg] = []
        last_str_name: Optional[str] = None
        for seg in path:
            if seg is None or isinstance(seg, int):
                norm.append(seg)
            elif isinstance(seg, str):
                s = seg.strip()
                if s:
                    norm.append(s)
                    last_str_name = s  # remember last property name for hints

        if not norm:
            continue

        leaf = _descend_by_path(schema, norm)

        # Assign a single-type schema to the leaf if not already set
        if "type" not in leaf and "properties" not in leaf and "items" not in leaf:
            leaf.update(_type_schema_for_name(last_str_name, default_leaf_type, leaf_type_hints))
        else:
            # If type exists and is a list (shouldn't happen here), collapse to the first
            if isinstance(leaf.get("type"), list) and leaf["type"]:
                leaf["type"] = leaf["type"][0]

    # Required core properties
    if include_core_claims:
        if required_core is None:
            required_core = ["vct", "iss"]
        if require_key_binding and "cnf" not in required_core:
            required_core.append("cnf")
        req = [k for k in required_core if k in schema["properties"]]
        if req:
            schema["required"] = req

    if additional_properties is not None:
        schema["additionalProperties"] = additional_properties

    return schema
