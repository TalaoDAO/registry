# vct_translate.py
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from flask import jsonify, request
from flask_login import login_required

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
logger = logging.getLogger("vct_translate")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# ----------------------------------------------------------------------------
# LangChain-based LLM plumbing (mirrors vct_registry.py style)
# ----------------------------------------------------------------------------
try:
    from langchain_openai import ChatOpenAI  # type: ignore
except Exception:
    ChatOpenAI = None  # type: ignore
try:
    # (gemini disabled in vct_registry.py; keeping openai parity)
    from langchain_core.messages import SystemMessage, HumanMessage  # type: ignore
except Exception:
    SystemMessage = None  # type: ignore
    HumanMessage = None  # type: ignore

try:
    with open("keys.json", "r") as f:
        KEYS = json.load(f)
except Exception:
    KEYS = {}

class LLMConfig:
    def __init__(self, provider: str = None, model: str = None, temperature: float = 0.1):
        self.provider = provider or os.environ.get("LLM_PROVIDER", "openai")
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.temperature = temperature

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
    # Gemini block is intentionally omitted to mirror vct_registry.py
    return None

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
        s = str(text).strip().strip("`")
        if s.startswith("json"):
            s = s[4:].strip()
        return json.loads(s)
    except Exception as e:
        logger.warning("LLM %s invocation failed: %s", phase, e)
        return None

# ----------------------------------------------------------------------------
# JSON helpers (schema-agnostic; ONLY touch display[] and claims[*].display[])
# ----------------------------------------------------------------------------

def _ensure_array(node: Dict[str, Any], key: str) -> List[Any]:
    arr = node.get(key)
    if isinstance(arr, list):
        return arr
    arr = []
    node[key] = arr
    return arr

def _first_nonempty_string(*vals) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def _get_top_level_displays(doc: Dict[str, Any]) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]]]:
    """
    Return (container_node, array_key, array_value) for the top-level display array.
    Prefer existing arrays under conventional keys; else create doc["display"].
    """
    candidates = ["display", "displays", "ui", "presentation.display"]
    for k in candidates:
        cur = doc
        parts = k.split(".")
        ok = True
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                arr = cur.get(part)
                if isinstance(arr, list):
                    return cur, part, arr
            else:
                nxt = cur.get(part)
                if not isinstance(nxt, dict):
                    ok = False
                    break
                cur = nxt
        if ok and isinstance(cur.get(parts[-1]), list):
            return cur, parts[-1], cur[parts[-1]]
    arr = _ensure_array(doc, "display")
    return doc, "display", arr

def _existing_langs(display_arr: List[Dict[str, Any]]) -> set:
    langs = set()
    for d in display_arr:
        if isinstance(d, dict):
            lang = _first_nonempty_string(d.get("lang"), d.get("language"), d.get("locale"))
            if lang:
                langs.add(lang)
    return langs

def _find_claims_array(doc: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    for key in ("claims", "fields", "properties_list"):
        arr = doc.get(key)
        if isinstance(arr, list):
            return arr
    vct = doc.get("vct")
    if isinstance(vct, dict) and isinstance(vct.get("claims"), list):
        return vct["claims"]
    schema = doc.get("schema")
    if isinstance(schema, dict) and isinstance(schema.get("claims"), list):
        return schema["claims"]
    return None

def _claim_key_from_item(item: Dict[str, Any]) -> Optional[str]:
    p = item.get("path")
    if isinstance(p, list) and p:
        head = p[0]
        if isinstance(head, str) and head.strip():
            return head.strip()
    if isinstance(p, str) and p.strip():
        return p.strip().split("/")[0].split(".")[0].split()[0]
    for alt in ("key", "name", "id", "property"):
        v = item.get(alt)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def _find_display_array_on_claim(claim: Dict[str, Any]) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]]]:
    for k in ("display", "labels"):
        arr = claim.get(k)
        if isinstance(arr, list):
            return claim, k, arr
    pres = claim.get("presentation")
    if isinstance(pres, dict) and isinstance(pres.get("display"), list):
        return pres, "display", pres["display"]
    arr = _ensure_array(claim, "display")
    return claim, "display", arr

def _pick_base_display_entry(displays: List[Dict[str, Any]], prefer_lang_prefix: str = "en") -> Optional[Dict[str, Any]]:
    # Prefer English entry with a label
    for d in displays:
        if not isinstance(d, dict):
            continue
        lang = _first_nonempty_string(d.get("lang"), d.get("language"), d.get("locale")) or ""
        if lang.lower().startswith(prefer_lang_prefix) and isinstance(d.get("label"), str) and d["label"].strip():
            return d
    # Else first with a label
    for d in displays:
        if isinstance(d, dict) and isinstance(d.get("label"), str) and d["label"].strip():
            return d
    # Else any object
    return displays[0] if displays else None

def _pick_base_claim_label(carr: List[Dict[str, Any]], prefer_lang_prefix: str = "en") -> Optional[str]:
    for d in carr:
        if not isinstance(d, dict):
            continue
        lang = _first_nonempty_string(d.get("lang"), d.get("language"), d.get("locale")) or ""
        if lang.lower().startswith(prefer_lang_prefix):
            lbl = d.get("label")
            if isinstance(lbl, str) and lbl.strip():
                return lbl.strip()
    for d in carr:
        lbl = (d or {}).get("label")
        if isinstance(lbl, str) and lbl.strip():
            return lbl.strip()
    return None

# ----------------------------------------------------------------------------
# LLM translation utility (array I/O, minimal prompt)
# ----------------------------------------------------------------------------

def _llm_translate_list(labels: List[str], target_lang: str) -> Optional[List[str]]:
    """
    Translate a list of UI labels to target_lang using the same LangChain client style.
    Returns None on failure (caller should fallback).
    """
    client = _ensure_llm(LLMConfig(), use_llm=True, phase=f"translate:{target_lang}")
    if not client:
        return None

    system = (
        "You are a precise UI localization assistant. "
        "Translate each input label into the requested target language. "
        "Return ONLY a JSON object: {\"labels\": [ ... ]} with the same length/order."
    )
    user = {"target_language": target_lang, "labels": labels}
    out = _invoke_llm_json(client, system, user, phase=f"translate:{target_lang}")
    if isinstance(out, dict) and isinstance(out.get("labels"), list) and len(out["labels"]) == len(labels):
        return [str(x) for x in out["labels"]]
    return None

# ----------------------------------------------------------------------------
# Core: add translations ONLY under display[] and claims[*].display[]
# ----------------------------------------------------------------------------

def _add_or_update_translations(vct: Dict[str, Any], target_langs: List[str]) -> Dict[str, Any]:
    """
    Returns a NEW VCT JSON with added translations.
    Constraints:
      - Only modify top-level display[] and per-claim display[].
      - Do not change top-level main/title/name/description/etc.
      - Prefer English as the source; fallback to first available label.
    """
    doc = json.loads(json.dumps(vct, ensure_ascii=False))  # deep copy

    # Top-level display
    _, _, top_displays = _get_top_level_displays(doc)
    existing_top_langs = _existing_langs(top_displays)
    base_top = _pick_base_display_entry(top_displays, "en")
    base_top_label = base_top.get("label") if isinstance(base_top, dict) else None
    base_alt_text = None
    if isinstance(base_top, dict):
        rendering = base_top.get("rendering") or {}
        simple = rendering.get("simple") if isinstance(rendering, dict) else None
        bg = simple.get("background_image") if isinstance(simple, dict) else None
        base_alt_text = (bg or {}).get("alt_text")

    # Claims collection
    claims = _find_claims_array(doc) or []
    # Precollect base labels per claim
    base_claim_labels: List[Tuple[int, str]] = []
    for idx, claim in enumerate(claims):
        if not isinstance(claim, dict):
            continue
        _, _, carr = _find_display_array_on_claim(claim)
        base_lbl = _pick_base_claim_label(carr, "en")
        if base_lbl is None:
            base_lbl = _claim_key_from_item(claim) or "label"
        base_claim_labels.append((idx, base_lbl))

    # Process per target language
    for L in target_langs or []:
        # 1) Top display entry for L
        if L not in existing_top_langs:
            new_disp: Dict[str, Any] = {"lang": L}
            # top label via LLM if we have a base; else leave missing
            if isinstance(base_top_label, str) and base_top_label.strip():
                xlated = _llm_translate_list([base_top_label], L)
                new_disp["label"] = (xlated[0] if xlated else f"{base_top_label} (TODO {L})")
            # copy rendering.simple and LLM translate alt_text if present
            if isinstance(base_top, dict) and isinstance(base_top.get("rendering"), dict):
                simple = base_top["rendering"].get("simple")
                if isinstance(simple, dict):
                    new_simple = json.loads(json.dumps(simple, ensure_ascii=False))
                    if isinstance(base_alt_text, str) and base_alt_text.strip():
                        alt = _llm_translate_list([base_alt_text], L)
                        if alt and "background_image" in new_simple and isinstance(new_simple["background_image"], dict):
                            new_simple["background_image"]["alt_text"] = alt[0]
                    new_disp["rendering"] = {"simple": new_simple}
            top_displays.append(new_disp)

        # 2) Per-claim entries for L
        batch_src: List[str] = []
        targets: List[Tuple[List[Dict[str, Any]], str]] = []  # (carr, L)
        for (idx, base_lbl) in base_claim_labels:
            claim = claims[idx]
            host, key, carr = _find_display_array_on_claim(claim)
            # skip if already has L
            if any(isinstance(d, dict) and (d.get("lang") == L or d.get("language") == L or d.get("locale") == L) for d in carr):
                continue
            src = base_lbl or _claim_key_from_item(claim) or "label"
            batch_src.append(src)
            targets.append((carr, L))

        if batch_src:
            xlated = _llm_translate_list(batch_src, L)
            if not xlated or len(xlated) != len(batch_src):
                xlated = [f"{t} (TODO {L})" for t in batch_src]

            for i, (carr, lang_tag) in enumerate(targets):
                carr.append({"lang": lang_tag, "label": xlated[i]})

    return doc




# ----------------------------------------------------------------------------
# API:
# ----------------------------------------------------------------------------

def api_translate_vct(vct, target_langs):
    """
    Body (ONLY two arguments as requested):
      {
        "vct": { ... }  OR  "vct": "<json string>",
        "target_langs": ["es-ES","fr-FR", ...]
      }

    Behavior:
      - Adds new language entries ONLY under top-level display[] and each claim's display[].
      - Does NOT modify top-level name/title/description/etc.
      - Prefers English as the translation source; otherwise falls back to the first available label.
      - Uses LangChain-based LLM if configured; else falls back with ' (TODO <lang>)'.
    """

    if not isinstance(target_langs, list) or not target_langs:
        return jsonify({"error": "target_langs must be a non-empty array"}), 400

    # Accept object or JSON string
    if isinstance(vct, str):
        try:
            vct_obj = json.loads(vct)
        except Exception:
            return jsonify({"error": "vct must be an object or a valid JSON string"}), 400
    elif isinstance(vct, dict):
        vct_obj = vct
    else:
        return jsonify({"error": "vct must be an object or a valid JSON string"}), 400

    updated = _add_or_update_translations(vct_obj, target_langs)
    return {"vct": updated}


# ----------------------------------------------------------------------------
# Route: POST /vct/translate/api
# ----------------------------------------------------------------------------

@login_required
def route_translate_vct():
    """
    Body (ONLY two arguments as requested):
      {
        "vct": { ... }  OR  "vct": "<json string>",
        "target_langs": ["es-ES","fr-FR", ...]
      }

    Behavior:
      - Adds new language entries ONLY under top-level display[] and each claim's display[].
      - Does NOT modify top-level name/title/description/etc.
      - Prefers English as the translation source; otherwise falls back to the first available label.
      - Uses LangChain-based LLM if configured; else falls back with ' (TODO <lang>)'.
    """
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    vct = body.get("vct")
    target_langs = body.get("target_langs")

    if not isinstance(target_langs, list) or not target_langs:
        return jsonify({"error": "target_langs must be a non-empty array"}), 400

    # Accept object or JSON string
    if isinstance(vct, str):
        try:
            vct_obj = json.loads(vct)
        except Exception:
            return jsonify({"error": "vct must be an object or a valid JSON string"}), 400
    elif isinstance(vct, dict):
        vct_obj = vct
    else:
        return jsonify({"error": "vct must be an object or a valid JSON string"}), 400

    updated = _add_or_update_translations(vct_obj, target_langs)
    return jsonify({"ok": True, "vct": updated})

# ----------------------------------------------------------------------------
# Registration hook
# ----------------------------------------------------------------------------

def init_app(app):
    """
    Wire into your Flask app:
        from vct_translate import init_app as init_vct_translate
        init_vct_translate(app)
    """
    app.add_url_rule("/vct/translate/api", view_func=route_translate_vct, methods=["POST"])



# ---- Dev entrypoint: `python app.py` ----
if __name__ == "__main__":
    vct = json.load(open("verifiable_id.json", "r"))
    target_langs = [ "de-DE", "it-IT"]
    vct_updated = api_translate_vct(vct, target_langs)["vct"]
    print(json.dumps(vct_updated, indent=4)) 


"""
[
  {"country":"United States","language":"English (US)","tag":"en-US"},
  {"country":"United Kingdom","language":"English (UK)","tag":"en-GB"},
  {"country":"Canada","language":"English (Canada)","tag":"en-CA"},
  {"country":"Australia","language":"English (Australia)","tag":"en-AU"},
  {"country":"India","language":"Hindi","tag":"hi-IN"},
  {"country":"Pakistan","language":"Urdu","tag":"ur-PK"},
  {"country":"Bangladesh","language":"Bengali","tag":"bn-BD"},
  {"country":"Indonesia","language":"Indonesian","tag":"id-ID"},
  {"country":"Malaysia","language":"Malay","tag":"ms-MY"},
  {"country":"Philippines","language":"Filipino","tag":"fil-PH"},
  {"country":"Vietnam","language":"Vietnamese","tag":"vi-VN"},
  {"country":"Thailand","language":"Thai","tag":"th-TH"},
  {"country":"China","language":"Chinese (Simplified)","tag":"zh-Hans-CN"},
  {"country":"Taiwan","language":"Chinese (Traditional)","tag":"zh-Hant-TW"},
  {"country":"Hong Kong","language":"Chinese (Traditional)","tag":"zh-Hant-HK"},
  {"country":"Japan","language":"Japanese","tag":"ja-JP"},
  {"country":"South Korea","language":"Korean","tag":"ko-KR"},
  {"country":"Spain","language":"Spanish (Spain)","tag":"es-ES"},
  {"country":"Mexico","language":"Spanish (Mexico)","tag":"es-MX"},
  {"country":"Argentina","language":"Spanish (Argentina)","tag":"es-AR"},
  {"country":"Colombia","language":"Spanish (Colombia)","tag":"es-CO"},
  {"country":"Brazil","language":"Portuguese (Brazil)","tag":"pt-BR"},
  {"country":"Portugal","language":"Portuguese (Portugal)","tag":"pt-PT"},
  {"country":"Germany","language":"German","tag":"de-DE"},
  {"country":"France","language":"French","tag":"fr-FR"},
  {"country":"Italy","language":"Italian","tag":"it-IT"},
  {"country":"Netherlands","language":"Dutch","tag":"nl-NL"},
  {"country":"Sweden","language":"Swedish","tag":"sv-SE"},
  {"country":"Poland","language":"Polish","tag":"pl-PL"},
  {"country":"Russia","language":"Russian","tag":"ru-RU"}
]


"""