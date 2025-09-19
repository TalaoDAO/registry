# Menu — VC‑REGISTRY.COM

**Audience:** Anyone creating, registering, or exploring **VC Type metadata** on vc‑registry.com.  
**Last updated:** 2025‑09‑17

This page documents the options on the **Menu** screen. The current menu is streamlined around three actions: **Create**, **Register & Publish (Free)**, and **Learn**.

---

## 1) Create VC Type
Open the generator to produce a valid **VC Type Metadata JSON** from scratch or from an existing JSON Schema.

- Include a **schema** (properties & constraints)
- Provide **display** entries (per language, with `lang`, `name`, `description`)
- Add **keywords** to boost catalog search
- Use a stable **`vct`** URL/URN that you control

**Go to:** `/attestation/generate`

---

## 2) Register & Publish (Free)
Upload your JSON to the **VC Type Registry**. The page will auto‑fill **Name** and **Description** when possible; these fields are **required**.

**Auto‑fill order:**  
1) Root: `name`, `description`  
2) `display` array (picks English when available) → `name`, `description`  
3) `schema.title`, `schema.description`

If either field is still missing, you’ll be prompted to fill it before upload.

After upload you can:
- Keep entries **Private** or **Publish** anytime
- Copy the stable **VCT URL**
- Copy the **sha256** integrity value (Subresource Integrity)
- Browse the **Public Catalog**, rate entries, and see popularity/usage

**Go to:** `/vct/registry` (Registry) • `/vct/registry?scope=public` (Public Catalog)

---

## 3) Learn the Basics
- **VCT Registry guide:** overview, auto‑fill rules, search tips, best practices.  
  **Link:** `/documentation/vct_registry`
- **Why publish:** improves discovery and interoperability across wallets and verifiers.
- **Spec alignment:** IETF *SD‑JWT VC issuer metadata* (see “Specification” links in the UI).

---

## Quick start
1. **Create** a VC Type → `/attestation/generate`  
2. **Register** it in the Registry → `/vct/registry`  
3. (Optional) **Publish** to the Public Catalog → `/vct/registry?scope=public`  
4. Share the **VCT URL** + **sha256** integrity with integrators.

---

## What changed from the old menu?
Advanced/legacy items (separate issuer/verifier modules, validators, status lists, etc.) were removed from the Menu to keep new users focused on the essential flow: **Create → Register/Publish → Learn**. Those modules can still be linked from docs or dedicated sections if needed.
