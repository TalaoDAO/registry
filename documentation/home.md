# SD‑JWT VC Open Registry


This page explains what the **SD‑JWT VC Open Registry** is, how **VC Type identifiers (vct)** work as **URNs** or **URLs**, and why choosing a **URL** unlocks decentralized, dereferenceable metadata that fits the open‑web model of SD‑JWT VCs.

---

## What is the Open Registry?

The Open Registry is a catalog of **VC Type Metadata (VCTs)** that anyone can **publish, discover, and reuse**.  
Each entry is a JSON document that describes a verifiable credential type: its **identifier (`vct`)**, **localized display** (labels, descriptions), and the **claims** (paths + UI labels) with an accompanying **JSON Schema** for validation.

**You use it to:**
- Discover existing VC Types instead of reinventing them.
- Reuse consistent **claim names** and **labels** across issuers and verifiers.
- Share your own VC Types publicly (or keep them private until ready).

---

## The `vct` identifier: URN vs URL

A VC Type’s **`vct`** MUST be a globally unique identifier. In practice there are **two patterns**:

- **URN (e.g., `urn:example:vct:verifiable-id`):**  
  - *Good for*: centralized or curated registries that promise stability.  
  - *Trade‑off*: **not dereferenceable** on the web by default; you need an out‑of‑band index or resolver.

- **URL (e.g., `https://example.org/vct/verifiable-id.json`):**  
  - *Good for*: decentralized publication; anyone can host.  
  - *Benefit*: **dereferenceable** with a plain HTTP GET → the VCT JSON.  
  - *Bonus*: can carry **integrity** (via hashing / content‑addressing) and **versioning** via normal web practices.

Both are valid. The registry supports them **side‑by‑side** so you can choose what fits your governance model.

---

## Why prefer a URL for `vct`?

- **Dereferenceable by design**  
  One click (or a simple fetch) returns the **authoritative VCT JSON**. No proprietary resolver needed.

- **Decentralized & portable**  
  Anyone who controls a domain can publish a VC Type. Forks and mirrors are natural and transparent.

- **Versionable**  
  Use web conventions (e.g., `v1/`, git tags, immutable content hashes) to make **versions explicit**.

- **Composability**  
  URLs can reference other resources (icons, style assets, `$defs` schemas) under the same origin.

- **Operational clarity**  
  Caching, ETags, `Last‑Modified`, and CDNs work out of the box. Observability is standard web tooling.

> TL;DR — **URLs make VCTs self‑describing, linkable, and easy to automate.**

---

## How resolution works (URL `vct`)

1. A wallet/verifier sees a `vct` that is a **URL**.  
2. It **fetches** that URL.  
3. The response is the **VC Type Metadata JSON** (or a small index that redirects to the current version).  
4. The app uses the **`display[]`** for labels/translations, **`claims[]`** for UI, and **`schema`** for validation.

> With URNs, step 2 requires a **separate resolver** or a central registry API to map the URN → JSON.

---

## Governance models

- **Centralized / curated (URN or URL)**  
  A single operator (or standards group) maintains canonical VCTs. URN is common; URL also works.

- **Federated / multi‑party (URL)**  
  Several organizations host their own VCTs at their domains and cross‑link or mirror each other.

- **Self‑published / long‑tail (URL)**  
  Individual issuers and solution vendors publish VCTs they control, then **submit pointers** to the Open Registry for discovery.

---

## Publishing a VC Type (quick recipe)

1. **Pick an identifier**
   - Prefer a **URL** on a domain you control (e.g., `https://issuer.example/vct/my-credential.json`).  
   - If your program mandates URNs, you can still list them in the Open Registry.

2. **Author the VCT JSON**
   - Fill `vct`, `display[]` (labels & descriptions in your languages), `claims[]` (paths + labels), and `schema` (draft 2020‑12).

3. **Host it**
   - Serve `application/json`. Consider immutable URLs per version (e.g., `/2025-09-28/…`) with a stable “latest” pointer.

4. **(Optional) Add integrity**
   - Publish a content hash (e.g., `sha256-…`) alongside, or embed a link to a content‑addressed location.

5. **Submit to the Open Registry**
   - Share the **URL or URN** so others can find and reuse your VC Type.

---

## Using VC Types from the registry

- **Browse** or **search by keyword** to find a VC Type.  
- **Inspect** `display[]` and `claims[]` to ensure they match your wallet/verifier UI needs.  
- **Adopt** the `vct` as is, or **extend** locally (custom translations, additional claims) while keeping the original link.

---

## Interop & migration tips

- If you **start with URNs** and later want dereferencing, publish a **URL mirror** and add it to the registry entry.  
- Keep labels in **`display[]`** localized for your users; it helps wallets show consistent UI across issuers.  
- Avoid breaking changes; use **new versions** for incompatible claim or schema updates.

---

## Security & privacy notes

- **No secrets** in VCTs — they are **public metadata**.  
- Prefer **HTTPS** and immutable versions for auditability.  
- If you embed icons/images, host them under the **same origin** as your VCT URL.  
- Consider **content hashing** to help relying parties detect unexpected changes.

---

## FAQ

**Q: Are URNs “wrong”?**  
No. They’re great for **curated** namespaces. But they’re not linkable without an external resolver.

**Q: Do I have to publish my VCT publicly?**  
No. You can keep it private or share only within a consortium — the Open Registry supports private visibility too.

**Q: Can I keep my URN but still be dereferenceable?**  
Yes. Publish the **same metadata** at a **URL** and list both in the registry entry.

---

## Where to go next

- **Publish** your first VC Type (URL recommended).  
- **Browse** existing types to reuse common building blocks.  
- **Localize** `display[]` to the languages your users need.  
- **Validate** your credential payloads with the `schema` shipped in the VCT.

