# VC Type Menu (Platform Guide)

**Audience:** users of the platform.  
This guide explains the **Menu** page (`menu.html`) where you choose how to create, manage, or discover **VC Type Metadata (VCTs)**. Think of it as the starting point for all workflows.

---

## What you’ll do on this page

From the menu you can:

- **Generate a VCT from an Issuer** (OIDC4VCI metadata).  
- **Generate a VCT from JSON Schema** you already have.  
- **Generate a VCT from Scratch**, assisted by AI.  
- **Manage your own VCTs** (publish, update, delete).  
- **Browse the Registry** of public VCTs.

Each card on the page corresponds to one of these flows.

---

## Quick Start (2 minutes)

1. Open the **Menu** page.  
2. Decide what you want to do:
   - Have an **Issuer URL**? → choose **Generate from an Issuer**.  
   - Have a **JSON Schema file**? → choose **Generate from JSON Schema**.  
   - Have only a **description of your credential**? → choose **Generate from Scratch**.  
   - Want to **edit or publish your own VCTs**? → open **Manage your VC Types**.  
   - Want to **see what others published**? → click **Browse the Registry**.  
3. Click the button on the card to continue.

---

## Step-by-Step: the options

### 1) Generate from an Issuer
- **Purpose**: Fetch OIDC4VCI **Credential Issuer** metadata to prefill a VCT.  
- **What happens**:  
  - Reads `vct`, `display[]`, `claims`, and `schema` from the issuer.  
  - Supports OIDC4VCI drafts 11 through final.  
- **Next**: After loading, you select the specific credential and continue editing.

### 2) Generate from JSON Schema
- **Purpose**: Reuse an existing schema (`.json` file).  
- **What happens**:  
  - The tool keeps your property names.  
  - Lets you add localized `display[]`.  
  - Optional AI assistance.  
- **Next**: Upload the file and proceed to the generator/editor.

### 3) Generate from Scratch
- **Purpose**: Start without an issuer or schema.  
- **What happens**:  
  - Describe your credential in free form.  
  - The tool drafts a `schema` and `display[]`.  
  - Supports up to 30 languages, with AI assistance.  
- **Next**: Review and refine the generated result.

### 4) Manage your VC Types
- **Purpose**: Workspace for your own VCTs.  
- **What happens**:  
  - List, update visibility (public/private), or delete VCTs.  
  - Each entry requires a name and description.  
  - The platform computes an integrity hash (`sha256-…`).  
- **Next**: Click a row to download, edit, or change settings.

### 5) Browse the Registry
- **Purpose**: Discover VCTs shared by others.  
- **What happens**:  
  - Search by keyword (with optional AI search).  
  - See ratings, usage counts, and supported languages.  
- **Next**: Reuse these VCTs directly in your own system.

---

## Result overview

By the end of any of the generation flows you’ll have a **VC Type Metadata JSON** file that includes:
- **`vct`** — identifier (URL or URN).  
- **`display[]`** — localized names, descriptions, and rendering options.  
- **`schema`** — JSON Schema of the claims.  
- **`claims[]`** — mapping of claim paths to localized display labels.  

If you choose Manage or Browse, you won’t generate a new file, but you’ll interact with existing VCTs.

---

## Practical recipes

- **You have an Issuer** → use *Generate from an Issuer*, then refine.  
- **You have a schema file** → use *Generate from JSON Schema*, add translations, then save.  
- **You only have an idea** → use *Generate from Scratch*, describe, then refine with AI help.  
- **You already published VCTs** → use *Manage your VC Types* to keep them up to date.  
- **You want to reuse community types** → use *Browse the Registry*.

---

## Tips & best practices

- Start from the **flow that matches what you already have** (issuer, schema, or just an idea).  
- Keep your VCT identifiers stable — use a URL or URN you control.  
- Localize names/descriptions for your target languages early.  
- Use the registry to avoid reinventing existing types.  
- Manage visibility: keep VCTs private until they’re ready.

---

## Troubleshooting

- **Issuer not loading** → Check the issuer URL is accessible and supports OIDC4VCI metadata.  
- **Schema upload fails** → Ensure it’s valid JSON, using draft 2020-12 or later.  
- **AI draft looks wrong** → Edit the schema/labels manually or retry with simpler description.  
- **Registry empty** → Try changing scope (My, Public, Private, All) or adjust search terms.  
- **Cannot change visibility** → Only the creator can change visibility of their VCTs.

---

## Where to get help

- On the page header, click **“Explain ?”** to open this guide.  
- For technical issues, include the VCT identifier or JSON snippet when contacting support.

---

**That’s it!** You now know what each menu option does and how to pick the right flow.


---

## Using the Open Registry: two integration patterns

There are **at least two ways** to consume VC Type metadata (`vct`) from this Open Registry:

### 1) **Use `vct` as a URL (direct dereferencing)**
- Put the **URL** directly as the `vct` in your SD‑JWT VC.  
  Example: `https://issuer.example/vct/person-id/2025-09-28.json`
- **Issuer**, **Verifier**, and **Wallet** can **fetch** the URL to retrieve the canonical VC Type Metadata JSON.  
- Pros: simple, decentralized, cache/CDN‑friendly, works without any central resolver.

**When to choose:** you control a domain, prefer open‑web linking, or want fast iteration with explicit versions (e.g., `.../v1/`, dated paths, or content hashes).

### 2) **Use `vct` as a URN (centralized resolution), with URL in the registry**
- Some ecosystems (e.g., **EUDI Wallet**) prefer or require a **URN** as the VC Type identifier.  
  Example: `urn:example:vct:person-id`
- In that case, **publish your VCT’s canonical URL inside the centralized registry** entry.  
- Relying parties resolve the **URN → registry entry → URL**, then fetch the metadata from that URL.

**When to choose:** your governance requires URNs or you operate in a curated, centrally resolved namespace—while still leveraging a URL for actual metadata hosting.

> Tip: The Open Registry supports **both**. You can **list a URN and a URL in the same entry** so ecosystems that dereference URLs **and** those that resolve URNs are both happy.
