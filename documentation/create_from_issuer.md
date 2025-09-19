# Create VC Type — From Existing Issuer

**Audience:** Users who want to derive a **VC Type (VCT) Metadata** file directly from an **OIDC4VCI Credential Issuer**.

---

## Purpose of this page
This form fetches **OIDC4VCI issuer metadata** (`/.well-known/openid-credential-issuer`), lets you **load and choose** a credential configuration, and generates a **VCT JSON** that mirrors the issuer’s definitions (schema, claims, display, vct).  
You can **review, edit, validate, and save** the result.

---

## Fields in the form

### 1. VCT name (optional)
- A friendly name, only used for the generated filename.  
- If left blank, the tool uses the first available `display.name` from the issuer metadata.

### 2. Credential Issuer URL
- The base URL of the OIDC4VCI issuer (example: `https://talao.co/issuer/hrngdrpura`).  
- Metadata is fetched from `/.well-known/openid-credential-issuer`.  
- If that path fails, the direct URL is tried.

### 3. Credential configuration
- After you fill the issuer URL, click **Load**.  
- The builder queries the issuer for its SD-JWT VC configurations.  
- A dropdown (`select`) will appear so you can pick the configuration to use.  
- Each option may include a `name`, `id`, and `vct`.

### 4. When issuer provides a remote VCT (URL)
- **Extends (default):** Your generated VCT includes an `extends` entry pointing to the remote VCT (with integrity).  
- **Import:** The remote VCT is imported inline into your JSON.

---

## Actions

- **Generate Metadata** — Build the VCT JSON for the selected configuration.  
- **Format** — Pretty-print the JSON.  
- **Validate** — Check that the JSON is valid.  
- **Reset to Server Result** — Discard edits and reload the original JSON.  
- **Copy** — Copy JSON to your clipboard.  
- **Save JSON to Desktop** — Download the file (name includes the VCT identifier and timestamp).  

The JSON editor appears once metadata has been generated.

---

## What the generated VCT contains
- **`vct`** — The exact identifier from the issuer configuration.  
- **`display[]`** — Taken directly from the issuer’s `display` entries (languages, names, logos, colors if present).  
- **`schema`** — JSON Schema (2020-12) built from the issuer’s claims definitions.  
- **`claims[]`** — Each claim path with `display` entries for all languages provided by the issuer.  
- No labels or languages are added — the file respects what the issuer publishes.

---

## Tips & Troubleshooting
- **Load button does nothing** — Check the URL and console (CORS errors may block requests).  
- **No configurations found** — The issuer may not support SD-JWT VC.  
- **Error on generate** — Ensure you selected a configuration after loading.  
- **Editing JSON** — Use **Format** and **Validate** before saving to ensure clean output.

---

✅ You now have a VCT file derived directly from an issuer, suitable for registry upload or further use.
