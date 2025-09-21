# Create VC Type — From Issuer

**Audience:** Users who have access to an **OIDC4VCI Credential Issuer** and want to generate a VC Type Metadata (VCT) directly from it.

---

## Purpose of this page

This form lets you **import metadata from an OIDC4VCI Credential Issuer** to prefill a Verifiable Credential Type (VCT).  
The system extracts configuration automatically and prepares the JSON for review.

---

## Quick Start (2 minutes)

1. Enter the **Issuer URL**.  
2. Click **Load issuer**.  
3. Select the credential configuration you want.  
4. The system fills in fields like `vct`, `display[]`, `claims`, and `schema`.  
5. Review and edit the generated metadata in the editor.  
6. Save JSON to your desktop or upload it to the registry.

---

## Step-by-Step

### 1) Issuer URL
- Paste the URL of the OIDC4VCI issuer.  
- Supported: Draft 11 through Final specification.

### 2) Load issuer
- Fetches issuer metadata.  
- Populates available credentials for selection.

### 3) VCT identifier
- Required text field.  
- Example: `https://issuer.example.com/vct/employee`.

### 4) VCT name
- Human-readable name.  
- Example: “Work ID”.

### 5) Display style
- Optional customization applied to all languages.  
- Fields: background color, text color, logo URL.

### 6) Languages
- Select one or more languages for `display[]`.  
- Use **Select all** / **Clear all** buttons.  
- We recommend English plus your target locales.

### 7) Actions
- **Generate Metadata** — fetch + prefill JSON.  
- **Format** — prettify JSON.  
- **Validate** — check JSON structure.  
- **Reset to Server Result** — restore original.  
- **Copy** — copy JSON to clipboard.  
- **Save JSON to Desktop** — download the file.

### 8) Upload to Registry
- Optional step to add this VCT into your registry space.  
- Choose whether to publish immediately.

---

## Result overview

At the end you’ll have a **VCT JSON file** with identifier, display metadata, schema, and claims extracted from the issuer.

---

## Practical recipes

- **Generate quickly** from a live issuer instead of starting from scratch.  
- **Reuse issuer metadata** across multiple environments.  
- **Combine with Manage Registry** to keep a private copy or publish.

---

## Tips & best practices

- Always verify the **issuer URL** is reachable.  
- Double-check localized `display[]` fields.  
- Keep your VCT identifiers stable.  
- Use the integrity hash if you reference the file externally.

---

## Troubleshooting

- **Issuer not loading** → Check the URL, it must support OIDC4VCI metadata.  
- **No credential offered** → The issuer might not advertise VCTs.  
- **Validation fails** → Correct the JSON manually in the editor.  
- **Upload disabled** → You may not be logged in.

---

✅ You can now generate a VC Type Metadata directly from an issuer and add it to your registry.
