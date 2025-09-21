# Create VC Type — From Scratch

**Audience:** Users who don’t have an issuer or schema, and want to define a new VC Type Metadata (VCT) starting from a description.

---

## Purpose of this page

This form lets you **describe a credential in free text** and automatically generate a draft VC Type Metadata.  
The system infers a JSON Schema and `display[]` entries, which you can refine.

---

## Quick Start (2 minutes)

1. Enter a **VCT identifier** (URL or URN).  
2. Provide a **VCT name**.  
3. Write an **Attestation description** (free text or bullet list).  
4. Optionally customize **Display style** (colors, logo).  
5. Select target **Languages**.  
6. Click **Generate Metadata**.  
7. Review and edit the generated JSON.  
8. Save JSON to your desktop or upload.

---

## Step-by-Step

### 1) VCT identifier
- Required field.  
- Example: `https://issuer.example.com/vct/your-credential`.

### 2) VCT name
- Human-readable name.  
- Example: “Employment Attestation”.

### 3) Attestation description
- Free text or bullet list.  
- Example:  
  ```
  An employment attestation proving a person works for ACME
  - employeeId
  - fullName
  - address: street, locality, region, postalCode, country
  ```  
- The system infers a schema from this.

### 4) Display style
- Background color, text color, optional logo.  
- Applies to all languages.

### 5) Languages
- Choose supported locales.  
- **Select all** / **Clear all** helpers.  
- Include English plus target locales.

### 6) Actions
- **Generate Metadata** — produce draft JSON.  
- **Format** — prettify JSON.  
- **Validate** — check structure.  
- **Reset to Server Result** — restore initial.  
- **Copy** — copy JSON to clipboard.  
- **Save JSON to Desktop** — download.

---

## Result overview

At the end you’ll have a **VCT JSON file** with:  
- A stable identifier.  
- Localized names and descriptions.  
- An inferred JSON Schema.  
- Claims mapped for display.

---

## Practical recipes

- **Prototype quickly** — just describe your credential.  
- **Use AI assistance** — let the system draft schema and claims.  
- **Refine later** — edit JSON directly.

---

## Tips & best practices

- Write clear descriptions with bullet points.  
- Keep identifiers stable.  
- Always check the generated schema manually.  
- Localize early if possible.

---

## Troubleshooting

- **Schema looks wrong** → Rewrite description more clearly.  
- **Validation fails** → Fix errors directly in the JSON.  
- **No output** → Ensure description isn’t empty.  
- **Download disabled** → Generate first.

---

✅ You can now generate a new VC Type Metadata from scratch and refine it to your needs.
