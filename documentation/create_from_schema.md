# Create VC Type — From JSON Schema

**Audience:** Users who already have a **JSON Schema (2020‑12 or later)** and want to generate a VC Type Metadata (VCT) from it.

---

## Purpose of this page

This form lets you **upload a JSON Schema file** and transform it into VC Type Metadata.  
You can then edit the generated JSON, add display information, and save or upload it.

---

## Quick Start (2 minutes)

1. Upload your **.json schema file**.  
2. Provide a **VCT identifier** (URL or URN).  
3. Enter a **VCT name**.  
4. Optionally set **Display style** and **Logo URL**.  
5. Select one or more **Languages** for localization.  
6. Click **Generate Metadata**.  
7. Edit the JSON if needed, then save or upload.

---

## Step-by-Step

### 1) JSON Schema file
- Required upload field.  
- File must be `.json` and conform to draft 2020‑12+.  
- The schema is used directly to build metadata.

### 2) VCT identifier
- Required text field.  
- Example: `https://issuer.example.com/vct/your-credential`.

### 3) VCT name
- Human-readable name for the type.  
- Example: “Work ID”.

### 4) Display style
- Background color, text color, optional logo.  
- Applies to all locales.

### 5) Languages
- Choose languages for `display[]`.  
- Use **Select all** / **Clear all** buttons.  
- Include English and your target locales.

### 6) Actions
- **Generate Metadata** — process schema into JSON.  
- **Format** — prettify JSON.  
- **Validate** — ensure schema validity.  
- **Reset to Server Result** — restore initial output.  
- **Copy** — copy JSON to clipboard.  
- **Save JSON to Desktop** — download.

---

## Result overview

You’ll produce a **VCT JSON file** that contains:  
- The VCT identifier.  
- Localized `display[]`.  
- The schema you uploaded.  
- Claims mapped for display.

---

## Practical recipes

- **Have an existing schema?** → Upload it here.  
- **Want multilingual labels?** → Select locales and add translations.  
- **Need to validate quickly?** → Use the Validate button.

---

## Tips & best practices

- Keep property names consistent with your schema.  
- Localize early for all required languages.  
- Use a stable identifier (URL/URN).  
- Store the integrity hash for reference.

---

## Troubleshooting

- **Invalid JSON** → Check your schema file format.  
- **Validation fails** → Review required fields in the editor.  
- **Languages missing** → Select them before generating.  
- **Download disabled** → Generate first to enable saving.

---

✅ You can now transform a JSON Schema into a VC Type Metadata file and reuse it in your registry.
