# Import VC Type — From File

**Audience:** Users who already have a **VC Type (VCT) Metadata JSON file** and want to add it to the registry.

---

## Purpose of this page

This form lets you **upload an existing `.json` VCT file** into the registry.  
The system computes a **sha256 integrity hash** for the file, stores it under your account, and (optionally) publishes it to the public catalog.

---

## Fields in the form

### 1. VC type name (required)
- Friendly name of the VCT for display in the registry.  
- If not filled, the tool tries to extract a name from the file (`name`, `display[]`, `schema.title`, or filename).

### 2. VC type description (required)
- Human-readable description.  
- If not filled, the tool tries to extract it from the file (`description`, `display[]`, `schema.description`).

### 3. File upload
- Drag & drop or choose a **`.json`** file.  
- Must be valid JSON and follow the VCT structure (with at least `vct` and `display[]` or `schema`).

### 4. Publish after upload
- Checkbox enabled by default.  
- If checked, the VCT becomes part of the **public catalog** immediately.  
- If unchecked, the VCT remains private and visible only to you.

---

## Actions

- **Upload** — Validate the file, compute integrity, and store it.  
- If name/description are missing, the system asks you to fill them manually.  
- Once uploaded, status is displayed:
  - “Added and published ✓” (if public)  
  - “Added ✓” (if private)

---

## What happens during upload

- The tool parses the JSON.  
- Extracts `name` and `description` if possible.  
- Computes an **integrity hash** (`sha256-…`) to ensure the file’s identity.  
- Saves the file in your registry space.  
- Publishes to catalog if the option is checked.

---

## Tips & Best Practices

- Always include **name** and **description** in your VCT for easier discovery.  
- Keep your JSON valid — use an external validator if needed.  
- Leave **Publish after upload** unchecked if you’re still drafting.  
- Re-uploading the same file updates its entry (with a new integrity hash).  
- Copy the integrity string when referencing the VCT in production.

---

## Troubleshooting

- **“Invalid JSON”** → The file isn’t valid JSON. Open in a JSON editor and fix errors.  
- **“Missing name or description”** → Fill both fields manually before uploading.  
- **Upload fails** → Check your internet connection or server status.  
- **File accepted but not visible** → Switch scope in the Manage Registry page to “My VCTs” or “All”.

---

✅ You now have your VCT imported into the registry — either private (draft) or public (shared with everyone).
