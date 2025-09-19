# VCT Registry — Upload, Catalog & Search

**Audience:** End‑users who upload and manage **VC Type (VCT) metadata** via the web page.  
**Last updated:** 2025-09-17

> This guide explains what the **VCT Registry** is, how to **upload** a VCT Type Metadata JSON, and how to **browse, search (keyword/AI), rate, and download** VCTs from the catalog. It’s designed for users filling the on‑page form (no API knowledge needed).

---

## 1) What is the VCT Registry?

The **VCT Registry** is a shared catalog for **VC Type (VCT) metadata**. It lets you:

- **Upload** your VCT Type Metadata JSON.
- Keep it **Private** (visible only to you) or **Publish** it so everyone on the platform can find and reuse it.
- **Browse & search** the catalog (keyword or AI‑assisted).
- **Rate** entries and see **popularity** (how often a type is used).
- **Download** either the **full VCT** or **schema only**, and **copy** the VCT’s stable link and integrity value for verification.

Every published VCT has a **stable link** (VCT URL) so others can reference exactly the type you shared.

---

## 2) Quick Start (2 minutes)

1. Open **VC Type Registry** from the menu.  
2. Drag your **VCT JSON** file to the **Drop area**, or click **Choose file**.  
3. The page auto‑fills **Name** and **Description** when it can (see rules below). If either remains empty, you must fill it manually before uploading.  
4. (Optional) Tick **Publish after upload** to share it publicly.  
5. Click **Upload**.  
6. Find your row in the **Catalog** table. Use **Actions** to **Download**, **Copy VCT URL**, **Copy integrity**, or change **Visibility**.

> **Tip:** Use the **Scope** selector to switch between **My VCTs**, **Public Catalog**, or **All**.

---

## 3) Name & Description — required

**Name** and **Description are required** to upload an entry into the registry.

When you select a file, the page tries to auto‑fill these fields from your JSON in the following order:

1. **Root fields**  
   - `name` → **Name**  
   - `description` → **Description**
2. **display** (object, or the first item if `display` is an array)  
   - `display.name` → **Name**  
   - `display.description` → **Description**
3. **schema** (JSON Schema metadata)  
   - `schema.title` → **Name**  
   - `schema.description` → **Description**

If **either** field cannot be found from the file, the page will prompt you to **fill it manually** before allowing the upload.  
The JSON that is ultimately uploaded will include the **name** and **description** as shown in the form (auto‑filled or provided by you).

### Examples that auto‑fill correctly

```json
{
  "vct": "https://example.org/vct/person",
  "name": "Person Identity",
  "description": "A generic identity credential type for persons.",
  "schema": {
    "$id": "https://example.org/schema/person.json",
    "title": "Person Identity",
    "description": "Schema describing the person identity credential."
  }
}
```

```json
{
  "vct": "urn:vct:eu:education:diploma",
  "display": [
    {
      "name": "Diploma",
      "description": "Higher‑education diploma credential."
    }
  ],
  "schema": { "$id": "urn:example:schema:diploma" }
}
```

---

## 4) Catalog — browsing & search

### Scope
Choose what to list:
- **My VCTs** — only your uploads (private or public).  
- **Public Catalog** — everyone’s published VCTs.  
- **All** — your items + all public items.

### Keyword search
Type words like `address`, `diploma`, `given_name`.  
The search looks at the VCT’s name, keywords, schema property names, and claims paths.

### AI search (optional)
Toggle **Use AI search** to get semantic results based on your description (e.g., “EU person identity with given name and birth date”).  
If AI isn’t configured, the page automatically falls back to keyword + popularity ranking.

---

## 5) Understanding popularity & ratings

Each row shows:
- **Stars** — average rating (click stars to submit your rating 1–5).  
- **Ratings** — how many users rated it.  
- **Calls** — how often the VCT is used (downloads and public resolves).

These help you quickly spot **popular** and **well‑rated** types.

---

## 6) Actions you can take on each VCT

- **Download VCT** — saves the full JSON file of that catalog entry.
- **Schema only** — saves just the JSON Schema; it also includes a note of the VCT and integrity for easy pinning.
- **Copy VCT URL** — copies the stable link for the published VCT.
- **Copy integrity** — copies a `sha256-…` value that pins the exact content you uploaded.
- **Visibility** — switch between **Private** and **Public** whenever you want (only for your own items).
- **Delete** — remove your entry (only for your own items).

> **Clipboard note:** Some browsers restrict clipboard access on non‑HTTPS pages. The site uses a safe fallback; if you see a prompt, allow copying.

---

## 7) Integrity — what it is and why it matters

When you upload a file, the page computes a **Subresource Integrity (SRI)** value:
```
sha256-<base64(SHA-256 of the JSON file)>
```
This lets others **verify** they are using the same content you published.  
When you **Download** or choose **Schema only**, you can also **Copy integrity** to share alongside the VCT URL.

---

## 8) Best practices

- Use a **stable `vct`** you control (URL or URN).  
- Keep the **name** short and the **description** clear.  
- Prefer **consistent property names** in your schema (e.g., `given_name`, `birthdate`, `address_line_1`).  
- Add useful **keywords** so search and AI can find your type more easily.  
- When changing a public VCT, consider **versioning** rather than breaking changes.  
- Rate the types you like — it helps the community discover high‑quality entries.

---

## 9) Troubleshooting

- **“Name/Description required”** — Your file didn’t contain those fields in any of the supported locations. Fill them in the form and retry.  
- **“Invalid JSON”** — Make sure the file is valid JSON and uses a `.json` extension.  
- **“Duplicate integrity”** — The exact same content was already uploaded; update your content or version.  
- **Upload shows “failed”** — You must be signed in; please login and retry.  
- **Copy buttons don’t work** — Allow clipboard access or use HTTPS; the page includes a fallback method.  
- **Can’t find my entry** — Check the **Scope** (e.g., “My VCTs”) and clear the search box.  
- **Not visible to others** — Ensure the row’s **Visibility** is set to **Public**.

---

If you need more help, use the **“Explain ?”** link in the header or contact support with the exact status message shown under the upload area.
