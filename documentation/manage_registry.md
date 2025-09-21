# Manage VC Types (Platform Guide)

**Audience:** users of the platform.  
This guide explains how to use the **Manage VC Types** page (`manage_registry.html`) to browse, search, and manage your own or public **VC Type Metadata (VCTs)**. Everything happens in the web interface — no API knowledge needed.

---

## What you’ll do on this page

- **Browse your own VCTs** (private or public).  
- **Explore the public catalog** of VCTs shared by others.  
- **Search** by keyword or description (with optional AI assistance).  
- **Rate** and see popularity of VCTs.  
- **Take actions**: download, copy VCT URL, copy integrity, change visibility, delete.

---

## Quick Start (2 minutes)

1. Open **Manage your VC Types** from the main menu.  
2. At the top, use the **Scope selector**:
   - **My VCTs** → only your entries.  
   - **Public Catalog** → VCTs published by everyone.  
   - **Private** → only your private entries.  
   - **All** (admins only) → everything.  
3. Type in the **Search bar** or toggle **Use AI search** for semantic results.  
4. Review results in the **Catalog table**.  
5. Use the **Actions column** to download, copy, change visibility, or delete.

---

## Step-by-Step: working with the Catalog

### 1) Scope selector
Choose what to display:
- **My VCTs** → your own uploads.  
- **Public Catalog** → shared VCTs.  
- **Private** → private only (AI search disabled for this).  
- **All** → everything (admins only).

### 2) Search & AI toggle
- **Keyword search** looks into names, descriptions, schema property names, and claims.  
- **AI search** (when enabled) lets you type natural descriptions like “EU identity with given name and birth date”.  
- If AI isn’t available or fails, the system falls back to keyword search.

### 3) Catalog table
Each row shows:
- **Name** — clickable link to the VCT URL.  
- **Description** — from the JSON or entered manually.  
- **Languages** — badges for supported locales.  
- **Popularity** — average rating, number of ratings, and call count.  
- **Visible** — shows whether the VCT is Public or Private (you can toggle your own entries).  
- **Actions** — buttons to download, copy, or delete.

### 4) Actions available
- **Download VCT** — full JSON file.  
- **Schema only** — JSON Schema plus VCT/integrity note.  
- **Copy VCT URL** — stable link for reference.  
- **Copy integrity** — SHA-256 hash (SRI) for content pinning.  
- **Visibility** — switch Public/Private (only on your entries).  
- **Delete** — remove your entry (only on your entries).  
- **Rate** — click stars to rate (1–5).  

---

## Result overview

Using this page you don’t produce a new file; instead you **manage existing entries**.  
The main results are:
- A clear view of your own VCTs and community-shared ones.  
- Direct downloads of JSON or schema.  
- Stable links and integrity values you can share.  
- Ratings and popularity indicators.

---

## Practical recipes

- **Find your own VCTs** → choose **My VCTs** scope.  
- **Discover community VCTs** → choose **Public Catalog**.  
- **Check which types are popular** → look at ratings and call counts.  
- **Switch a draft to public** → change **Visibility** to Public.  
- **Remove outdated versions** → use **Delete** on your own entries.  
- **Reuse a schema** → download **Schema only**.

---

## Tips & best practices

- Keep your **Name** and **Description** concise and accurate.  
- Use **keywords** in your metadata so others can find your type.  
- Switch to **Public** only when the VCT is stable.  
- Ratings help the community: leave stars when you try others’ VCTs.  
- Copy the **integrity hash** when referencing a type in production systems.

---

## Troubleshooting

- **Search finds nothing** → clear the box, reset filters, or check Scope.  
- **AI toggle disabled** → not available for “Private” scope or if server doesn’t support it.  
- **Visibility button disabled** → you can only change your own entries.  
- **Copy buttons don’t work** → allow clipboard access or use HTTPS.  
- **Upload missing** → To add new entries, go through the **Generate** flows (Issuer/Schema/Scratch) then return here.

---

## Where to get help

- On the page header, click **“Explain ?”** to open this guide.  
- For support, provide the VCT identifier and the error message shown in the table.

---

**You’re done!** You can now search, rate, and manage your Verifiable Credential Types directly from the registry.
