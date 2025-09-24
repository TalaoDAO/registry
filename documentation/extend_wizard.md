# Extend VC Type

**Audience:** Users who already have a base VC Type Metadata (VCT) and want to create an **extension** that overrides labels or adds new claims, while inheriting the rest. The page follows the same wide-card layout and concise UX style as the “Create from Scratch” documentation.

---

## Purpose of this page

This wizard lets you **pick an existing VCT as a base**, then **override claim display** (per language) and **add new claims**. The output is a new VCT JSON that references the base via `extends`, keeping your delta small and maintainable.

---

## Quick Start (2 minutes)

1. Click **Select Base VCT** and choose a public VCT from the picker.  
2. (Optional) In **Overrides**, click **Override…** on any claim to change its label per language.  
3. (Optional) In **Add a new claim**, enter a **path**, **label**, and **lang**, then **+ Add**.  
4. Provide **New VCT name** and **description**.  
5. Click **Generate Extended VCT**, review the JSON, then **Save to Desktop** or **Upload to Registry**.

---

## Step-by-Step

### 1) Choose the base VCT
- Use **Select Base VCT** to open the picker. You can **search** (name, keywords, properties) and **sort** (Newest, Name, Rating, Calls, Popularity). Pick one with **Select**.  
- The wizard loads the base, shows its friendly name, and enables the next steps.

**What’s inherited?**  
The base VCT’s claim metadata is read and displayed in a table. You’ll only materialize changes you make—everything else stays inherited from the base.

---

### 2) Override claim display (optional)
- In **Overrides**, click **Override…** for any claim path to change labels per language.  
- You’ll be prompted for a **language code** (e.g., `en`) and a **new label**. The wizard tracks your overrides and highlights progress.

**Tip:** You can add multiple languages for the same claim (repeat **Override…** with another language code).

---

### 3) Add new claims (optional)
- In **Add a new claim**, specify:
  - **Path** — e.g., `nationalities` or `address.city`  
  - **Display label** — human-friendly label  
  - **lang** — BCP-47 code (default `en`)  
- Click **+ Add**. The claim is queued and listed; you can add more or update labels for other languages by reusing the same path.

---

### 4) Name, description, and generation
- Enter **New VCT name** and **description** (both required).  
- Click **Generate Extended VCT**. The editor shows the **resulting JSON**:
  - `extends` points to the base VCT (the wizard also captures base integrity from response headers when available).  
  - `claims` contains only your **overrides** and **new claims**.  
  - A draft `vct` identifier is generated automatically (you can edit it in the editor).

---

## Editor & actions

- **Editable JSON** — Review and refine directly in the built-in editor.  
- **Save to Desktop** — Downloads your extended VCT as a JSON file.  
- **Upload to Registry** — Publishes the VCT. On success, a modal shows **VCT URL**, **Integrity (SRI)**, and **VCT URN**, with an option to **Open VCT**.

---

## Practical recipes

- **Localize labels**: Use **Override…** to add localized labels for high-traffic claims (e.g., `en`, `bg`, `ro`, `el`).  
- **Add a property without touching the base**: Use **Add a new claim** with a dotted path (e.g., `employment.startDate`).  
- **Keep your delta minimal**: Only override what you must; everything else stays inherited via `extends`.

---

## Tips & best practices

- Start by selecting the most accurate **base VCT** to minimize edits.  
- Prefer **language-specific overrides** to maintain clean, localized displays.  
- Use clear, stable **claim paths** (dotted notation for nested fields).  
- Generate, skim the diff in the editor, then **save** or **upload**. Keep a local copy for versioning.

---

## Troubleshooting

- **“Generate Extended VCT” is disabled** → Ensure a **base** is selected and both **name** and **description** are filled.  
- **Nothing appears in Overrides** → Your base might have no explicit `claims` metadata; you can still **add new claims**.  
- **Upload succeeded but no modal** → The wizard shows the success modal for public uploads; verify your registry response or publication status.

---

✅ You can now extend an existing VCT, override only what you need, add new claims, and publish—using the same clean, consistent UX style as the rest of the documentation.
