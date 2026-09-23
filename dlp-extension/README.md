# DLP Guard — Browser Extension

Chrome (Manifest V3) extension implementing the "Channel — Browser Extension"
component from the architecture doc. Intercepts paste events and file
uploads on any page, calls the DLP backend's `/api/scan`, and blocks/warns
per its decision.

## Load it

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select this `dlp-extension/` folder
4. Click the extension icon → **Configure backend & org** and fill in:
   - Backend URL (`http://localhost:8000` if running the FastAPI backend locally)
   - Organization ID (the `org_id` from your Supabase `organizations` table — sign into the dashboard once and copy it from `org_members`)
   - User ID (your Supabase auth user id)
5. **Test connection** in the options page should return `{"status": "ok"}`.

## Try it

On any page with a text field, paste something like:

```
here is my card 4111 1111 1111 1111
```

With the default policy set (or none at all — the policy engine fails open
to WARN when no policy matches), you should see a warning or block banner
instead of the text landing in the field. Check the extension popup for a
running log of recent decisions.

## Scope limits (matches architecture doc §8)

- Only text-like file uploads (`.txt .csv .json .md .log`) are content-scanned. Binary files (images, PDFs, zips) pass through unscanned in v1.
- No enforcement on drag-and-drop file uploads yet — only the native file input's `change` event and clipboard paste are covered.
- Backend-unreachable failures **fail open** (allow) rather than blocking every page — a DLP extension that breaks the internet when the backend is down is worse than one with gaps. This is visible in the popup's activity log as `allow` with an "unreachable" reason.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 config, permissions, content script registration |
| `content.js` | Runs on every page — intercepts paste/upload, shows banners |
| `background.js` | Service worker — the only place that calls the backend |
| `options.html/js` | Backend URL + org/user config, connection test |
| `popup.html/js` | Toolbar popup — on/off toggle, recent activity |
