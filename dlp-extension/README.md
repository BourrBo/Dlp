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
6. Optionally enable **Block when backend is unavailable** for a fail-closed posture. It is off by default.

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

- Clipboard paste, native file selection, and file drag-and-drop are intercepted. For allowed file selections, the extension dispatches a new `change` event after scanning so page upload handlers run only after the decision.
- `.txt`, `.csv`, `.json`, `.md`, and `.log` files are scanned up to 5 MB each. Unsupported binary formats are reported as not scanned and pass through; PDF/DOCX support depends on a future backend extraction endpoint.
- If the extension is reloaded while a page remains open, that stale page context cannot scan. It shows a banner asking the user to refresh.
- Backend-unavailable behavior is configurable: fail open by default, or block when enabled in Settings. The popup activity log records the decision.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 config, permissions, content script registration |
| `content.js` | Runs on every page — intercepts paste/upload, shows banners |
| `background.js` | Service worker — the only place that calls the backend |
| `options.html/js` | Backend URL + org/user config, connection test |
| `popup.html/js` | Toolbar popup — on/off toggle, recent activity |
