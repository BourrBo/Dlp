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
   - Supabase Project URL and **publishable** key (the same public values used by the frontend; never use a service-role key)
   - Organization ID to scan (the backend verifies membership for this organization against the authenticated account)
   - Sign in with your existing Supabase account email and password
5. **Test connection** in the options page should return `{"status": "ok"}`.
6. The extension stores the short-lived access token and refresh token in extension-local storage, refreshes the session as needed, and never stores the password. Sign out from settings to remove the saved session.
7. Pastes and uploads are blocked when authentication or scanning fails or returns an invalid result.

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
- Backend failures, rejected authentication, invalid scan responses, and extension messaging failures block pastes and uploads. The popup activity log records the decision.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 config, permissions, content script registration |
| `content.js` | Runs on every page — intercepts paste/upload, shows banners |
| `background.js` | Service worker — the only place that calls the backend |
| `options.html/js` | Backend/Supabase public config, account sign-in, and connection test |
| `popup.html/js` | Toolbar popup — on/off toggle, recent activity |
