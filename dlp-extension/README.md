# DLP Guard browser extension

Manifest V3 browser collector for configured AI destinations. The extension sends scans from paste, file input, drag-and-drop, and form submission through its background worker. Page scripts never receive the API key.

## Local developer preview

1. Build a local Chrome package: `node scripts/build.mjs --target chrome --out dist/chrome`.
2. Start the DLP backend at `http://localhost:8000`.
3. Open `chrome://extensions`, enable Developer mode, and load `dlp-extension/dist` unpacked.
4. Open the extension settings and enter a development API key only after the backend API-key contract is available.
5. Test the backend connection, then visit a packaged AI destination and try a synthetic card number.

The backend now requires a verified Supabase user bearer token and checks organization membership. This extension sends a managed, scoped DLP API key instead, and the backend does not yet verify that key or resolve its principal. The extension therefore cannot complete a live scan yet. Do not enter a service-role key here or expose the extension until the scoped API-key adapter is integrated.

## Managed enterprise configuration

Chrome policy uses the schema in `managed-schema.json`, with these managed values:

| Key | Type | Purpose |
| --- | --- | --- |
| `backendUrl` | string | DLP API origin |
| `apiKey` | string | Scoped/revocable DLP key; supplied by policy, not page code |
| `enabled` | boolean | Enable or disable browser inspection |
| `failClosed` | boolean | Block when the DLP service cannot return a decision |
| `aiSites` | array of strings | Admin-managed monitored AI hostnames |

Managed values override locally saved developer settings. Local settings use `chrome.storage.local`, not sync storage. The options page never displays an existing key. The service worker adds it only to authenticated backend requests and does not include organization/user IDs in the body.

Build with the exact customer backend and destination allowlist so host permissions stay narrow:

```powershell
node scripts/build.mjs --backend-origin https://dlp-api.example.com `
  --ai-host chatgpt.com --ai-host gemini.google.com --ai-host claude.ai `
  --ai-host copilot.microsoft.com --ai-host perplexity.ai --out dist
```

The extension package injects only on these HTTPS hosts and their subdomains. `aiSites` can further limit the packaged hosts at runtime; adding a hostname in policy alone does not inject a content script on a host absent from the build. The package grants backend access only to the configured backend origin. For localhost development, HTTP is allowed only for `localhost`, `127.0.0.1`, or `::1`.

The managed API key is readable by authorized local administrators and extension code running in the extension context. Use a scoped, revocable key and device-management policy; do not distribute a shared service-role secret.

Separate desktop builds are available for Microsoft Edge and Firefox. Use `--target edge` for Chromium Edge. Firefox uses an event page and needs a stable extension ID: `node scripts/build.mjs --target firefox --firefox-id dlp-guard@company.example --backend-origin https://dlp-api.example.com --ai-host chatgpt.com --out dist/firefox`. Firefox managed settings require Mozilla's native managed-storage manifest or `3rdparty` policy; the Chrome `managed_schema` manifest entry is removed from that Firefox package. See `../docs/extension.md` for deployment details.

On Windows, create a store submission ZIP after building: `powershell -ExecutionPolicy Bypass -File scripts/package.ps1 -Target chrome` (use `edge` or `firefox` for the other package). This ZIP is the source package for a browser-store submission. Store review/signing and enterprise update hosting still require the organization's browser-store accounts or update service.

## Behavior and limits

- Hosts are lowercased, IDNs use the browser's URL normalization, and leading `www.` is removed. A configured host matches itself and its subdomains, not a lookalike suffix.
- Warn uses a browser confirmation prompt in this core slice. A justification prompt and an audited override endpoint depend on P2's policy/override contract.
- Small `.txt`, `.csv`, `.json`, `.md`, and `.log` files (up to 5 MiB) use the synchronous route. Binary, other text formats, and larger files (up to 25 MiB) stream through the background worker to `/scan-jobs`; its scoped API-key identity handoff is still pending.
- The content script cannot inspect content inside cross-origin frames unless that frame's site is included in the build and the browser grants the corresponding host permission. Shadow DOM and incognito coverage still require browser-matrix verification.
- Folder drops are detected through the browser's file-entry API. Because recursive folder scanning is not implemented yet, fail-closed mode blocks them; fail-open mode lets them through with a banner. Selecting a directory through a supported file input scans the exposed files individually.
- The service worker is stateless between requests; local recent activity stores decisions and destination only, never submitted text or finding snippets.
- If the backend denies or cannot reach the configured API, behavior follows `failClosed`; revoked keys show a clear administrator-facing error.

## Tests

Run `node --test tests/*.test.js` from this directory. Before publishing a customer package, install it through the target browser's enterprise policy and complete the checklist in `../docs/extension.md`.
