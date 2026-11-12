# Browser extension deployment and verification

## Current implementation slice

The extension now uses a Manifest V3 background service worker for all backend requests, a managed-storage policy schema, a locally editable developer configuration, hostname normalization, and capture listeners for paste, file selection, drop, and form submission. Its packaged host access is generated from a destination allowlist and one backend origin. The service worker asks Chrome to restrict local and managed storage to trusted extension contexts. The local activity list contains only decisions, destination hostnames, and time.

## Backend authentication handoff still needed for the extension

The backend now requires a verified Supabase user bearer token on scan and scan-job routes, resolves the organization membership server-side, and ignores caller-supplied ownership fields. The extension currently stores a scoped managed API key and sends it as a bearer token; the backend does not yet resolve that API-key format. Before an authenticated extension integration test, add an API-key-to-principal adapter (or change the extension to obtain and refresh a Supabase user session) that:

1. Require a scoped, revocable API key in `Authorization: Bearer <key>`.
2. Resolve the authenticated user and organization from the key on the server; reject disabled, expired, or revoked keys with 401/403.
3. Accept the extension scan fields `channel`, normalized `destination`, `content`, and optional `filename`.
4. Apply the P2 policy gate and return the shared `ScanResult` shape.
5. Never log the key or raw request content. Record only masked evidence under the resolved tenant.
6. Apply the same authentication and principal resolution to `POST /scan-jobs`, `GET /scan-jobs/{id}`, and `DELETE /scan-jobs/{id}`. For extension uploads, accept multipart `file` and `destination` fields without caller-provided tenant/user IDs; owner-scoped status and cancellation must use the key-resolved principal.

Keep all scan routes inaccessible without authentication. The current user-token API routes enforce that requirement, but requests using the extension's managed API-key format will fail authentication until the adapter above is implemented. The extension can check backend `/health`, which is only a liveness check.

## Build a least-privilege package

Use Node.js 20+ and run from `dlp-extension`:

```powershell
node scripts/build.mjs --backend-origin https://dlp-api.example.com `
  --ai-host chatgpt.com --ai-host gemini.google.com --ai-host claude.ai `
  --ai-host copilot.microsoft.com --ai-host perplexity.ai --out dist
```

The build validates HTTPS for remote API origins (HTTP is allowed only for localhost development), rewrites both content-script matches and `host_permissions`, then packages the extension files into `dist`. Review `dist/manifest.json` before publishing; it should contain only approved AI hosts and the one API origin. Add a site to the build allowlist first, then enable it using the managed `aiSites` list. Runtime policy cannot cause script injection on a domain absent from the package. Changing host access changes the extension permission set, so republish through the normal enterprise approval process.

Create separate Chromium packages for Chrome and Edge with `--target chrome` and `--target edge`. Those builds use the MV3 service worker. A Firefox desktop package uses an event background script and needs the organization's stable extension ID:

```powershell
node scripts/build.mjs --target firefox --firefox-id dlp-guard@company.example `
  --backend-origin https://dlp-api.example.com --ai-host chatgpt.com `
  --ai-host gemini.google.com --ai-host claude.ai --out dist/firefox
```

Firefox builds target desktop Firefox 140+. Firefox does not use the Chrome `storage.managed_schema` manifest entry. For managed deployment, configure `storage.managed` through a Mozilla managed-storage JSON manifest or the `3rdparty` enterprise policy, using the exact `browser_specific_settings.gecko.id` as the policy name. Firefox may need a browser restart to pick up managed-storage changes. Test the signed package and policy on the organization's Firefox version before rollout. See the official [Mozilla background-script compatibility guide](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background), [managed-storage guide](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage/managed), and [Chrome managed-storage manifest guide](https://developer.chrome.com/docs/extensions/reference/manifest/storage).

Build a store-submission ZIP on Windows after generating a target folder: `powershell -ExecutionPolicy Bypass -File scripts/package.ps1 -Target chrome` (or `edge` / `firefox`). Review its SHA-256 hash and contents before upload. It is an unsigned source ZIP; store approval/signing, CRX/update hosting, and publication are organization-owned tasks and are not complete in this repo.

## Managed policy

`managed-schema.json` is bound through the manifest's `storage.managed_schema` value. Set policy for the installed extension with:

- `backendUrl`: the same HTTPS backend origin used to build the package.
- `apiKey`: a user/org scoped, revocable API key with only scan permission.
- `enabled`: `true` to turn on inspection.
- `failClosed`: organization decision when a backend response cannot be obtained.
- `aiSites`: monitored hostnames selected from those packaged in the extension.

Managed values override local unpacked-extension settings. Validate Chrome policy in `chrome://policy`. The key is never displayed in the extension options or sent to the page. Since an endpoint agent or local administrator can inspect extension policy on a managed device, avoid a tenant-wide service secret and rotate/revoke keys through P2's API-key service.

Example managed values (replace the endpoint and key using the organization's secret-delivery process):

```json
{
  "backendUrl": "https://dlp-api.example.com",
  "apiKey": "<scoped-revocable-key>",
  "enabled": true,
  "failClosed": true,
  "aiSites": ["chatgpt.com", "gemini.google.com", "claude.ai"]
}
```

### Permission rationale

| Permission | Why it is needed |
| --- | --- |
| `storage` | Read administrator-managed configuration and retain a short, non-sensitive local decision history. |
| AI-site host permissions | Run the scanner on configured AI sites and inspect paste/file/form content before submission. Generated only for the build's explicit host list. |
| DLP backend host permission | Let the background worker send authenticated scan requests to the single configured API origin. |

The manifest does not request `<all_urls>`, browsing-history access, clipboard read access, or page scripting APIs. Paste inspection reads the user-triggered paste event's text; file inspection reads the user-selected file content.

For force-installation, publish the package to the browser's approved extension store or the organization's signed update service, then use that browser's extension-management policy for the extension ID. Chrome's and Edge's force-install policy also needs a valid update source; a locally loaded unpacked folder is only for development. Edge uses its `ExtensionSettings` or force-list policy and requires an update URL for force-installed packages. See Microsoft's [Edge extension policy guide](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-manage-extensions-policies) and [ExtensionSettings reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/extensionsettings). Chrome policy configuration must be completed by the company's Chrome administrator before claiming a no-user-input install.

After the package is published, the Chrome `ExtensionSettings` policy entry has this shape (replace the ID and keep the chosen update source):

```json
{
  "<extension-id>": {
    "installation_mode": "force_installed",
    "update_url": "https://clients2.google.com/service/update2/crx"
  }
}
```

The example update URL is for a Chrome Web Store listing. Use the organization's update manifest if self-hosting; enterprise policy requires an actual published package and stable extension ID. Chrome administrators configure managed values against the extension's declared schema and verify them in `chrome://policy`. Chrome documents extension policies under `3rdparty/extensions/<extension-id>/policy`; Mozilla describes a separate managed-storage manifest / `3rdparty` route for Firefox. Do not put an API key into source control or the downloadable package. See Google's [extension policy configuration](https://support.google.com/chrome/a/answer/7532015) and [Chromium extension policy paths](https://www.chromium.org/administrators/configuring-policy-for-extensions/).

## Browser test checklist

Run after the extension API-key adapter is implemented and P4 provides seeded policies/incidents:

1. Load the generated package unpacked in a clean Chrome profile. Confirm `chrome://extensions` has no manifest or permissions error.
2. Confirm an unlisted host receives no content script; a packaged but policy-disabled AI host is allowed without a backend scan.
3. Configure a test managed policy and confirm settings are read-only and the extension works without user entry of IDs or keys.
4. Submit synthetic non-sensitive text and a synthetic PDF to each monitored AI site; confirm content passes only after a scan decision. The binary client streams to `/scan-jobs`, polls progress, and returns the strictest chunk decision.
5. Use a synthetic Luhn-valid card and confirm a blocking policy prevents paste, file-input upload, drop, and form submit. Confirm the event is visible in the dashboard with masked evidence.
6. Use a warning policy; confirm allow/cancel behavior. A justification dialog must not be marked complete until the override is recorded through P2's audited policy API.
7. Revoke the test key and confirm a clear administrator-facing message. Stop the backend and verify behavior for both `failClosed` values.
8. Test that key and raw seeded value do not appear in extension logs, browser console, network error text, or stored local activity.
9. Test service-worker suspension/wake, an iframe, shadow DOM, file size limit, extension reload, and site refresh.
10. Repeat on managed Chrome and Edge. Firefox uses a separate event-page manifest and still needs its own runtime/policy test pass before it can be claimed as supported.

## Current limits

- The backend scan and scan-job routes require a verified Supabase user bearer token and organization membership. The extension currently sends a managed API key, which the backend does not yet resolve, so authenticated extension end-to-end scanning is pending the API-key principal adapter described above.
- Small text-like files (`.txt`, `.csv`, `.json`, `.md`, `.log`) up to 5 MiB use the synchronous API. Binary, unsupported text formats, and larger files stream to the background worker and use asynchronous multipart `/scan-jobs`, capped at 25 MiB. The client is covered by a mocked transport test; the authenticated live API path is not yet verified.
- Warning uses a confirmation prompt; audited justification is pending the P2 override contract.
- Folder drag-and-drop is not recursively scanned yet. Fail-closed blocks a detected or unreadable directory entry; fail-open allows it with a banner. Directory selection through a browser file input is handled as individual exposed files.
- The browser currently intercepts form submit events, but AI apps that send content through custom JavaScript handlers without a submit event need app-specific test coverage.
- Chrome, Edge, and Firefox build targets and source ZIPs exist. Managed runtime tests, force-install/update policy verification, signing, and store publication remain incomplete.
