# P08 — Policy and access UI

## Scope and architecture

P08 adds a standalone React 19, TypeScript, and Vite frontend in `frontend/`. P01–P07
backend code and migrations were not changed. The app uses a small local component
layer and CSS; it introduces no router or global state framework. Navigation changes
the active view in memory.

The sidebar provides Policies, Destinations, Exceptions, Suppressions, Sandbox,
Approvals, Actions, and Access & settings. These are policy administration and access
views, not findings or incident dashboards.

## API integration

`src/api.ts` centralizes the `/api` base path, bearer header, omitted browser
credentials, redirect rejection, 204 handling, safe status-specific errors, and
unauthorized-session expiry. Vite strips `/api` and proxies to the local FastAPI
service (`VITE_API_PROXY_TARGET` can change its origin). It uses the P01–P07 contracts:

- `/auth/me`
- `/policies`, `/policies/{id}`, `/policies/{id}/versions`, `/policies/{id}/diff`,
  `/policies/{id}/rollback`, `/policies/test`, and historical version test
- `/destinations`
- `/exceptions`
- `/suppressions`
- `/approvals`, `/approvals/{id}/approve`, `/reject`, `/cancel`, and `/actions`

No tenant identifier is accepted as UI input. Tenant and role context is taken from
`/auth/me`; the API authorizes all protected operations.

## Workflows

- **Policies:** list, inspect conditions/actions and active version, create/edit,
  enable/disable, browse versions, compare backend diffs, and roll back after a
  contextual confirmation.
- **Destinations:** list and manage the existing destination records, with a
  consequence-specific removal confirmation.
- **Exceptions:** list/create/edit, inspect policy scope and expiry, and revoke after
  confirmation. Expired, expiring-soon, active, and revoked states include text.
- **Suppressions:** list/create/edit, inspect match/reason/expiry, and revoke after
  confirmation.
- **Sandbox:** evaluate the selected policy or historical version using generated
  synthetic content and metadata. Results are explicitly marked `SIMULATION RESULT`;
  no production scan or external side effect is invoked.
- **Approvals/actions:** inspect approvals and action records, expose approve/reject
  only to an owner/admin with `approvals:decide`, and confirm state transitions.
  `pending_executor` remains visibly pending and is not reported as successful.
- **Access & settings:** display verified subject, organization, role, actor type,
  authentication method, and scopes. User administration, API key creation, SSO,
  SCIM, organization switching, and writable settings are not present because those
  are not available in the P02/P08 UI contract.

## Authentication and security

P02 exposes identity verification (`/auth/me`) but no interactive login or browser
session issuer. The connection screen therefore accepts a token from an existing
authenticated session, checks it with `/auth/me`, and stores it only in React memory
for the current tab. It is not written to local/session storage, cookies, or URLs.
Sign-out and any 401 clear it. No token, secret, or raw scan content is logged.

The sandbox sends generated synthetic content only; user-provided sensitive content
is not requested. API errors are mapped to safe messages without rendering response
details. UI capability checks are convenience only; P02/P05/P06/P07 API authorization
remains authoritative. High-impact transitions use contextual confirmation dialogs.

## Accessibility and responsive behavior

Inputs have labels; actions use native buttons; navigation has an accessible label;
dialogs use dialog semantics; keyboard focus is visible; status text does not depend on
color. Layout CSS has narrow-screen breakpoints and horizontal overflow for wide data
tables. Browser review at 1366×768 and 390×844 confirmed no document-level horizontal
overflow; the mobile navigation remains horizontally scrollable.

## P09 handoff

P09 may add secret-vault API/UI boundaries separately. P08 does not store or retrieve
API-key plaintext, does not add a vault substitute, and does not expose token values
after the in-memory connection step. Any later secret creation flow must follow the
existing P02 one-time-secret response contract and avoid later retrieval.

## Known limitations

- There is no P02 login/session issuance UI; users need an existing bearer token.
- Access & settings is intentionally read-only because current P02 endpoints provide
  identity inspection but no organization/user settings API.
- The source P2 roadmap calls for five main P08 areas; Approvals and Actions were also
  added because the supplied P08 execution prompt explicitly includes P07 workflows.
- No P4 design kit was present, so the app uses a small self-contained component layer.
