# GitHub App integration (P3 W15–17)

## Current implementation state

The backend has security primitives for signing GitHub App JWTs, validating
`X-Hub-Signature-256`, and exchanging a JWT for a repository-scoped
installation token. Five unit tests cover signature verification, claim timing,
RS256 verification, least-privilege permissions, repository scoping, and
sanitized API failures.

The repository working-tree service is implemented; details and limits are in
`repository-scanning.md`. The signed `/webhooks/github` route is mounted and
stores only allowlisted delivery metadata in a durable SQLite queue. Install and
uninstall routes, P2 integration records and vault retrieval, the queue consumer,
repository list UI, and a live GitHub App test are still pending. Do not connect
a live installation until the P2 identity/vault handoff and queue consumer are
in place; signed push events are queued but do not yet trigger scans or P4
incidents.

Set `GITHUB_WEBHOOK_SECRET` in the backend's environment (or `.env` when using
the repository Compose setup). The endpoint returns HTTP 503 when this secret is
not configured. Keep it out of source control and frontend configuration.

## Credential and identity boundary

- The app client ID is an identifier, not a secret. The private key must be
  retrieved through P2's credential vault and passed to the service call in
  memory. This code does not read or persist a private key.
- Installation tokens are short-lived secrets. The caller must store them in
  P2's vault; the token model hides its value from `repr` and errors do not
  include GitHub response bodies.
- Bind every installation to an authenticated DLP organization before it can
  be listed or scanned. P2 owns principal resolution, tenant authorization,
  vault storage, and the `dlp_integrations` contract. P3 must not accept an org
  ID from an unauthenticated browser request.
- The install URL flow needs a random, single-use state value bound to the
  signed-in principal and organization. Never put a credential or access token
  in a URL.

## App settings to create when the routes are ready

Use a GitHub App with the P3 plan's minimal permissions: repository contents
read, metadata read, and checks write. Subscribe to the installation,
installation-repositories, and push events needed by the install lifecycle and
repository scanner. Store the app client ID, private key, and webhook secret
using the approved secret-delivery process. Point the webhook at the deployed
backend's `/webhooks/github` route only after it is implemented and tested.

The current JWT builder uses RS256 with `iat` 60 seconds in the past and a
default expiration 540 seconds in the future. GitHub limits app JWTs to ten
minutes; the 60-second allowance keeps the full issued-to-expiry span at ten
minutes. Installation-token requests default to `contents: read`,
`metadata: read`, and `checks: write`, and can be narrowed to selected repository
IDs. These claims and endpoints follow [GitHub's JWT guidance](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app) and [installation-token API](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app).

## Webhook requirements before enabling delivery

The route reads at most 2 MiB, verifies the SHA-256 HMAC before JSON parsing,
rejects invalid signatures with HTTP 401, validates delivery metadata, and
durably deduplicates by both GitHub delivery ID and a fingerprint of the
verified signature. It stores no raw payload or commit messages. The SQLite
queue is capped at 10,000 pending deliveries and requeues in-flight work after
restart. GitHub retries with HTTP 503 if the queue cannot accept an event.
Payloads, signatures, JWTs, and installation tokens must never be logged. Queue
consumption, repository scans, and P4 incident creation remain to be connected
before claiming the W21 push-to-incident exit test.

## Verification

Run `python -m unittest tests.test_github_app tests.test_github_webhooks -v`
from `dlp-backend/` for the cryptographic, webhook, and mocked HTTP contract
tests. The complete backend suite currently has 68 passing tests in Docker. A
live install/uninstall test still requires the P2 vault/auth handoff and a
registered test GitHub App.
