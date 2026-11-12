# P11 security notes

## OIDC transaction and token controls

- State and nonce are cryptographically random. State is bound to a signed, five-minute, HttpOnly, Secure, `__Host-` browser cookie; server-side transaction state and nonce are stored as SHA-256 digests and consumed once.
- PKCE uses S256; the verifier is protected in the signed browser cookie and is not persisted in plaintext in the database.
- ID tokens are accepted only with RS256 or ES256 and a matching JWKS key. PyJWT verifies signature, issuer, audience, expiration, issued-at, and required claims. The nonce and `email_verified=true` are required. Multi-audience tokens require matching `azp`.
- JWKS keys are cached for five minutes, refreshed on an unknown key ID, and unknown-key refresh is rate-limited per JWKS URL.

## Provider URL and network controls

Issuer and discovered endpoints must use HTTPS, default/443 port, have no URL credentials or fragment, and resolve only to globally routable addresses. Literal IPs, loopback/local names, `.local`, `.internal`, and redirects are rejected. Requests disable environment proxies, use bounded timeouts and response sizes, and do not follow redirects. The HTTP client pins its TLS connection to the public IP address returned by DNS validation while verifying the configured hostname in TLS, preventing DNS rebinding between validation and connection. Deployment network egress controls remain useful defense in depth.

## SAML controls

The implementation delegates XML parsing and signature verification to `python3-saml`/`xmlsec`; strict mode is enabled, assertions must be signed, and the trusted certificate comes from the tenant's Vault reference. The SP validates issuer, audience, destination, recipient, time constraints, and request correlation. Assertion IDs are stored for replay rejection. The ACS limits URL-encoded request size and rejects repeated form fields. Failure responses do not include XML, certificate, or toolkit diagnostics.

## Identity and tenant safety

Provider secrets and certificates are not returned by APIs or stored in SSO configuration JSON; rows contain only tenant-bound Vault IDs. External identity keys include organization, provider config, issuer, and subject. Verified email plus an administrator-claimed domain is the documented first-login trust assumption. New members receive viewer; existing roles are loaded from the member record. Provider group/role claims are ignored. Manual account links require owner/admin authorization and a same-tenant member.

RLS is forced on all P11 tables. Config and identity policies require matching `org_id` plus owner/admin role. Transaction and replay tables have no authenticated role grants or policies and are intended for the trusted server database role. Real PostgreSQL isolation tests are required before release.

## Secrets, audit, and failures

Audit events contain action, result, provider config/member identifiers, and normal request context; tokens, codes, assertions, and secret values are not audit metadata. Callback errors are normalized to a generic frontend failure and failed-login events are recorded when an enabled provider is identifiable. Access tokens are short-lived (15 minutes), use a distinct secret, and appear only in the URL fragment until the frontend removes it.

## Temporary design and known limits

The P11 callback transaction cookie and 15-minute bearer token bridge are deliberately narrower than a browser session system. P13 owns session lifecycle, revocation, IP allowlists, multi-organization switching, and identity administration. SSO configuration and callback route integration use the existing PostgreSQL application service role, while authenticated RLS behavior is independently exercised under the `authenticated` role.
