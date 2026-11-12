# P09 Secret Vault

## Design

P09 adds tenant-owned application secrets protected with AES-256-GCM from the
existing `cryptography` dependency. `SecretVault` uses an `EncryptionProvider`
and a versioned `KeyProvider`; the supplied environment provider is intended for
local development and can be replaced with a KMS/HSM adapter without changing
the vault service. The environment keyring is configured with a standard
Base64-encoded 32-byte active key and optional previous keys keyed by version.
No key material is stored in PostgreSQL.

Each encryption uses a cryptographically random 96-bit nonce. AES-GCM's
authentication tag is stored in the ciphertext. Associated data binds the
ciphertext to the tenant, opaque record ID, logical name, and type. A key
version is stored with each record so callers can retain old keys while
re-encrypting records with `SecretVault.rotate`.

The `dlp_vault_secrets` table stores only ciphertext, nonce, key version, and
non-secret metadata. PostgreSQL RLS is enabled and forced, with authenticated
tenant policies for select/insert/update/delete. Application permissions are
checked independently by `SecretVault`; the database policy remains the
tenant boundary if an application query omits its organization filter.

## API and authorization

`/vault/secrets` supports secure create, metadata listing, metadata detail,
replacement, and soft-disable. Responses contain no secret values and use
`Cache-Control: no-store`. Validation errors are generic so submitted values
are not reflected in error responses. Plaintext retrieval is available only
through the Python-internal `SecretVault.get` interface, requiring
`vault:use`; no HTTP plaintext retrieval endpoint exists.

Owners receive all vault capabilities. Admins can read metadata, write, and
disable secrets, but cannot retrieve plaintext. Analyst, Viewer, and Auditor
roles receive no vault capabilities. API-key scopes use the same closed
permission vocabulary and remain constrained by the caller's role.

Delete is a soft-disable: the ciphertext remains in the database and backups.
This does not claim cryptographic erasure. Expired secrets cannot be retrieved
or reported as existing, though metadata remains available for management.

## Configuration and operations

The vault is disabled unless `DLP_VAULT_ENABLED=true`. When enabled, provide
`DLP_VAULT_MASTER_KEY` as Base64 for exactly 32 random bytes and set
`DLP_VAULT_ACTIVE_KEY_VERSION` to a positive integer. During rotation, make the
new key active and retain older keys in `DLP_VAULT_PREVIOUS_KEYS`, a JSON object
mapping key-version strings to Base64 keys. Re-encrypt records with the
internal rotation operation before retiring an old key. Backups are only
recoverable while the corresponding external key material remains available.

Generate local development key material with a trusted password manager or
operating-system cryptographic random generator. Put it in an ignored local
environment file; never commit it or add it to `.env.example`. Production
deployments should load keys from an external secret manager and should not
rely on a developer `.env` file. Application processes necessarily hold
plaintext briefly in memory during authorized use; Python cannot guarantee
zeroization of immutable strings.

P09 does not add a general secret viewer, connector-specific credential flows,
or cloud KMS integration. P10 now records vault lifecycle metadata without secret
values. Connector phases can consume the internal vault abstraction later.
