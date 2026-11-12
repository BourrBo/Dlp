# P09 Security Notes

- Data is encrypted with AES-256-GCM using a fresh 12-byte nonce per write.
- Tenant ID, record ID, logical name, and secret type are authenticated as
  associated data; moving or relabeling ciphertext causes decryption failure.
- The database contains ciphertext and metadata only. The master key is
  external to PostgreSQL and is never included in source or sample config.
- P09 deliberately uses direct AES-256-GCM encryption with a versioned key
  provider, as specified in its phase design. It does not implement per-record
  envelope DEKs, KMS wrapping, or an HSM integration. A replaceable key-provider
  interface is the extension point; deployments must supply key material through
  an external secret manager. This design is not a claim of KMS-backed key
  isolation.
- RLS uses the verified transaction-local tenant claims, with forced RLS and
  operation-specific policies. Application authorization is an additional
  boundary, not a replacement for database isolation.
- HTTP routes never return plaintext. Validation errors are sanitized and
  responses are marked `no-store`.
- Retain old key versions until all affected ciphertext is re-encrypted and
  verified. Losing a key makes its records unrecoverable.
- Soft-disable is not secure erasure; database backups and WAL may retain
  ciphertext. Key retirement or future crypto-shredding requires a deliberate
  external key-management design.
- Do not log `SecretStr.get_secret_value()` or include it in exception text.
  Plaintext exists transiently in process memory for authorized internal use.
