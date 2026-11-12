# P06 decisions

- Use Alembic revision `0006_exceptions_versions`, since P05 already owns revision
  number 0005.
- Existing P02 role/scope values remain unchanged. Writes require `api_keys:write` and
  Owner/Admin; reads require `identity:read`.
- Exceptions apply only to the specifically matched P05 policy. Any other matching
  policy retains the existing strictest-action behavior.
- Exception and suppression expiry are evaluated using the P04 scan-start clock.
- Suppression matching is exact and metadata-only: HMAC fingerprint, path, or detector
  identifier. The detector identifier is called `pattern` by the route contract; it is
  not a wildcard language.
- Policy history is immutable; rollback appends a new version. Policy deletion is a
  versioned disable so history and references remain intact.
- The sandbox uses the existing P05 evaluator with supplied sample metadata/findings;
  it does not call a detector or write production records.
- The audit seam is injectable and emits safe identifiers only. Durable append-only
  audit storage remains out of scope for P06.
