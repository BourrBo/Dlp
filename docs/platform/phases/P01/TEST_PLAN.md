# P01 test plan

- Compare each generated Pydantic JSON Schema with the committed snapshot.
- Confirm every contract rejects unknown fields.
- Confirm scan content is represented by SecretStr, omitted from repr, and redacted
  from JSON serialization.
- Confirm tenant identity fields are absent from ScanRequest.
- Apply the baseline migration to an empty SQLite database and downgrade it.
- Confirm event persistence contains no request-body or raw-content column.
- Run Ruff and mypy.
- Run Gitleaks against the repository and a synthetic canary fixture when its executable is
  available.
