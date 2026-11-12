# P18 acceptance and test plan

## Provider fixture coverage

- S3 AssumeRole uses the expected account, configured role, and external ID; bucket version listing resumes with key/version markers.
- S3 requester-pays is opt-in; SQS notifications are bucket-bound, decoded, and acknowledged only after the connector checkpoint.
- Public S3 object/bucket ACLs and public object-read bucket policies are detected. Non-public statements are ignored; conditional matching rules are classified as unknown.
- GCS version listing resumes with provider page tokens and generations; Pub/Sub events are bucket-bound and acknowledged after checkpoint.
- GCS public IAM and applicable object ACL grants are detected, while enforced/inherited Public Access Prevention is represented accurately.
- Connector APIs enforce tenant ownership and connector-write authorization, keep credentials out of responses/configuration, and store secrets in Vault.
- End-to-end fixture sync traverses scan(), policy evaluation, audit/exposure reporting and durable checkpointing; unsupported P05/P07 provider actions fail closed.
- Event delivery is deduplicated and checkpointed before acknowledgement; failed checkpoint leaves inventory retryable.

## Database and project validation

Run the P18 tests, PostgreSQL migration upgrade/downgrade/re-upgrade tests, and the complete P01–P18 test suite with `P03_TEST_DATABASE_URL` set to the dedicated PostgreSQL test database. Then run Ruff, mypy, pre-commit, pip-audit, frontend lint/typecheck/build/tests, and available secret scanning. Record exact commands/results and whether any real-provider validation occurred in the release record.

No mocked test establishes that a production AWS or GCP account is configured correctly. Live provider verification requires authorized credentials and cloud resources; report it separately from fixture tests.
