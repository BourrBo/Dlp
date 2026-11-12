# P18 — S3 and Google Cloud Storage connectors

## Scope

P18 adds tenant-scoped S3 and Google Cloud Storage connector registrations, secret verification through the existing P09 Vault, metadata-only versioned object inventory, provider event intake, public access exposure reporting, and integration with the existing scan, policy, audit, and connector checkpoint paths. It does not download object contents, implement a cloud scan pipeline, or automatically remediate public access.

S3 access uses a bootstrap AWS credential stored in the Vault to assume the configured cross-account role with an external ID. The expected AWS account ID is checked before inventory. Bucket version inventory uses bounded pages and preserves key/version resume markers. Requester-pays is explicit opt-in. The connector inspects bucket and object ACLs, bucket policy status and policy grants, bucket Block Public Access, and account Block Public Access. Conditional public-read policies that cannot be safely classified are reported as unknown.

GCS access uses service-account JSON stored in the Vault. Versioned object inventory preserves provider page tokens and generations. Public IAM members and legacy object ACLs are inspected where applicable. Public Access Prevention can make inherited public grants ineffective; inherited or indeterminate settings are reported as unknown rather than asserted private/public.

S3 event intake uses SQS and GCS uses Pub/Sub. The deployment must provision the queue/subscription, cloud-side bucket notification, cross-account role trust/policy, and service-account permissions. Event receipts are hashed and checkpointed before messages are acknowledged. A repeated event is therefore idempotent across retries. Initial inventory and notifications each process bounded batches.

The P18 routes are under `/connectors/s3/*` and `/connectors/gcs/*`; they use the authenticated organization, enforce connector write permission, and store credentials only in the encrypted Vault. Migration `0017_cloud_storage_connectors` extends the existing provider checks and retains the existing RLS-protected connector tables. Downgrade is refused while P18 connector records exist.

## Configuration and operation

Create a connector with its bucket, AWS account/region or GCP project, and notification resource. Connect by supplying the bootstrap AWS key, role ARN, external ID, and AWS secret (plus optional session token), or a GCP service-account JSON document. The API verifies provider access before saving the credential in the Vault. Never place credentials in connector configuration, source control, logs, or support output.

The web UI provides S3/GCS registration, connection, one bounded sync page, and disconnect. Use cloud IAM and provider controls to restrict permissions to the configured bucket, required object metadata/version/ACL/policy reads, and notification queue/subscription operations. Follow the provider's official cross-account role and notification setup guidance for production deployment.

## Validation record

Automated acceptance uses Moto for AWS behavior and deterministic GCS/provider fixtures. These prove adapter and route behavior without claiming live AWS or GCP account validation. Real provider credentials were not used for the fixture validation. PostgreSQL migration and forced-RLS validation must be recorded from the actual P18 validation run before release; the migration tests exercise the upgrade/downgrade/re-upgrade chain against the configured PostgreSQL test database.
