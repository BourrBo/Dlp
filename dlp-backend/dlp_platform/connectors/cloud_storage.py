"""Read-only S3 and Cloud Storage adapters for P18 bucket inventory/events."""

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

import boto3  # type: ignore[import-untyped]
from botocore.config import Config as BotoConfig  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from google.api_core.retry import Retry
from google.cloud import pubsub_v1, storage  # type: ignore[import-untyped]
from google.oauth2 import service_account
from pydantic import BaseModel, ConfigDict, Field

from dlp_platform.connectors.models import Exposure, ExposureKind

PAGE_SIZE = 100
MAX_EVENTS = 100
SDK_TIMEOUT_SECONDS = 20
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$")
_ACCOUNT = re.compile(r"^\d{12}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
_GCS_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,220}[a-z0-9]$")
_GCP_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_QUEUE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_SUBSCRIPTION = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/subscriptions/[A-Za-z0-9_-]{1,255}$"
)


class CloudStorageObject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str = Field(pattern=r"^(aws_s3|google_cloud_storage)$")
    bucket: str = Field(min_length=3, max_length=222)
    object_name: str = Field(min_length=1, max_length=1024)
    version: str | None = Field(default=None, max_length=256)
    provider_project_or_account: str = Field(min_length=1, max_length=128)
    size_bytes: int | None = Field(default=None, ge=0)
    content_type: str | None = Field(default=None, max_length=256)
    modified_at: datetime | None = None
    etag: str | None = Field(default=None, max_length=256)
    deleted: bool = False

    @property
    def object_id(self) -> str:
        return json.dumps(
            [self.bucket, self.object_name, self.version], separators=(",", ":"), ensure_ascii=True
        )


class CloudObjectPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    objects: tuple[CloudStorageObject, ...]
    next_page_token: str | None = Field(default=None, max_length=2048)


class CloudNotification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=1024)
    bucket: str = Field(min_length=3, max_length=222)
    object_name: str = Field(min_length=1, max_length=1024)
    version: str | None = Field(default=None, max_length=256)
    deleted: bool = False
    acknowledgement: str = Field(min_length=1, max_length=4096)


@dataclass(frozen=True)
class NotificationBatch:
    events: tuple[CloudNotification, ...]
    acknowledgement_tokens: tuple[str, ...]


class CloudProviderFailure(RuntimeError):
    """Sanitized provider failure. Raw SDK messages are intentionally discarded."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _aws_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = str(error.response.get("Error", {}).get("Code", "provider_error"))
        if code in {"NoSuchKey", "NoSuchVersion", "NoSuchBucket", "NotFound"}:
            return "not_found"
        if code in {"AccessDenied", "InvalidAccessKeyId", "ExpiredToken", "SignatureDoesNotMatch"}:
            return "authorization_failed"
        if code in {"RequestPayer", "RequesterPays"}:
            return "requester_pays_required"
        if code in {"SlowDown", "Throttling", "ThrottlingException", "ServiceUnavailable"}:
            return "provider_throttled"
    return "provider_unavailable"


def _provider_failure(error: Exception) -> CloudProviderFailure:
    retryable = isinstance(error, BotoCoreError)
    if isinstance(error, ClientError):
        status_code = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        retryable = (
            status_code in {429, 500, 502, 503, 504}
            or _aws_error_code(error) == "provider_throttled"
        )
    return CloudProviderFailure(_aws_error_code(error), retryable=retryable)


class S3StorageAdapter:
    """S3 inventory, object ACL/public policy inspection, and SQS notifications."""

    def __init__(self, config: dict[str, object], credential_json: str) -> None:
        self.bucket = _required_string(config, "bucket")
        self.region = _required_string(config, "region")
        self.account_id = _required_string(config, "aws_account_id")
        self.requester_pays = config.get("requester_pays") is True
        self.queue_name = _required_string(config, "sqs_queue_name")
        if not _BUCKET.fullmatch(self.bucket) or not _REGION.fullmatch(self.region):
            raise CloudProviderFailure("invalid_provider_configuration")
        if self.region not in boto3.session.Session().get_available_regions("s3"):
            raise CloudProviderFailure("invalid_provider_configuration")
        if not _ACCOUNT.fullmatch(self.account_id) or not _QUEUE_NAME.fullmatch(self.queue_name):
            raise CloudProviderFailure("invalid_provider_configuration")
        try:
            credentials = json.loads(credential_json)
            if not isinstance(credentials, dict):
                raise ValueError
            role_arn = credentials.get("role_arn")
            external_id = credentials.get("external_id")
            access_key = credentials.get("access_key_id")
            secret_key = credentials.get("secret_access_key")
            session_token = credentials.get("session_token")
            if (
                not isinstance(role_arn, str)
                or not role_arn.startswith(f"arn:aws:iam::{self.account_id}:role/")
                or len(role_arn) > 2048
                or not isinstance(external_id, str)
                or not 2 <= len(external_id) <= 1224
                or not re.fullmatch(r"[A-Za-z0-9+=,.@:/_-]+", external_id)
                or not isinstance(access_key, str)
                or not access_key
                or not isinstance(secret_key, str)
                or not secret_key
                or (session_token is not None and not isinstance(session_token, str))
            ):
                raise ValueError
            base = {
                "aws_access_key_id": access_key,
                "aws_secret_access_key": secret_key,
                **({"aws_session_token": session_token} if session_token else {}),
                "region_name": self.region,
                "config": BotoConfig(
                    connect_timeout=5,
                    read_timeout=SDK_TIMEOUT_SECONDS,
                    retries={"max_attempts": 3, "mode": "standard"},
                ),
            }
            sts = boto3.client("sts", **base)
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="dlp-p18-storage-scan",
                ExternalId=external_id,
                DurationSeconds=3600,
            )["Credentials"]
            assumed_kwargs = {
                "aws_access_key_id": assumed["AccessKeyId"],
                "aws_secret_access_key": assumed["SecretAccessKey"],
                "aws_session_token": assumed["SessionToken"],
                "region_name": self.region,
                "config": base["config"],
            }
            self.s3 = boto3.client("s3", **assumed_kwargs)
            self.s3control = boto3.client("s3control", **assumed_kwargs)
            self.sqs = boto3.client("sqs", **assumed_kwargs)
            self.queue_url = self.sqs.get_queue_url(
                QueueName=self.queue_name, QueueOwnerAWSAccountId=self.account_id
            )["QueueUrl"]
        except CloudProviderFailure:
            raise
        except (BotoCoreError, ClientError) as exc:
            raise _provider_failure(exc) from None
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise CloudProviderFailure("invalid_provider_configuration") from None

    def verify(self) -> None:
        try:
            self.s3.get_bucket_location(Bucket=self.bucket, ExpectedBucketOwner=self.account_id)
            self.sqs.get_queue_attributes(QueueUrl=self.queue_url, AttributeNames=["QueueArn"])
        except (BotoCoreError, ClientError) as exc:
            raise _provider_failure(exc) from None

    def list_page(self, page_token: str | None, page_size: int = PAGE_SIZE) -> CloudObjectPage:
        if not 1 <= page_size <= PAGE_SIZE:
            raise CloudProviderFailure("invalid_page_size")
        kwargs: dict[str, object] = {
            "Bucket": self.bucket,
            "ExpectedBucketOwner": self.account_id,
            "MaxKeys": page_size,
        }
        if page_token:
            try:
                marker = json.loads(page_token)
                if not isinstance(marker, dict):
                    raise ValueError
                key_marker, version_marker = marker.get("key"), marker.get("version")
                if not isinstance(key_marker, str):
                    raise ValueError
                kwargs["KeyMarker"] = key_marker
                if version_marker is not None:
                    if not isinstance(version_marker, str):
                        raise ValueError
                    kwargs["VersionIdMarker"] = version_marker
            except (ValueError, json.JSONDecodeError):
                raise CloudProviderFailure("invalid_inventory_checkpoint") from None
        if self.requester_pays:
            kwargs["RequestPayer"] = "requester"
        try:
            raw = self.s3.list_object_versions(**kwargs)
            objects: list[CloudStorageObject] = []
            for version in raw.get("Versions", []):
                objects.append(
                    CloudStorageObject(
                        provider="aws_s3",
                        bucket=self.bucket,
                        object_name=version["Key"],
                        version=version["VersionId"],
                        provider_project_or_account=self.account_id,
                        size_bytes=version.get("Size"),
                        modified_at=version.get("LastModified"),
                        etag=str(version.get("ETag", "")).strip('"') or None,
                    )
                )
            for marker in raw.get("DeleteMarkers", []):
                objects.append(
                    CloudStorageObject(
                        provider="aws_s3",
                        bucket=self.bucket,
                        object_name=marker["Key"],
                        version=marker["VersionId"],
                        provider_project_or_account=self.account_id,
                        deleted=True,
                    )
                )
            next_token = None
            if raw.get("IsTruncated"):
                next_key, next_version = raw.get("NextKeyMarker"), raw.get("NextVersionIdMarker")
                if not isinstance(next_key, str) or not isinstance(next_version, str):
                    raise CloudProviderFailure("malformed_provider_response")
                next_token = json.dumps(
                    {"key": next_key, "version": next_version}, separators=(",", ":")
                )
                if next_token == page_token:
                    raise CloudProviderFailure("repeated_page_token")
            return CloudObjectPage(objects=tuple(objects), next_page_token=next_token)
        except CloudProviderFailure:
            raise
        except (BotoCoreError, ClientError) as exc:
            raise _provider_failure(exc) from None

    def get_event_object(
        self, key: str, version: str | None, *, deleted: bool
    ) -> CloudStorageObject:
        if deleted:
            return CloudStorageObject(
                provider="aws_s3",
                bucket=self.bucket,
                object_name=key,
                version=version,
                provider_project_or_account=self.account_id,
                deleted=True,
            )
        kwargs: dict[str, object] = {
            "Bucket": self.bucket,
            "Key": key,
            "ExpectedBucketOwner": self.account_id,
        }
        if version:
            kwargs["VersionId"] = version
        if self.requester_pays:
            kwargs["RequestPayer"] = "requester"
        try:
            raw = self.s3.head_object(**kwargs)
            return CloudStorageObject(
                provider="aws_s3",
                bucket=self.bucket,
                object_name=key,
                version=raw.get("VersionId") or version,
                provider_project_or_account=self.account_id,
                size_bytes=raw.get("ContentLength"),
                content_type=raw.get("ContentType"),
                modified_at=raw.get("LastModified"),
                etag=str(raw.get("ETag", "")).strip('"') or None,
            )
        except (BotoCoreError, ClientError) as exc:
            raise _provider_failure(exc) from None

    def detect_exposure(self, obj: CloudStorageObject) -> tuple[Exposure, ...]:
        grants: list[Exposure] = []
        public_policy: bool | None = False
        ignored_acls = False
        restrict_public = False
        try:
            block = self.s3.get_public_access_block(
                Bucket=self.bucket, ExpectedBucketOwner=self.account_id
            )["PublicAccessBlockConfiguration"]
            ignored_acls = block.get("IgnorePublicAcls") is True
            restrict_public = block.get("RestrictPublicBuckets") is True
        except ClientError as exc:
            code = _aws_error_code(exc)
            if (
                code not in {"provider_unavailable"}
                or str(exc.response.get("Error", {}).get("Code", ""))
                != "NoSuchPublicAccessBlockConfiguration"
            ):
                return (Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN),)
            restrict_public = False
        try:
            account_block = self.s3control.get_public_access_block(AccountId=self.account_id)[
                "PublicAccessBlockConfiguration"
            ]
            ignored_acls = ignored_acls or account_block.get("IgnorePublicAcls") is True
            restrict_public = restrict_public or account_block.get("RestrictPublicBuckets") is True
        except ClientError as exc:
            if str(exc.response.get("Error", {}).get("Code", "")) not in {
                "NoSuchPublicAccessBlockConfiguration",
                "NoSuchPublicAccessBlockConfigurationException",
            }:
                return (Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN),)
        try:
            status = self.s3.get_bucket_policy_status(
                Bucket=self.bucket, ExpectedBucketOwner=self.account_id
            )["PolicyStatus"]
            if status.get("IsPublic") is True and not restrict_public:
                try:
                    policy_doc = json.loads(
                        self.s3.get_bucket_policy(
                            Bucket=self.bucket, ExpectedBucketOwner=self.account_id
                        )["Policy"]
                    )
                    public_policy = _policy_grants_public_object_read(policy_doc, self.bucket)
                except ClientError as exc:
                    if str(exc.response.get("Error", {}).get("Code", "")) not in {
                        "NoSuchBucketPolicy",
                        "NoSuchBucketPolicyStatus",
                    }:
                        return (Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN),)
        except ClientError as exc:
            if str(exc.response.get("Error", {}).get("Code", "")) not in {
                "NoSuchBucketPolicy",
                "NoSuchBucketPolicyStatus",
            }:
                return (Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN),)
        if public_policy:
            grants.append(
                Exposure(
                    object_id=obj.object_id,
                    kind=ExposureKind.PUBLIC,
                    principals=("bucket_policy:*",),
                )
            )
        elif public_policy is None:
            grants.append(Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN))
        try:
            bucket_acl = self.s3.get_bucket_acl(
                Bucket=self.bucket, ExpectedBucketOwner=self.account_id
            )
            bucket_public = any(
                grant.get("Grantee", {}).get("URI")
                == "http://acs.amazonaws.com/groups/global/AllUsers"
                and grant.get("Permission") in {"READ", "FULL_CONTROL"}
                and not ignored_acls
                for grant in bucket_acl.get("Grants", [])
            )
            if bucket_public and not restrict_public:
                grants.append(
                    Exposure(
                        object_id=obj.object_id,
                        kind=ExposureKind.PUBLIC,
                        principals=("bucket_acl:AllUsers",),
                    )
                )
        except (BotoCoreError, ClientError):
            return (Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN),)
        if not ignored_acls:
            kwargs: dict[str, object] = {
                "Bucket": self.bucket,
                "Key": obj.object_name,
                "ExpectedBucketOwner": self.account_id,
            }
            if obj.version:
                kwargs["VersionId"] = obj.version
            if self.requester_pays:
                kwargs["RequestPayer"] = "requester"
            try:
                acl = self.s3.get_object_acl(**kwargs)
            except (BotoCoreError, ClientError):
                return (Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN),)
            public: list[str] = []
            authenticated: list[str] = []
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI")
                if uri == "http://acs.amazonaws.com/groups/global/AllUsers" and grant.get(
                    "Permission"
                ) in {
                    "READ",
                    "FULL_CONTROL",
                }:
                    public.append("object_acl:AllUsers")
                elif (
                    uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    and grant.get("Permission") in {"READ", "FULL_CONTROL"}
                ):
                    authenticated.append("object_acl:AuthenticatedUsers")
            if public:
                grants.append(
                    Exposure(
                        object_id=obj.object_id, kind=ExposureKind.PUBLIC, principals=tuple(public)
                    )
                )
            if authenticated:
                grants.append(
                    Exposure(
                        object_id=obj.object_id,
                        kind=ExposureKind.AUTHENTICATED,
                        principals=tuple(authenticated),
                    )
                )
        return tuple(grants) or (Exposure(object_id=obj.object_id, kind=ExposureKind.PRIVATE),)

    def poll_notifications(self, limit: int = 10) -> NotificationBatch:
        try:
            raw = self.sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=min(max(limit, 1), 10),
                WaitTimeSeconds=1,
                MessageAttributeNames=["All"],
                AttributeNames=["ApproximateReceiveCount"],
            )
            events: list[CloudNotification] = []
            ack: list[str] = []
            for message in raw.get("Messages", []):
                body = json.loads(message["Body"])
                if not isinstance(body, dict) or body.get("Event") == "s3:TestEvent":
                    ack.append(message["ReceiptHandle"])
                    continue
                records = body.get("Records")
                if not isinstance(records, list):
                    raise CloudProviderFailure("malformed_notification")
                if len(events) + len(records) > MAX_EVENTS:
                    raise CloudProviderFailure("notification_batch_too_large")
                for record in records:
                    if not isinstance(record, dict) or record.get("eventSource") != "aws:s3":
                        raise CloudProviderFailure("malformed_notification")
                    s3_data = record.get("s3")
                    if (
                        not isinstance(s3_data, dict)
                        or s3_data.get("bucket", {}).get("name") != self.bucket
                    ):
                        raise CloudProviderFailure("notification_bucket_mismatch")
                    object_data = s3_data.get("object")
                    if not isinstance(object_data, dict):
                        raise CloudProviderFailure("malformed_notification")
                    key = object_data.get("key")
                    event_name = record.get("eventName")
                    event_id = record.get("eventID") or object_data.get("sequencer")
                    if (
                        not isinstance(key, str)
                        or not isinstance(event_name, str)
                        or not isinstance(event_id, str)
                    ):
                        raise CloudProviderFailure("malformed_notification")
                    events.append(
                        CloudNotification(
                            event_id=f"s3:{self.bucket}:{event_id}",
                            bucket=self.bucket,
                            object_name=unquote_plus(key),
                            version=object_data.get("versionId"),
                            deleted=event_name.startswith("ObjectRemoved:"),
                            acknowledgement=message["ReceiptHandle"],
                        )
                    )
                ack.append(message["ReceiptHandle"])
            return NotificationBatch(tuple(events), tuple(ack))
        except CloudProviderFailure:
            raise
        except (BotoCoreError, ClientError) as exc:
            raise _provider_failure(exc) from None
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise CloudProviderFailure("malformed_notification") from None

    def acknowledge(self, receipts: tuple[str, ...]) -> None:
        for start in range(0, len(receipts), 10):
            entries = [
                {"Id": str(index), "ReceiptHandle": receipt}
                for index, receipt in enumerate(receipts[start : start + 10])
            ]
            try:
                result = self.sqs.delete_message_batch(QueueUrl=self.queue_url, Entries=entries)
                if result.get("Failed"):
                    raise CloudProviderFailure("notification_ack_failed", retryable=True)
            except CloudProviderFailure:
                raise
            except (BotoCoreError, ClientError) as exc:
                raise _provider_failure(exc) from None


class GCSStorageAdapter:
    """Versioned GCS inventory, IAM/ACL public access inspection and Pub/Sub events."""

    def __init__(self, config: dict[str, object], credential_json: str) -> None:
        self.bucket_name = _required_string(config, "bucket")
        self.project_id = _required_string(config, "project_id")
        self.subscription = _required_string(config, "pubsub_subscription")
        if (
            not _GCS_BUCKET.fullmatch(self.bucket_name)
            or not _GCP_PROJECT.fullmatch(self.project_id)
            or not _SUBSCRIPTION.fullmatch(self.subscription)
            or not self.subscription.startswith(f"projects/{self.project_id}/")
        ):
            raise CloudProviderFailure("invalid_provider_configuration")
        try:
            data = json.loads(credential_json)
            if not isinstance(data, dict) or data.get("type") != "service_account":
                raise ValueError
            credentials = service_account.Credentials.from_service_account_info(  # type: ignore[no-untyped-call]
                data, scopes=("https://www.googleapis.com/auth/cloud-platform",)
            )
            self.client = storage.Client(project=self.project_id, credentials=credentials)
            self.bucket = self.client.bucket(self.bucket_name)
            self.subscriber = pubsub_v1.SubscriberClient(credentials=credentials)
            self.bucket.reload(timeout=SDK_TIMEOUT_SECONDS, retry=Retry(deadline=30))
            self.subscriber.get_subscription(
                request={"subscription": self.subscription}, timeout=SDK_TIMEOUT_SECONDS
            )
        except CloudProviderFailure:
            raise
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            raise CloudProviderFailure("invalid_provider_configuration") from None
        except Exception:
            raise CloudProviderFailure("provider_unavailable", retryable=True) from None

    def verify(self) -> None:
        try:
            self.bucket.reload(timeout=SDK_TIMEOUT_SECONDS, retry=Retry(deadline=30))
            if self.bucket.project != self.project_id:
                raise CloudProviderFailure("bucket_project_mismatch")
        except CloudProviderFailure:
            raise
        except Exception:
            raise CloudProviderFailure("authorization_failed") from None

    def list_page(self, page_token: str | None, page_size: int = PAGE_SIZE) -> CloudObjectPage:
        if not 1 <= page_size <= PAGE_SIZE:
            raise CloudProviderFailure("invalid_page_size")
        try:
            iterator = self.client.list_blobs(
                self.bucket_name,
                max_results=page_size,
                page_token=page_token,
                versions=True,
                timeout=SDK_TIMEOUT_SECONDS,
                retry=Retry(deadline=30),
            )
            page = next(iterator.pages, None)
            if page is None:
                return CloudObjectPage(objects=(), next_page_token=None)
            objects = tuple(self._normalize_blob(blob) for blob in page)
            next_token = iterator.next_page_token
            if next_token is not None and next_token == page_token:
                raise CloudProviderFailure("repeated_page_token")
            return CloudObjectPage(objects=objects, next_page_token=next_token)
        except CloudProviderFailure:
            raise
        except Exception as exc:
            raise CloudProviderFailure(
                _google_error_code(exc), retryable=_google_retryable(exc)
            ) from None

    def get_event_object(
        self, name: str, generation: str | None, *, deleted: bool
    ) -> CloudStorageObject:
        if deleted:
            return CloudStorageObject(
                provider="google_cloud_storage",
                bucket=self.bucket_name,
                object_name=name,
                version=generation,
                provider_project_or_account=self.project_id,
                deleted=True,
            )
        try:
            blob = self.bucket.get_blob(
                name,
                generation=int(generation) if generation else None,
                timeout=SDK_TIMEOUT_SECONDS,
                retry=Retry(deadline=30),
            )
            if blob is None:
                return self.get_event_object(name, generation, deleted=True)
            return self._normalize_blob(blob)
        except CloudProviderFailure:
            raise
        except Exception as exc:
            raise CloudProviderFailure(
                _google_error_code(exc), retryable=_google_retryable(exc)
            ) from None

    def _normalize_blob(self, blob: Any) -> CloudStorageObject:
        generation = getattr(blob, "generation", None)
        return CloudStorageObject(
            provider="google_cloud_storage",
            bucket=self.bucket_name,
            object_name=str(blob.name),
            version=str(generation) if generation is not None else None,
            provider_project_or_account=self.project_id,
            size_bytes=blob.size,
            content_type=blob.content_type,
            modified_at=blob.updated,
            etag=blob.etag,
        )

    def detect_exposure(self, obj: CloudStorageObject) -> tuple[Exposure, ...]:
        found: list[Exposure] = []
        try:
            self.bucket.reload(
                timeout=SDK_TIMEOUT_SECONDS,
                retry=Retry(deadline=30),
                if_metageneration_match=None,
            )
            prevention = getattr(self.bucket.iam_configuration, "public_access_prevention", None)
            public_prevention = prevention == "enforced"
            inherited_prevention_unknown = prevention == "inherited"
            policy = self.bucket.get_iam_policy(
                requested_policy_version=3,
                timeout=SDK_TIMEOUT_SECONDS,
                retry=Retry(deadline=30),
            )
            for binding in policy.bindings:
                role = str(binding.get("role", ""))
                if binding.get("condition"):
                    if any(
                        member in binding.get("members", ())
                        for member in ("allUsers", "allAuthenticatedUsers")
                    ):
                        found.append(Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN))
                    continue
                if role not in {
                    "roles/storage.objectViewer",
                    "roles/storage.objectAdmin",
                    "roles/storage.admin",
                    "roles/storage.legacyBucketReader",
                    "roles/storage.legacyObjectReader",
                    "roles/storage.legacyBucketOwner",
                }:
                    continue
                members = binding.get("members", ())
                if "allUsers" in members and not public_prevention:
                    found.append(
                        Exposure(
                            object_id=obj.object_id,
                            kind=(
                                ExposureKind.UNKNOWN
                                if inherited_prevention_unknown
                                else ExposureKind.PUBLIC
                            ),
                            principals=(f"bucket_iam:{role}:allUsers",),
                        )
                    )
                if "allAuthenticatedUsers" in members and not public_prevention:
                    found.append(
                        Exposure(
                            object_id=obj.object_id,
                            kind=(
                                ExposureKind.UNKNOWN
                                if inherited_prevention_unknown
                                else ExposureKind.AUTHENTICATED
                            ),
                            principals=(f"bucket_iam:{role}:allAuthenticatedUsers",),
                        )
                    )
            if (
                not getattr(self.bucket, "_properties", {})
                .get("iamConfiguration", {})
                .get("uniformBucketLevelAccess", {})
                .get("enabled", False)
            ):
                blob = self.bucket.blob(obj.object_name, generation=obj.version)
                blob.acl.reload(timeout=SDK_TIMEOUT_SECONDS, retry=Retry(deadline=30))
                entities = blob.acl.get_entities()
                if "allUsers" in entities and not public_prevention:
                    found.append(
                        Exposure(
                            object_id=obj.object_id,
                            kind=(
                                ExposureKind.UNKNOWN
                                if inherited_prevention_unknown
                                else ExposureKind.PUBLIC
                            ),
                            principals=("object_acl:allUsers",),
                        )
                    )
                if "allAuthenticatedUsers" in entities and not public_prevention:
                    found.append(
                        Exposure(
                            object_id=obj.object_id,
                            kind=(
                                ExposureKind.UNKNOWN
                                if inherited_prevention_unknown
                                else ExposureKind.AUTHENTICATED
                            ),
                            principals=("object_acl:allAuthenticatedUsers",),
                        )
                    )
            return tuple(found) or (Exposure(object_id=obj.object_id, kind=ExposureKind.PRIVATE),)
        except Exception:
            return (Exposure(object_id=obj.object_id, kind=ExposureKind.UNKNOWN),)

    def poll_notifications(self, limit: int = 10) -> NotificationBatch:
        try:
            response = self.subscriber.pull(
                request={
                    "subscription": self.subscription,
                    "max_messages": min(max(limit, 1), 100),
                },
                timeout=SDK_TIMEOUT_SECONDS,
            )
            if len(response.received_messages) > MAX_EVENTS:
                raise CloudProviderFailure("notification_batch_too_large")
            events: list[CloudNotification] = []
            ack_tokens: list[str] = []
            for received in response.received_messages:
                import base64

                data = json.loads(base64.b64decode(received.message.data, validate=True))
                if not isinstance(data, dict):
                    raise CloudProviderFailure("malformed_notification")
                if data.get("bucket") != self.bucket_name:
                    raise CloudProviderFailure("notification_bucket_mismatch")
                name, generation = data.get("name"), data.get("generation")
                event_id = received.message.message_id
                event_type = received.message.attributes.get("eventType", "OBJECT_FINALIZE")
                if not isinstance(name, str) or not name or not isinstance(event_id, str):
                    raise CloudProviderFailure("malformed_notification")
                events.append(
                    CloudNotification(
                        event_id=f"gcs:{self.bucket_name}:{event_id}",
                        bucket=self.bucket_name,
                        object_name=name,
                        version=str(generation) if generation is not None else None,
                        deleted=event_type in {"OBJECT_DELETE", "OBJECT_ARCHIVE"},
                        acknowledgement=received.ack_id,
                    )
                )
                ack_tokens.append(received.ack_id)
            return NotificationBatch(tuple(events), tuple(ack_tokens))
        except CloudProviderFailure:
            raise
        except Exception as exc:
            raise CloudProviderFailure(
                _google_error_code(exc), retryable=_google_retryable(exc)
            ) from None

    def acknowledge(self, ack_ids: tuple[str, ...]) -> None:
        if ack_ids:
            try:
                self.subscriber.acknowledge(
                    request={"subscription": self.subscription, "ack_ids": list(ack_ids)},
                    timeout=SDK_TIMEOUT_SECONDS,
                )
            except Exception:
                raise CloudProviderFailure("notification_ack_failed", retryable=True) from None


def storage_exposures(
    adapter: S3StorageAdapter | GCSStorageAdapter, obj: CloudStorageObject
) -> tuple[Exposure, ...]:
    return adapter.detect_exposure(obj)


def _required_string(config: dict[str, object], key: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise CloudProviderFailure("invalid_provider_configuration")
    return value


def _policy_grants_public_object_read(policy: object, bucket: str) -> bool | None:
    if not isinstance(policy, dict):
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    conditional_public_read = False
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        public = principal == "*" or (
            isinstance(principal, dict)
            and any(
                value == "*" or (isinstance(value, list) and "*" in value)
                for value in principal.values()
            )
        )
        if not public:
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        grants_read = isinstance(actions, list) and any(
            action in {"s3:GetObject", "s3:*", "*"} for action in actions
        )
        grants_object = isinstance(resources, list) and any(
            resource in {f"arn:aws:s3:::{bucket}/*", "*"} for resource in resources
        )
        if grants_read and grants_object:
            if statement.get("Condition"):
                conditional_public_read = True
                continue
            return True
    return None if conditional_public_read else False


def _google_error_code(error: Exception) -> str:
    code = getattr(error, "code", None)
    if callable(code):
        try:
            code = code()
        except Exception:
            code = None
    value = str(code).lower()
    if "permission_denied" in value or "unauthenticated" in value:
        return "authorization_failed"
    if "not_found" in value:
        return "not_found"
    if "resource_exhausted" in value or "429" in value:
        return "provider_throttled"
    return "provider_unavailable"


def _google_retryable(error: Exception) -> bool:
    code = _google_error_code(error)
    return code in {"provider_throttled", "provider_unavailable"}
