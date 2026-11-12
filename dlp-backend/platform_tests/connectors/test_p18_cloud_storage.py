"""P18 fixture coverage for S3/GCS pagination, events, and public exposure."""

import base64
import json
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from dlp_platform.connectors.cloud_storage import (
    CloudProviderFailure,
    CloudStorageObject,
    GCSStorageAdapter,
    S3StorageAdapter,
    _policy_grants_public_object_read,
)
from dlp_platform.connectors.models import ExposureKind

AWS_ACCOUNT = "123456789012"
AWS_REGION = "us-east-1"
BUCKET_NAME = "p18-test-bucket-123"


def _s3_adapter(*, requester_pays: bool = False, queue: str = "p18-events"):
    iam = boto3.client("iam", region_name=AWS_REGION)
    role_name = f"dlp-test-{queue}"
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                        "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"sts:ExternalId": "fixture-external-id"}},
                    }
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="fixture-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        ),
    )
    s3 = boto3.client("s3", region_name=AWS_REGION)
    s3.create_bucket(Bucket=BUCKET_NAME)
    s3.put_bucket_versioning(Bucket=BUCKET_NAME, VersioningConfiguration={"Status": "Enabled"})
    queue_response = boto3.client("sqs", region_name=AWS_REGION).create_queue(QueueName=queue)
    account = "123456789012"
    config = {
        "bucket": BUCKET_NAME,
        "region": AWS_REGION,
        "aws_account_id": account,
        "requester_pays": requester_pays,
        "sqs_queue_name": queue,
    }
    secret = json.dumps(
        {
            "access_key_id": "AKIAEXAMPLEACCESSKEY",
            "secret_access_key": "fixture-secret-access-key",
            "role_arn": role["Role"]["Arn"],
            "external_id": "fixture-external-id",
        }
    )
    return S3StorageAdapter(config, secret), s3, queue_response["QueueUrl"]


@mock_aws
def test_s3_uses_external_id_role_and_pages_versioned_objects():
    adapter, s3, _queue_url = _s3_adapter()
    for index in range(3):
        s3.put_object(Bucket=BUCKET_NAME, Key=f"object-{index}.txt", Body=b"fixture")
    page = adapter.list_page(None, page_size=2)
    assert len(page.objects) == 2
    assert all(item.version for item in page.objects)
    assert page.next_page_token is not None
    second = adapter.list_page(page.next_page_token, page_size=2)
    assert len(second.objects) == 1
    assert second.next_page_token is None
    assert all(item.provider_project_or_account == AWS_ACCOUNT for item in page.objects)


@mock_aws
def test_s3_public_object_acl_is_detected_and_requester_pays_is_opt_in():
    adapter, s3, _queue_url = _s3_adapter()
    s3.put_object(Bucket=BUCKET_NAME, Key="public.txt", Body=b"metadata-only")
    s3.put_object_acl(Bucket=BUCKET_NAME, Key="public.txt", ACL="public-read")
    obj = adapter.list_page(None).objects[0]
    assert ExposureKind.PUBLIC in {exposure.kind for exposure in adapter.detect_exposure(obj)}

    paying, _, _ = _s3_adapter(requester_pays=True, queue="p18-requester-pays")
    assert paying.requester_pays is True
    assert len(paying.list_page(None).objects) == 1


@mock_aws
def test_s3_bucket_acl_public_read_is_detected_for_each_object():
    adapter, s3, _queue_url = _s3_adapter()
    s3.put_object(Bucket=BUCKET_NAME, Key="bucket-public.txt", Body=b"metadata")
    s3.put_bucket_acl(Bucket=BUCKET_NAME, ACL="public-read")
    obj = adapter.list_page(None).objects[0]
    assert ExposureKind.PUBLIC in {item.kind for item in adapter.detect_exposure(obj)}


@mock_aws
def test_s3_notification_is_bucket_bound_and_acknowledged_after_processing():
    adapter, _s3, queue_url = _s3_adapter()
    message = {
        "Records": [
            {
                "eventSource": "aws:s3",
                "eventName": "ObjectCreated:Put",
                "eventID": "fixture-event-1",
                "s3": {
                    "bucket": {"name": BUCKET_NAME},
                    "object": {"key": "folder%2Fcreated.txt", "versionId": "v1"},
                },
            }
        ]
    }
    boto3.client("sqs", region_name=AWS_REGION).send_message(
        QueueUrl=queue_url, MessageBody=json.dumps(message)
    )
    batch = adapter.poll_notifications()
    assert len(batch.events) == 1
    assert batch.events[0].object_name == "folder/created.txt"
    assert batch.events[0].version == "v1"
    assert batch.events[0].event_id == f"s3:{BUCKET_NAME}:fixture-event-1"
    adapter.acknowledge(batch.acknowledgement_tokens)
    assert adapter.poll_notifications().events == ()


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        (
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket-name/*",
                }
            },
            True,
        ),
        (
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::bucket-name",
                }
            },
            False,
        ),
        (
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket-name/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            },
            None,
        ),
    ],
)
def test_s3_public_read_policy_detector_avoids_unrelated_policy_and_handles_conditions(
    policy, expected
):
    assert _policy_grants_public_object_read(policy, "bucket-name") is expected


class FakeGCSIterator:
    def __init__(self, page, token):
        self.pages = iter([page])
        self.next_page_token = token


class FakeGCSClient:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def list_blobs(self, bucket, **kwargs):
        self.calls.append((bucket, kwargs))
        return FakeGCSIterator(*self.pages.pop(0))


class FakeACL:
    def __init__(self, entities=()):
        self.entities = entities

    def reload(self, **_kwargs):
        pass

    def get_entities(self):
        return self.entities


class FakeBlob:
    def __init__(self, name, generation, entities=()):
        self.name = name
        self.generation = generation
        self.size = 7
        self.content_type = "text/plain"
        self.updated = None
        self.etag = "fixture-etag"
        self.acl = FakeACL(entities)


class FakeBucket:
    def __init__(self, members=(), prevention="enforced", uniform=False):
        self.iam_configuration = SimpleNamespace(public_access_prevention=prevention)
        self._properties = {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": uniform}}}
        self.members = members

    def reload(self, **_kwargs):
        pass

    def get_iam_policy(self, **_kwargs):
        return SimpleNamespace(
            bindings=[{"role": "roles/storage.objectViewer", "members": self.members}]
        )

    def blob(self, name, generation=None):
        return FakeBlob(name, generation, self.members)


def _gcs_adapter(bucket, pages):
    adapter = GCSStorageAdapter.__new__(GCSStorageAdapter)
    adapter.bucket_name = "fixture-bucket"
    adapter.project_id = "fixture-project"
    adapter.subscription = "projects/fixture-project/subscriptions/events"
    adapter.client = FakeGCSClient(pages)
    adapter.bucket = bucket
    return adapter


def test_gcs_versions_page_resume_and_public_access_prevention():
    first_blob = FakeBlob("one.txt", 10)
    second_blob = FakeBlob("two.txt", 11)
    adapter = _gcs_adapter(
        FakeBucket(("allUsers",), prevention="enforced"),
        [([first_blob], "next"), ([second_blob], None)],
    )
    first = adapter.list_page(None, 1)
    assert first.objects[0].version == "10"
    assert first.next_page_token == "next"
    second = adapter.list_page(first.next_page_token, 1)
    assert second.objects[0].version == "11"
    assert second.next_page_token is None
    assert adapter.detect_exposure(first.objects[0])[0].kind is ExposureKind.PRIVATE


def test_gcs_public_iam_and_acl_are_flagged_but_inherited_pap_is_unknown():
    obj = CloudStorageObject(
        provider="google_cloud_storage",
        bucket="fixture-bucket",
        object_name="public.txt",
        version="4",
        provider_project_or_account="fixture-project",
    )
    public = _gcs_adapter(FakeBucket(("allUsers",), prevention="unspecified"), [])
    assert public.detect_exposure(obj)[0].kind is ExposureKind.PUBLIC
    inherited = _gcs_adapter(FakeBucket(("allUsers",), prevention="inherited"), [])
    assert inherited.detect_exposure(obj)[0].kind is ExposureKind.UNKNOWN


def test_gcs_pubsub_notification_is_decoded_without_object_download():
    adapter = _gcs_adapter(FakeBucket(), [])
    event = {"bucket": "fixture-bucket", "name": "new.txt", "generation": "42"}
    message = SimpleNamespace(
        data=base64.b64encode(json.dumps(event).encode()),
        message_id="message-1",
        attributes={"eventType": "OBJECT_FINALIZE"},
    )
    adapter.subscriber = SimpleNamespace(
        pull=lambda **_kwargs: SimpleNamespace(
            received_messages=[SimpleNamespace(message=message, ack_id="ack-1")]
        ),
        acknowledge=lambda **_kwargs: None,
    )
    batch = adapter.poll_notifications()
    assert batch.events[0].object_name == "new.txt"
    assert batch.events[0].version == "42"
    assert batch.acknowledgement_tokens == ("ack-1",)
    adapter.acknowledge(batch.acknowledgement_tokens)


def test_invalid_bucket_notification_is_rejected():
    adapter = _gcs_adapter(FakeBucket(), [])
    message = SimpleNamespace(
        data=base64.b64encode(b'{"bucket":"other","name":"x"}'),
        message_id="message-1",
        attributes={},
    )
    adapter.subscriber = SimpleNamespace(
        pull=lambda **_kwargs: SimpleNamespace(
            received_messages=[SimpleNamespace(message=message, ack_id="ack-1")]
        )
    )
    with pytest.raises(CloudProviderFailure, match="notification_bucket_mismatch"):
        adapter.poll_notifications()
