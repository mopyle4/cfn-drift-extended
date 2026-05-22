"""Unit tests for the S3 collector."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.s3_collector import S3Collector

_BUCKET = "my-test-bucket"


def _create_bucket(s3, bucket_name: str = _BUCKET) -> None:
    s3.create_bucket(Bucket=bucket_name)


@mock_aws
def test_get_bucket_state_basic() -> None:
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert state.bucket_name == _BUCKET
    assert state.policy_statements == ()
    assert state.lifecycle_rule_ids == ()
    assert state.cors_rules == ()


@mock_aws
def test_get_bucket_state_with_policy() -> None:
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{_BUCKET}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=_BUCKET, Policy=json.dumps(policy))

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert len(state.policy_statements) == 1
    stmt = json.loads(state.policy_statements[0])
    assert stmt["Sid"] == "AllowPublicRead"


@mock_aws
def test_get_bucket_state_with_lifecycle_rules() -> None:
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    s3.put_bucket_lifecycle_configuration(
        Bucket=_BUCKET,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "expire-old-logs",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "logs/"},
                    "Expiration": {"Days": 30},
                },
                {
                    "ID": "transition-to-glacier",
                    "Status": "Enabled",
                    "Filter": {"Prefix": "archive/"},
                    "Transitions": [{"Days": 90, "StorageClass": "GLACIER"}],
                },
            ]
        },
    )

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert set(state.lifecycle_rule_ids) == {"expire-old-logs", "transition-to-glacier"}


@mock_aws
def test_get_bucket_state_with_cors() -> None:
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    s3.put_bucket_cors(
        Bucket=_BUCKET,
        CORSConfiguration={
            "CORSRules": [
                {
                    "AllowedHeaders": ["*"],
                    "AllowedMethods": ["GET", "PUT"],
                    "AllowedOrigins": ["https://example.com"],
                    "MaxAgeSeconds": 3000,
                }
            ]
        },
    )

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert len(state.cors_rules) == 1
    cors = json.loads(state.cors_rules[0])
    assert "GET" in cors["AllowedMethods"]


@mock_aws
def test_get_bucket_state_not_found() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state("nonexistent-bucket-xyz-123")
    assert state is None


@mock_aws
def test_get_bucket_state_no_policy_returns_empty_tuple() -> None:
    """A bucket with no policy should return empty tuple, not None."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert state.policy_statements == ()


@mock_aws
def test_get_bucket_state_no_lifecycle_returns_empty_tuple() -> None:
    """A bucket with no lifecycle config should return empty tuple, not None."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert state.lifecycle_rule_ids == ()


@mock_aws
def test_get_bucket_state_no_cors_returns_empty_tuple() -> None:
    """A bucket with no CORS config should return empty tuple, not None."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert state.cors_rules == ()


@mock_aws
def test_get_bucket_state_returns_immutable_state() -> None:
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    _create_bucket(s3)

    collector = S3Collector(region="us-east-1", session=session)
    state = collector.get_bucket_state(_BUCKET)

    assert state is not None
    assert isinstance(state.policy_statements, tuple)
    assert isinstance(state.lifecycle_rule_ids, tuple)
    assert isinstance(state.cors_rules, tuple)
