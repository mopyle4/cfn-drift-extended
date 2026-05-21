"""Collect actual S3 bucket state from AWS.

Required IAM permissions (least privilege):
- s3:GetBucketPolicy
- s3:GetBucketLifecycleConfiguration
- s3:GetBucketCors
"""

import json
import logging
from dataclasses import dataclass, field

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)


@dataclass(frozen=True, slots=True)
class ActualS3State:
    """What actually exists on an S3 bucket in AWS."""

    bucket_name: str
    # Normalized JSON strings of each bucket policy statement
    policy_statements: tuple[str, ...] = field(default_factory=tuple)
    # Lifecycle rule IDs
    lifecycle_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    # Normalized JSON strings of each CORS rule
    cors_rules: tuple[str, ...] = field(default_factory=tuple)


class S3Collector:
    """Collects actual S3 bucket state from the AWS S3 API.

    Features:
    - Adaptive retry with exponential backoff
    - Read-only API calls (least privilege)
    - Returns None on not-found/access-denied (graceful degradation)
    - Handles NoSuchBucketPolicy, NoSuchLifecycleConfiguration, NoSuchCORSConfiguration
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._s3 = self._session.client("s3", config=_BOTO_CONFIG)

    def get_bucket_state(self, bucket_name: str) -> ActualS3State | None:
        """Get the actual state of an S3 bucket.

        Returns None if the bucket doesn't exist or cannot be accessed.
        """
        # Verify the bucket exists by checking its location
        try:
            self._s3.get_bucket_location(Bucket=bucket_name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchBucket":
                logger.warning("S3 bucket '%s' does not exist", bucket_name)
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied accessing S3 bucket '%s'.",
                    bucket_name,
                )
            else:
                logger.error(
                    "Unexpected error accessing S3 bucket '%s': %s",
                    bucket_name,
                    error_code,
                )
            return None

        policy_statements = self._get_policy_statements(bucket_name)
        lifecycle_rule_ids = self._get_lifecycle_rule_ids(bucket_name)
        cors_rules = self._get_cors_rules(bucket_name)

        return ActualS3State(
            bucket_name=bucket_name,
            policy_statements=tuple(policy_statements),
            lifecycle_rule_ids=tuple(lifecycle_rule_ids),
            cors_rules=tuple(cors_rules),
        )

    def _get_policy_statements(self, bucket_name: str) -> list[str]:
        """Get normalized JSON strings of each bucket policy statement.

        Returns an empty list if no policy exists (NoSuchBucketPolicy).
        """
        try:
            response = self._s3.get_bucket_policy(Bucket=bucket_name)
            policy_str = response.get("Policy", "{}")
            policy = json.loads(policy_str) if isinstance(policy_str, str) else {}
            statements = policy.get("Statement", [])
            if not isinstance(statements, list):
                return []
            return [
                json.dumps(stmt, sort_keys=True)
                for stmt in statements
                if isinstance(stmt, dict)
            ]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchBucketPolicy":
                return []
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied reading policy for S3 bucket '%s'. "
                    "Ensure s3:GetBucketPolicy permission is granted.",
                    bucket_name,
                )
            else:
                logger.error(
                    "Unexpected error reading policy for S3 bucket '%s': %s",
                    bucket_name,
                    error_code,
                )
            return []

    def _get_lifecycle_rule_ids(self, bucket_name: str) -> list[str]:
        """Get lifecycle rule IDs from the bucket.

        Returns an empty list if no lifecycle configuration exists.
        """
        try:
            response = self._s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = response.get("Rules", [])
            if not isinstance(rules, list):
                return []
            return [
                rule.get("ID", "")
                for rule in rules
                if isinstance(rule, dict) and rule.get("ID")
            ]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchLifecycleConfiguration":
                return []
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied reading lifecycle config for S3 bucket '%s'. "
                    "Ensure s3:GetBucketLifecycleConfiguration permission is granted.",
                    bucket_name,
                )
            else:
                logger.error(
                    "Unexpected error reading lifecycle config for S3 bucket '%s': %s",
                    bucket_name,
                    error_code,
                )
            return []

    def _get_cors_rules(self, bucket_name: str) -> list[str]:
        """Get normalized JSON strings of each CORS rule.

        Returns an empty list if no CORS configuration exists.
        """
        try:
            response = self._s3.get_bucket_cors(Bucket=bucket_name)
            rules = response.get("CORSRules", [])
            if not isinstance(rules, list):
                return []
            return [
                json.dumps(rule, sort_keys=True)
                for rule in rules
                if isinstance(rule, dict)
            ]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchCORSConfiguration":
                return []
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied reading CORS config for S3 bucket '%s'. "
                    "Ensure s3:GetBucketCors permission is granted.",
                    bucket_name,
                )
            else:
                logger.error(
                    "Unexpected error reading CORS config for S3 bucket '%s': %s",
                    bucket_name,
                    error_code,
                )
            return []
