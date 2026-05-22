"""Collect actual DynamoDB table state from AWS.

Required IAM permissions (least privilege):
- dynamodb:DescribeTable
- application-autoscaling:DescribeScalableTargets
- application-autoscaling:DescribeScalingPolicies
"""

import logging
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)


@dataclass(frozen=True, slots=True)
class ActualDynamoDBState:
    """What actually exists on a DynamoDB table in AWS."""

    table_name: str
    gsi_names: tuple[str, ...] = field(default_factory=tuple)
    # ResourceId strings like "table/MyTable" or "table/MyTable/index/MyIndex"
    scaling_target_ids: tuple[str, ...] = field(default_factory=tuple)
    scaling_policy_names: tuple[str, ...] = field(default_factory=tuple)


class DynamoDBCollector:
    """Collects actual DynamoDB table state from the AWS DynamoDB and
    Application Auto Scaling APIs.

    Features:
    - Adaptive retry with exponential backoff
    - Read-only API calls (least privilege)
    - Returns None on not-found/access-denied (graceful degradation)
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._dynamodb = self._session.client("dynamodb", config=_BOTO_CONFIG)
        self._autoscaling = self._session.client(
            "application-autoscaling", config=_BOTO_CONFIG
        )

    def get_table_state(self, table_name: str) -> ActualDynamoDBState | None:
        """Get the actual state of a DynamoDB table.

        Returns None if the table doesn't exist or cannot be accessed.
        """
        try:
            response = self._dynamodb.describe_table(TableName=table_name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                logger.warning("DynamoDB table '%s' does not exist", table_name)
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied accessing DynamoDB table '%s'. "
                    "Ensure dynamodb:DescribeTable permission is granted.",
                    table_name,
                )
            else:
                logger.error(
                    "Unexpected error fetching DynamoDB table '%s': %s",
                    table_name,
                    error_code,
                )
            return None

        table = response.get("Table", {})
        gsi_names = self._extract_gsi_names(table)
        scaling_target_ids = self._get_scaling_target_ids(table_name)
        scaling_policy_names = self._get_scaling_policy_names(table_name)

        return ActualDynamoDBState(
            table_name=table_name,
            gsi_names=tuple(gsi_names),
            scaling_target_ids=tuple(scaling_target_ids),
            scaling_policy_names=tuple(scaling_policy_names),
        )

    def _extract_gsi_names(self, table: dict[str, Any]) -> list[str]:
        """Extract GSI names from the table description."""
        gsis = table.get("GlobalSecondaryIndexes", [])
        if not isinstance(gsis, list):
            return []
        return [
            gsi.get("IndexName", "")
            for gsi in gsis
            if isinstance(gsi, dict) and gsi.get("IndexName")
        ]

    def _get_scaling_target_ids(self, table_name: str) -> list[str]:
        """Get Application Auto Scaling target ResourceIds for the table."""
        resource_ids: list[str] = []
        try:
            paginator = self._autoscaling.get_paginator("describe_scalable_targets")
            for page in paginator.paginate(
                ServiceNamespace="dynamodb",
                ResourceIds=[f"table/{table_name}"],
            ):
                for target in page.get("ScalableTargets", []):
                    resource_id = target.get("ResourceId", "")
                    if isinstance(resource_id, str) and resource_id:
                        resource_ids.append(resource_id)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied listing scaling targets for table '%s'. "
                    "Ensure application-autoscaling:DescribeScalableTargets "
                    "permission is granted.",
                    table_name,
                )
            else:
                logger.error(
                    "Unexpected error listing scaling targets for table '%s': %s",
                    table_name,
                    error_code,
                )
        return resource_ids

    def _get_scaling_policy_names(self, table_name: str) -> list[str]:
        """Get Application Auto Scaling policy names for the table."""
        policy_names: list[str] = []
        try:
            paginator = self._autoscaling.get_paginator("describe_scaling_policies")
            for page in paginator.paginate(
                ServiceNamespace="dynamodb",
                ResourceId=f"table/{table_name}",
            ):
                for policy in page.get("ScalingPolicies", []):
                    name = policy.get("PolicyName", "")
                    if isinstance(name, str) and name:
                        policy_names.append(name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied listing scaling policies for table '%s'. "
                    "Ensure application-autoscaling:DescribeScalingPolicies "
                    "permission is granted.",
                    table_name,
                )
            else:
                logger.error(
                    "Unexpected error listing scaling policies for table '%s': %s",
                    table_name,
                    error_code,
                )
        return policy_names
