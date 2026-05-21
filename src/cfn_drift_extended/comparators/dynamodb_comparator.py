"""Compare expected DynamoDB table state (from CFN) vs actual state (from AWS APIs).

Detects:
- Extra Global Secondary Indexes (added outside CFN)
- Extra auto-scaling targets (added outside CFN)
- Extra auto-scaling policies (added outside CFN)

Uses set difference operations for O(n) comparison performance.
"""

import logging

from cfn_drift_extended.collectors.cfn_dynamodb_extractor import ExpectedDynamoDBState
from cfn_drift_extended.collectors.dynamodb_collector import ActualDynamoDBState
from cfn_drift_extended.models import DriftFinding, DriftType, ResourceAudit, Severity

logger = logging.getLogger(__name__)


class DynamoDBComparator:
    """Compares expected vs actual DynamoDB table state to find additive drift.

    Detects:
    - Additions: GSIs, scaling targets, or scaling policies present in AWS
      but not in CFN

    Removals are handled by native CloudFormation drift detection.
    """

    _RESOURCE_TYPE = "AWS::DynamoDB::Table"

    def compare(
        self, expected: ExpectedDynamoDBState, actual: ActualDynamoDBState
    ) -> ResourceAudit:
        """Compare a single DynamoDB table's expected state against its actual state.

        Uses set operations for efficient O(n) comparison.
        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []
        findings.extend(self._find_extra_gsis(expected, actual))
        findings.extend(self._find_extra_scaling_targets(expected, actual))
        findings.extend(self._find_extra_scaling_policies(expected, actual))

        return ResourceAudit(
            resource_type=self._RESOURCE_TYPE,
            resource_id=expected.table_name,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def _find_extra_gsis(
        self, expected: ExpectedDynamoDBState, actual: ActualDynamoDBState
    ) -> list[DriftFinding]:
        """Find GSIs on the table not declared in the template."""
        expected_set = set(expected.gsi_names)
        extra = sorted(
            name for name in actual.gsi_names if name not in expected_set
        )

        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.table_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.DYNAMODB_GSI_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Global Secondary Index '{name}' exists on DynamoDB table "
                    f"'{expected.table_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=sorted(expected.gsi_names),
                actual=sorted(actual.gsi_names),
                extra=name,
            )
            for name in extra
        ]

    def _find_extra_scaling_targets(
        self, expected: ExpectedDynamoDBState, actual: ActualDynamoDBState
    ) -> list[DriftFinding]:
        """Find scaling targets on the table not declared in the template."""
        expected_set = set(expected.scaling_target_ids)
        extra = sorted(
            target_id for target_id in actual.scaling_target_ids
            if target_id not in expected_set
        )

        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.table_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.DYNAMODB_SCALING_TARGET_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Auto-scaling target '{target_id}' exists for DynamoDB table "
                    f"'{expected.table_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=sorted(expected.scaling_target_ids),
                actual=sorted(actual.scaling_target_ids),
                extra=target_id,
            )
            for target_id in extra
        ]

    def _find_extra_scaling_policies(
        self, expected: ExpectedDynamoDBState, actual: ActualDynamoDBState
    ) -> list[DriftFinding]:
        """Find scaling policies on the table not declared in the template."""
        expected_set = set(expected.scaling_policy_names)
        extra = sorted(
            name for name in actual.scaling_policy_names if name not in expected_set
        )

        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.table_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.DYNAMODB_SCALING_POLICY_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Auto-scaling policy '{name}' exists for DynamoDB table "
                    f"'{expected.table_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=sorted(expected.scaling_policy_names),
                actual=sorted(actual.scaling_policy_names),
                extra=name,
            )
            for name in extra
        ]
