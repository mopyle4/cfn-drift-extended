"""Compare expected S3 bucket state (from CFN) vs actual state (from S3 API).

Detects:
- Extra bucket policy statements (added outside CFN)
- Extra lifecycle rules (added outside CFN)
- Extra CORS rules (added outside CFN)

Uses set difference operations for O(n) comparison performance.
"""

import json
import logging

from cfn_drift_extended.collectors.cfn_s3_extractor import ExpectedS3State
from cfn_drift_extended.collectors.s3_collector import ActualS3State
from cfn_drift_extended.models import DriftFinding, DriftType, ResourceAudit, Severity

logger = logging.getLogger(__name__)


class S3Comparator:
    """Compares expected vs actual S3 bucket state to find additive drift.

    Detects:
    - Additions: policy statements, lifecycle rules, or CORS rules present
      in AWS but not in CFN

    Removals are handled by native CloudFormation drift detection.
    """

    _RESOURCE_TYPE = "AWS::S3::Bucket"

    def compare(
        self, expected: ExpectedS3State, actual: ActualS3State
    ) -> ResourceAudit:
        """Compare a single S3 bucket's expected state against its actual state.

        Uses set operations for efficient O(n) comparison.
        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []
        findings.extend(self._find_extra_policy_statements(expected, actual))
        findings.extend(self._find_extra_lifecycle_rules(expected, actual))
        findings.extend(self._find_extra_cors_rules(expected, actual))

        return ResourceAudit(
            resource_type=self._RESOURCE_TYPE,
            resource_id=expected.bucket_name,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def _find_extra_policy_statements(
        self, expected: ExpectedS3State, actual: ActualS3State
    ) -> list[DriftFinding]:
        """Find policy statements on the bucket not declared in the template."""
        expected_set = set(expected.policy_statements)
        extra = [s for s in actual.policy_statements if s not in expected_set]

        findings: list[DriftFinding] = []
        for stmt_json in extra:
            try:
                stmt = json.loads(stmt_json)
            except (json.JSONDecodeError, ValueError):
                stmt = {"Sid": "<parse-error>"}
            sid = stmt.get("Sid", "<no-sid>") if isinstance(stmt, dict) else "<no-sid>"
            findings.append(
                DriftFinding(
                    resource_type=self._RESOURCE_TYPE,
                    resource_id=expected.bucket_name,
                    stack_name=expected.stack_name,
                    drift_type=DriftType.S3_POLICY_STATEMENT_ADDED,
                    severity=Severity.HIGH,
                    description=(
                        f"Policy statement with Sid '{sid}' exists on S3 bucket "
                        f"'{expected.bucket_name}' but is not declared in the "
                        f"CloudFormation template for stack '{expected.stack_name}'"
                    ),
                    expected=list(expected.policy_statements),
                    actual=list(actual.policy_statements),
                    extra=stmt,
                )
            )
        return findings

    def _find_extra_lifecycle_rules(
        self, expected: ExpectedS3State, actual: ActualS3State
    ) -> list[DriftFinding]:
        """Find lifecycle rules on the bucket not declared in the template."""
        expected_set = set(expected.lifecycle_rule_ids)
        extra = sorted(
            rule_id for rule_id in actual.lifecycle_rule_ids
            if rule_id not in expected_set
        )

        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.bucket_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.S3_LIFECYCLE_RULE_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Lifecycle rule '{rule_id}' exists on S3 bucket "
                    f"'{expected.bucket_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=sorted(expected.lifecycle_rule_ids),
                actual=sorted(actual.lifecycle_rule_ids),
                extra=rule_id,
            )
            for rule_id in extra
        ]

    def _find_extra_cors_rules(
        self, expected: ExpectedS3State, actual: ActualS3State
    ) -> list[DriftFinding]:
        """Find CORS rules on the bucket not declared in the template."""
        expected_set = set(expected.cors_rules)
        extra = [r for r in actual.cors_rules if r not in expected_set]

        findings: list[DriftFinding] = []
        for cors_json in extra:
            try:
                cors_rule = json.loads(cors_json)
            except (json.JSONDecodeError, ValueError):
                cors_rule = {"raw": cors_json}
            findings.append(
                DriftFinding(
                    resource_type=self._RESOURCE_TYPE,
                    resource_id=expected.bucket_name,
                    stack_name=expected.stack_name,
                    drift_type=DriftType.S3_CORS_RULE_ADDED,
                    severity=Severity.LOW,
                    description=(
                        f"CORS rule exists on S3 bucket '{expected.bucket_name}' "
                        f"but is not declared in the CloudFormation template "
                        f"for stack '{expected.stack_name}'"
                    ),
                    expected=list(expected.cors_rules),
                    actual=list(actual.cors_rules),
                    extra=cors_rule,
                )
            )
        return findings
