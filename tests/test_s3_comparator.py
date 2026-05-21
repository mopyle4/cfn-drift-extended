"""Unit tests for the S3 comparator."""

import json

from cfn_drift_extended.collectors.cfn_s3_extractor import ExpectedS3State
from cfn_drift_extended.collectors.s3_collector import ActualS3State
from cfn_drift_extended.comparators.s3_comparator import S3Comparator
from cfn_drift_extended.models import DriftType, Severity

_BUCKET = "my-bucket"
_STACK = "my-stack"

_STMT_A = json.dumps(
    {"Sid": "StmtA", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"},
    sort_keys=True,
)
_STMT_B = json.dumps(
    {"Sid": "StmtB", "Effect": "Allow", "Principal": "*", "Action": "s3:PutObject"},
    sort_keys=True,
)
_CORS_RULE = json.dumps(
    {"AllowedMethods": ["GET"], "AllowedOrigins": ["https://evil.com"]},
    sort_keys=True,
)


def _make_expected(
    policy_statements: tuple[str, ...] = (),
    lifecycle_rule_ids: tuple[str, ...] = (),
    cors_rules: tuple[str, ...] = (),
) -> ExpectedS3State:
    return ExpectedS3State(
        bucket_name=_BUCKET,
        logical_id="MyBucket",
        stack_name=_STACK,
        policy_statements=policy_statements,
        lifecycle_rule_ids=lifecycle_rule_ids,
        cors_rules=cors_rules,
    )


def _make_actual(
    policy_statements: tuple[str, ...] = (),
    lifecycle_rule_ids: tuple[str, ...] = (),
    cors_rules: tuple[str, ...] = (),
) -> ActualS3State:
    return ActualS3State(
        bucket_name=_BUCKET,
        policy_statements=policy_statements,
        lifecycle_rule_ids=lifecycle_rule_ids,
        cors_rules=cors_rules,
    )


class TestS3Comparator:
    def setup_method(self) -> None:
        self.comparator = S3Comparator()

    def test_no_drift(self) -> None:
        expected = _make_expected(
            policy_statements=(_STMT_A,),
            lifecycle_rule_ids=("rule-1",),
            cors_rules=(_CORS_RULE,),
        )
        actual = _make_actual(
            policy_statements=(_STMT_A,),
            lifecycle_rule_ids=("rule-1",),
            cors_rules=(_CORS_RULE,),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_extra_policy_statements_detected(self) -> None:
        expected = _make_expected(policy_statements=(_STMT_A,))
        actual = _make_actual(policy_statements=(_STMT_A, _STMT_B))

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.S3_POLICY_STATEMENT_ADDED
        assert f.severity == Severity.HIGH
        assert f.extra["Sid"] == "StmtB"

    def test_extra_lifecycle_rules_detected(self) -> None:
        expected = _make_expected(lifecycle_rule_ids=("rule-1",))
        actual = _make_actual(lifecycle_rule_ids=("rule-1", "rogue-rule"))

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.S3_LIFECYCLE_RULE_ADDED
        assert f.severity == Severity.MEDIUM
        assert f.extra == "rogue-rule"

    def test_extra_cors_rules_detected(self) -> None:
        expected = _make_expected()
        actual = _make_actual(cors_rules=(_CORS_RULE,))

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.S3_CORS_RULE_ADDED
        assert f.severity == Severity.LOW

    def test_multiple_drift_types(self) -> None:
        expected = _make_expected(policy_statements=(_STMT_A,))
        actual = _make_actual(
            policy_statements=(_STMT_A, _STMT_B),
            lifecycle_rule_ids=("rogue-rule",),
            cors_rules=(_CORS_RULE,),
        )

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        drift_types = {f.drift_type for f in audit.findings}
        assert DriftType.S3_POLICY_STATEMENT_ADDED in drift_types
        assert DriftType.S3_LIFECYCLE_RULE_ADDED in drift_types
        assert DriftType.S3_CORS_RULE_ADDED in drift_types

    def test_no_false_positives_when_actual_has_fewer_statements(self) -> None:
        """Removals are not flagged — handled by native CFN drift detection."""
        expected = _make_expected(policy_statements=(_STMT_A, _STMT_B))
        actual = _make_actual(policy_statements=(_STMT_A,))
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_no_false_positives_when_actual_has_fewer_lifecycle_rules(self) -> None:
        expected = _make_expected(lifecycle_rule_ids=("rule-1", "rule-2"))
        actual = _make_actual(lifecycle_rule_ids=("rule-1",))
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_empty_bucket_no_drift(self) -> None:
        expected = _make_expected()
        actual = _make_actual()
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_resource_type_and_id(self) -> None:
        expected = _make_expected()
        actual = _make_actual()
        audit = self.comparator.compare(expected, actual)
        assert audit.resource_type == "AWS::S3::Bucket"
        assert audit.resource_id == _BUCKET
        assert audit.stack_name == _STACK
