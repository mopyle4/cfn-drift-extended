"""Unit tests for the DynamoDB comparator."""

from cfn_drift_extended.collectors.cfn_dynamodb_extractor import ExpectedDynamoDBState
from cfn_drift_extended.collectors.dynamodb_collector import ActualDynamoDBState
from cfn_drift_extended.comparators.dynamodb_comparator import DynamoDBComparator
from cfn_drift_extended.models import DriftType, Severity

_TABLE = "my-table"
_STACK = "my-stack"


def _make_expected(
    gsi_names: tuple[str, ...] = (),
    scaling_target_ids: tuple[str, ...] = (),
    scaling_policy_names: tuple[str, ...] = (),
) -> ExpectedDynamoDBState:
    return ExpectedDynamoDBState(
        table_name=_TABLE,
        logical_id="MyTable",
        stack_name=_STACK,
        gsi_names=gsi_names,
        scaling_target_ids=scaling_target_ids,
        scaling_policy_names=scaling_policy_names,
    )


def _make_actual(
    gsi_names: tuple[str, ...] = (),
    scaling_target_ids: tuple[str, ...] = (),
    scaling_policy_names: tuple[str, ...] = (),
) -> ActualDynamoDBState:
    return ActualDynamoDBState(
        table_name=_TABLE,
        gsi_names=gsi_names,
        scaling_target_ids=scaling_target_ids,
        scaling_policy_names=scaling_policy_names,
    )


class TestDynamoDBComparator:
    def setup_method(self) -> None:
        self.comparator = DynamoDBComparator()

    def test_no_drift(self) -> None:
        expected = _make_expected(
            gsi_names=("my-index",),
            scaling_target_ids=(f"table/{_TABLE}",),
            scaling_policy_names=("my-policy",),
        )
        actual = _make_actual(
            gsi_names=("my-index",),
            scaling_target_ids=(f"table/{_TABLE}",),
            scaling_policy_names=("my-policy",),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_extra_gsis_detected(self) -> None:
        expected = _make_expected(gsi_names=("declared-index",))
        actual = _make_actual(gsi_names=("declared-index", "rogue-index"))

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.DYNAMODB_GSI_ADDED
        assert f.severity == Severity.MEDIUM
        assert f.extra == "rogue-index"

    def test_extra_scaling_targets_detected(self) -> None:
        expected = _make_expected()
        actual = _make_actual(scaling_target_ids=(f"table/{_TABLE}",))

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.DYNAMODB_SCALING_TARGET_ADDED
        assert f.severity == Severity.MEDIUM
        assert f.extra == f"table/{_TABLE}"

    def test_extra_scaling_policies_detected(self) -> None:
        expected = _make_expected()
        actual = _make_actual(scaling_policy_names=("rogue-policy",))

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.DYNAMODB_SCALING_POLICY_ADDED
        assert f.severity == Severity.MEDIUM
        assert f.extra == "rogue-policy"

    def test_multiple_drift_types(self) -> None:
        expected = _make_expected(gsi_names=("declared-index",))
        actual = _make_actual(
            gsi_names=("declared-index", "rogue-index"),
            scaling_target_ids=(f"table/{_TABLE}",),
            scaling_policy_names=("rogue-policy",),
        )

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        drift_types = {f.drift_type for f in audit.findings}
        assert DriftType.DYNAMODB_GSI_ADDED in drift_types
        assert DriftType.DYNAMODB_SCALING_TARGET_ADDED in drift_types
        assert DriftType.DYNAMODB_SCALING_POLICY_ADDED in drift_types

    def test_no_false_positives_when_actual_has_fewer_gsis(self) -> None:
        """Removals are not flagged — handled by native CFN drift detection."""
        expected = _make_expected(gsi_names=("index-a", "index-b"))
        actual = _make_actual(gsi_names=("index-a",))
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_no_false_positives_when_actual_has_fewer_policies(self) -> None:
        expected = _make_expected(scaling_policy_names=("policy-a", "policy-b"))
        actual = _make_actual(scaling_policy_names=("policy-a",))
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_empty_table_no_drift(self) -> None:
        expected = _make_expected()
        actual = _make_actual()
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_resource_type_and_id(self) -> None:
        expected = _make_expected()
        actual = _make_actual()
        audit = self.comparator.compare(expected, actual)
        assert audit.resource_type == "AWS::DynamoDB::Table"
        assert audit.resource_id == _TABLE
        assert audit.stack_name == _STACK

    def test_extra_gsis_sorted(self) -> None:
        expected = _make_expected()
        actual = _make_actual(gsi_names=("z-index", "a-index", "m-index"))
        audit = self.comparator.compare(expected, actual)
        extras = [f.extra for f in audit.findings]
        assert extras == sorted(extras)
