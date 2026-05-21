"""Unit tests for the Lambda comparator."""

import json

from cfn_drift_extended.collectors.cfn_lambda_extractor import ExpectedLambdaState
from cfn_drift_extended.collectors.lambda_collector import ActualLambdaState
from cfn_drift_extended.comparators.lambda_comparator import LambdaComparator
from cfn_drift_extended.models import DriftType, Severity

_LAYER_ARN = "arn:aws:lambda:us-east-1:123456789012:layer:my-layer:1"
_EXTRA_LAYER_ARN = "arn:aws:lambda:us-east-1:123456789012:layer:extra-layer:2"


def _make_expected(
    env_vars: dict | None = None,
    layer_arns: tuple[str, ...] = (),
    permission_principals: tuple[tuple[str, str], ...] = (),
) -> ExpectedLambdaState:
    return ExpectedLambdaState(
        function_name="my-function",
        logical_id="MyFunction",
        stack_name="my-stack",
        environment_variables=env_vars or {},
        layer_arns=layer_arns,
        permission_principals=permission_principals,
    )


def _make_actual(
    env_vars: dict | None = None,
    layer_arns: tuple[str, ...] = (),
    policy_statements: tuple[str, ...] = (),
) -> ActualLambdaState:
    return ActualLambdaState(
        function_name="my-function",
        environment_variables=env_vars or {},
        layer_arns=layer_arns,
        resource_policy_statements=policy_statements,
    )


class TestLambdaComparator:
    def setup_method(self) -> None:
        self.comparator = LambdaComparator()

    def test_no_drift(self) -> None:
        expected = _make_expected(
            env_vars={"KEY": "val"},
            layer_arns=(_LAYER_ARN,),
        )
        actual = _make_actual(
            env_vars={"KEY": "val"},
            layer_arns=(_LAYER_ARN,),
        )
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True
        assert audit.findings == ()

    def test_extra_env_vars_detected(self) -> None:
        expected = _make_expected(env_vars={"KEY": "val"})
        actual = _make_actual(env_vars={"KEY": "val", "SECRET": "leaked"})

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.LAMBDA_ENV_VAR_ADDED
        assert f.severity == Severity.MEDIUM
        assert f.extra == "SECRET"

    def test_extra_layers_detected(self) -> None:
        expected = _make_expected(layer_arns=(_LAYER_ARN,))
        actual = _make_actual(layer_arns=(_LAYER_ARN, _EXTRA_LAYER_ARN))

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.LAMBDA_LAYER_ADDED
        assert f.severity == Severity.MEDIUM
        assert f.extra == _EXTRA_LAYER_ARN

    def test_extra_permissions_detected(self) -> None:
        stmt = {
            "Sid": "RoguePermission",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:us-east-1:123:function:my-function",
        }
        expected = _make_expected()
        actual = _make_actual(
            policy_statements=(json.dumps(stmt, sort_keys=True),)
        )

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        assert len(audit.findings) == 1
        f = audit.findings[0]
        assert f.drift_type == DriftType.LAMBDA_PERMISSION_ADDED
        assert f.severity == Severity.HIGH
        assert f.extra["Sid"] == "RoguePermission"

    def test_declared_permission_not_flagged(self) -> None:
        """A permission declared as Lambda::Permission in CFN should not be flagged."""
        stmt = {
            "Sid": "DeclaredPermission",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:us-east-1:123:function:my-function",
        }
        expected = _make_expected(
            permission_principals=(("lambda:InvokeFunction", "s3.amazonaws.com"),)
        )
        actual = _make_actual(
            policy_statements=(json.dumps(stmt, sort_keys=True),)
        )

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_multiple_drift_types(self) -> None:
        stmt = {
            "Sid": "Extra",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "lambda:InvokeFunction",
            "Resource": "*",
        }
        expected = _make_expected(env_vars={"A": "1"})
        actual = _make_actual(
            env_vars={"A": "1", "B": "2"},
            layer_arns=(_EXTRA_LAYER_ARN,),
            policy_statements=(json.dumps(stmt, sort_keys=True),),
        )

        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is False
        drift_types = {f.drift_type for f in audit.findings}
        assert DriftType.LAMBDA_ENV_VAR_ADDED in drift_types
        assert DriftType.LAMBDA_LAYER_ADDED in drift_types
        assert DriftType.LAMBDA_PERMISSION_ADDED in drift_types

    def test_no_false_positives_when_actual_has_fewer_env_vars(self) -> None:
        """Removals are not flagged — handled by native CFN drift detection."""
        expected = _make_expected(env_vars={"A": "1", "B": "2"})
        actual = _make_actual(env_vars={"A": "1"})
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_no_false_positives_when_actual_has_fewer_layers(self) -> None:
        expected = _make_expected(layer_arns=(_LAYER_ARN, _EXTRA_LAYER_ARN))
        actual = _make_actual(layer_arns=(_LAYER_ARN,))
        audit = self.comparator.compare(expected, actual)
        assert audit.in_sync is True

    def test_extra_env_vars_sorted(self) -> None:
        expected = _make_expected()
        actual = _make_actual(env_vars={"Z_KEY": "z", "A_KEY": "a"})
        audit = self.comparator.compare(expected, actual)
        extras = [f.extra for f in audit.findings]
        assert extras == sorted(extras)
