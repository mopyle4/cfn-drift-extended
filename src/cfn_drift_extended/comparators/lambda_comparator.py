"""Compare expected Lambda function state (from CFN) vs actual state (from Lambda API).

Detects:
- Extra environment variables (added outside CFN)
- Extra layers (added outside CFN)
- Extra resource-based policy permissions (added outside CFN)

Uses set difference operations for O(n) comparison performance.
"""

import json
import logging
from typing import Any

from cfn_drift_extended.collectors.cfn_lambda_extractor import ExpectedLambdaState
from cfn_drift_extended.collectors.lambda_collector import ActualLambdaState
from cfn_drift_extended.models import DriftFinding, DriftType, ResourceAudit, Severity

logger = logging.getLogger(__name__)


class LambdaComparator:
    """Compares expected vs actual Lambda function state to find additive drift.

    Detects:
    - Additions: env vars, layers, or permissions present in AWS but not in CFN

    Removals are handled by native CloudFormation drift detection.
    """

    _RESOURCE_TYPE = "AWS::Lambda::Function"

    def compare(
        self, expected: ExpectedLambdaState, actual: ActualLambdaState
    ) -> ResourceAudit:
        """Compare a single Lambda function's expected state against its actual state.

        Uses set operations for efficient O(n) comparison.
        Returns a ResourceAudit with any additive drift findings.
        """
        findings: list[DriftFinding] = []
        findings.extend(self._find_extra_env_vars(expected, actual))
        findings.extend(self._find_extra_layers(expected, actual))
        findings.extend(self._find_extra_permissions(expected, actual))

        return ResourceAudit(
            resource_type=self._RESOURCE_TYPE,
            resource_id=expected.function_name,
            stack_name=expected.stack_name,
            in_sync=len(findings) == 0,
            findings=tuple(findings),
        )

    def _find_extra_env_vars(
        self, expected: ExpectedLambdaState, actual: ActualLambdaState
    ) -> list[DriftFinding]:
        """Find environment variables on the function not declared in the template."""
        extra_keys = set(actual.environment_variables) - set(expected.environment_variables)
        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.function_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.LAMBDA_ENV_VAR_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Environment variable '{key}' exists on Lambda function "
                    f"'{expected.function_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=sorted(expected.environment_variables.keys()),
                actual=sorted(actual.environment_variables.keys()),
                extra=key,
            )
            for key in sorted(extra_keys)
        ]

    def _find_extra_layers(
        self, expected: ExpectedLambdaState, actual: ActualLambdaState
    ) -> list[DriftFinding]:
        """Find layers attached to the function not declared in the template."""
        extra_arns = set(actual.layer_arns) - set(expected.layer_arns)
        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.function_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.LAMBDA_LAYER_ADDED,
                severity=Severity.MEDIUM,
                description=(
                    f"Layer '{arn}' is attached to Lambda function "
                    f"'{expected.function_name}' but is not declared in the "
                    f"CloudFormation template for stack '{expected.stack_name}'"
                ),
                expected=sorted(expected.layer_arns),
                actual=sorted(actual.layer_arns),
                extra=arn,
            )
            for arn in sorted(extra_arns)
        ]

    def _find_extra_permissions(
        self, expected: ExpectedLambdaState, actual: ActualLambdaState
    ) -> list[DriftFinding]:
        """Find resource policy statements not declared as Lambda::Permission in CFN.

        Compares by (Action, Principal) pairs extracted from the live policy
        against the declared AWS::Lambda::Permission resources.
        """
        expected_pairs = set(expected.permission_principals)

        extra_statements: list[dict[str, Any]] = []
        for stmt_json in actual.resource_policy_statements:
            try:
                stmt = json.loads(stmt_json)
            except (json.JSONDecodeError, ValueError):
                continue
            action = stmt.get("Action", "")
            principal_raw = stmt.get("Principal", "")
            # Principal can be a string or {"Service": "..."} dict
            if isinstance(principal_raw, dict):
                principal = (
                    principal_raw.get("Service", "")
                    or principal_raw.get("AWS", "")
                    or str(principal_raw)
                )
            else:
                principal = str(principal_raw)

            if isinstance(action, list):
                actions: list[str] = action
            else:
                actions = [action]

            for act in actions:
                if (act, principal) not in expected_pairs:
                    extra_statements.append(stmt)
                    break

        return [
            DriftFinding(
                resource_type=self._RESOURCE_TYPE,
                resource_id=expected.function_name,
                stack_name=expected.stack_name,
                drift_type=DriftType.LAMBDA_PERMISSION_ADDED,
                severity=Severity.HIGH,
                description=(
                    f"Resource policy statement with Sid "
                    f"'{stmt.get('Sid', '<no-sid>')}' exists on Lambda function "
                    f"'{expected.function_name}' but is not declared as an "
                    f"AWS::Lambda::Permission in the CloudFormation template "
                    f"for stack '{expected.stack_name}'"
                ),
                expected=list(expected.permission_principals),
                actual=[json.loads(s) for s in actual.resource_policy_statements],
                extra=stmt,
            )
            for stmt in extra_statements
        ]
