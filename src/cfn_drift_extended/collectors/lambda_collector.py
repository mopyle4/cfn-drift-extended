"""Collect actual Lambda function state from AWS.

Required IAM permissions (least privilege):
- lambda:GetFunctionConfiguration
- lambda:GetPolicy
"""

import json
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
class ActualLambdaState:
    """What actually exists on a Lambda function in AWS."""

    function_name: str
    environment_variables: dict[str, str] = field(default_factory=dict)
    layer_arns: tuple[str, ...] = field(default_factory=tuple)
    # Normalized JSON strings of each resource policy statement
    resource_policy_statements: tuple[str, ...] = field(default_factory=tuple)


class LambdaCollector:
    """Collects actual Lambda function state from the AWS Lambda API.

    Features:
    - Adaptive retry with exponential backoff
    - Read-only API calls (least privilege)
    - Returns None on not-found/access-denied (graceful degradation)
    """

    def __init__(self, region: str, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session(region_name=region)
        self._lambda = self._session.client("lambda", config=_BOTO_CONFIG)

    def get_function_state(self, function_name: str) -> ActualLambdaState | None:
        """Get the actual state of a Lambda function.

        Returns None if the function doesn't exist or cannot be accessed.
        """
        try:
            config = self._lambda.get_function_configuration(
                FunctionName=function_name
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                logger.warning(
                    "Lambda function '%s' does not exist", function_name
                )
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied accessing Lambda function '%s'. "
                    "Ensure lambda:GetFunctionConfiguration permission is granted.",
                    function_name,
                )
            else:
                logger.error(
                    "Unexpected error fetching Lambda function '%s': %s",
                    function_name,
                    error_code,
                )
            return None

        env_vars = self._extract_env_vars(config)
        layer_arns = self._extract_layer_arns(config)
        policy_statements = self._get_resource_policy_statements(function_name)

        return ActualLambdaState(
            function_name=function_name,
            environment_variables=env_vars,
            layer_arns=tuple(layer_arns),
            resource_policy_statements=tuple(policy_statements),
        )

    def _extract_env_vars(self, config: dict[str, Any]) -> dict[str, str]:
        """Extract environment variables from function configuration."""
        env = config.get("Environment", {})
        if not isinstance(env, dict):
            return {}
        variables = env.get("Variables", {})
        if not isinstance(variables, dict):
            return {}
        return {k: v for k, v in variables.items() if isinstance(k, str) and isinstance(v, str)}

    def _extract_layer_arns(self, config: dict[str, Any]) -> list[str]:
        """Extract layer ARNs from function configuration."""
        layers = config.get("Layers", [])
        if not isinstance(layers, list):
            return []
        arns: list[str] = []
        for layer in layers:
            if isinstance(layer, dict):
                arn = layer.get("Arn", "")
                if isinstance(arn, str) and arn:
                    arns.append(arn)
        return arns

    def _get_resource_policy_statements(self, function_name: str) -> list[str]:
        """Get normalized JSON strings of each resource policy statement.

        Returns an empty list if no policy exists (ResourceNotFoundException).
        """
        try:
            response = self._lambda.get_policy(FunctionName=function_name)
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
            if error_code == "ResourceNotFoundException":
                # No resource policy — this is normal, not an error
                return []
            elif error_code in ("AccessDenied", "AccessDeniedException"):
                logger.error(
                    "Permission denied accessing policy for Lambda function '%s'. "
                    "Ensure lambda:GetPolicy permission is granted.",
                    function_name,
                )
            else:
                logger.error(
                    "Unexpected error fetching policy for Lambda function '%s': %s",
                    function_name,
                    error_code,
                )
            return []
