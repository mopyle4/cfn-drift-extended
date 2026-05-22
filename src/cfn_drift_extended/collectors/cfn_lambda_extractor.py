"""Extract expected Lambda function state from CloudFormation stack templates.

Handles:
- AWS::Lambda::Function resources (env vars, layers)
- AWS::Lambda::Permission resources (resource-based policy statements)

Required IAM permissions (least privilege):
- cloudformation:GetTemplate (already required by CfnCollector)
- cloudformation:DescribeStackResource (already required by CfnCollector)
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExpectedLambdaState:
    """What CloudFormation declares for a Lambda function."""

    function_name: str
    logical_id: str
    stack_name: str
    environment_variables: dict[str, str] = field(default_factory=dict)
    layer_arns: tuple[str, ...] = field(default_factory=tuple)
    # Each entry is a (Action, Principal) tuple representing a declared permission
    permission_principals: tuple[tuple[str, str], ...] = field(default_factory=tuple)


class CfnLambdaExtractor:
    """Extracts expected Lambda function state from CFN template resources."""

    def extract_functions(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> list[ExpectedLambdaState]:
        """Extract expected Lambda state from a stack's template resources.

        Args:
            resources: The Resources section of the CFN template.
            stack_name: Name of the stack.
            physical_ids: Mapping of logical ID → physical resource ID.

        Returns:
            List of ExpectedLambdaState for each Lambda function in the template.
        """
        # Collect permissions grouped by function logical ID
        permissions_by_function: dict[str, list[tuple[str, str]]] = {}
        self._collect_permissions(resources, permissions_by_function, physical_ids)

        results: list[ExpectedLambdaState] = []
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::Lambda::Function":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                properties = {}

            # Physical ID for Lambda functions is the function name
            function_name = physical_ids.get(logical_id, logical_id)

            env_vars = self._extract_env_vars(properties, physical_ids)
            layer_arns = self._extract_layer_arns(properties, physical_ids)
            permissions = permissions_by_function.get(logical_id, []) + \
                          permissions_by_function.get(function_name, [])

            results.append(
                ExpectedLambdaState(
                    function_name=function_name,
                    logical_id=logical_id,
                    stack_name=stack_name,
                    environment_variables=env_vars,
                    layer_arns=tuple(layer_arns),
                    permission_principals=tuple(permissions),
                )
            )

        return results

    def _extract_env_vars(
        self, properties: dict[str, Any], physical_ids: dict[str, str]
    ) -> dict[str, str]:
        """Extract environment variables from function properties."""
        env = properties.get("Environment", {})
        if not isinstance(env, dict):
            return {}
        variables = env.get("Variables", {})
        if not isinstance(variables, dict):
            return {}
        result: dict[str, str] = {}
        for k, v in variables.items():
            if not isinstance(k, str):
                continue
            if isinstance(v, str):
                result[k] = v
            elif isinstance(v, dict):
                # Resolve intrinsics like Ref or Fn::Sub
                resolved = self._resolve_value(v, physical_ids)
                if isinstance(resolved, str):
                    result[k] = resolved
        return result

    def _extract_layer_arns(
        self, properties: dict[str, Any], physical_ids: dict[str, str]
    ) -> list[str]:
        """Extract layer ARNs from function properties."""
        layers = properties.get("Layers", [])
        if not isinstance(layers, list):
            return []
        arns: list[str] = []
        for layer in layers:
            if isinstance(layer, str):
                arns.append(layer)
            elif isinstance(layer, dict):
                resolved = self._resolve_value(layer, physical_ids)
                if isinstance(resolved, str) and resolved:
                    arns.append(resolved)
        return arns

    def _collect_permissions(
        self,
        resources: dict[str, Any],
        permissions_by_function: dict[str, list[tuple[str, str]]],
        physical_ids: dict[str, str],
    ) -> None:
        """Collect AWS::Lambda::Permission resources and map to target functions."""
        for _logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::Lambda::Permission":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            action = properties.get("Action", "")
            principal = properties.get("Principal", "")
            function_ref = properties.get("FunctionName")

            if not action or not principal or not function_ref:
                continue

            if not isinstance(action, str):
                continue
            if not isinstance(principal, str):
                principal = self._resolve_value(principal, physical_ids)
                if not isinstance(principal, str):
                    continue

            # Resolve the function reference to a logical or physical ID
            function_key = self._resolve_function_ref(function_ref, physical_ids)
            if function_key:
                permissions_by_function.setdefault(function_key, []).append(
                    (action, principal)
                )

    def _resolve_function_ref(
        self, function_ref: Any, physical_ids: dict[str, str]
    ) -> str | None:
        """Resolve a FunctionName reference to a logical or physical ID."""
        if isinstance(function_ref, str):
            return function_ref
        if isinstance(function_ref, dict):
            if "Ref" in function_ref:
                ref = function_ref["Ref"]
                if isinstance(ref, str):
                    return ref  # Return logical ID so we can look up by it
            if "Fn::GetAtt" in function_ref:
                get_att = function_ref["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    logical_id = get_att[0]
                    if isinstance(logical_id, str):
                        return logical_id
        return None

    def _resolve_value(self, value: Any, physical_ids: dict[str, str]) -> Any:
        """Resolve a simple intrinsic (Ref, Fn::GetAtt, Fn::Sub) to a string."""
        if not isinstance(value, dict):
            return value
        if "Ref" in value:
            ref = value["Ref"]
            if isinstance(ref, str):
                return physical_ids.get(ref, ref)
        if "Fn::GetAtt" in value:
            get_att = value["Fn::GetAtt"]
            if isinstance(get_att, list) and len(get_att) >= 1:
                logical_id = get_att[0]
                if isinstance(logical_id, str):
                    return physical_ids.get(logical_id, logical_id)
        if "Fn::Sub" in value:
            sub_val = value["Fn::Sub"]
            if isinstance(sub_val, str):
                return self._resolve_sub(sub_val, physical_ids)
        return value

    def _resolve_sub(self, template: str, physical_ids: dict[str, str]) -> str:
        """Resolve ${LogicalId} references in Fn::Sub strings."""
        import re

        def replace_ref(match: re.Match[str]) -> str:
            ref_name = match.group(1)
            return physical_ids.get(ref_name, match.group(0))

        return re.sub(r"\$\{([^}]+)\}", replace_ref, template)
