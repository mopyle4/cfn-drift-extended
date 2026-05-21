"""Extract expected DynamoDB table state from CloudFormation stack templates.

Handles:
- AWS::DynamoDB::Table resources (GSI names)
- AWS::ApplicationAutoScaling::ScalableTarget resources
- AWS::ApplicationAutoScaling::ScalingPolicy resources

Required IAM permissions (least privilege):
- cloudformation:GetTemplate (already required by CfnCollector)
- cloudformation:DescribeStackResource (already required by CfnCollector)
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExpectedDynamoDBState:
    """What CloudFormation declares for a DynamoDB table."""

    table_name: str
    logical_id: str
    stack_name: str
    gsi_names: tuple[str, ...] = field(default_factory=tuple)
    # ResourceId strings like "table/MyTable"
    scaling_target_ids: tuple[str, ...] = field(default_factory=tuple)
    scaling_policy_names: tuple[str, ...] = field(default_factory=tuple)


class CfnDynamoDBExtractor:
    """Extracts expected DynamoDB table state from CFN template resources."""

    def extract_tables(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> list[ExpectedDynamoDBState]:
        """Extract expected DynamoDB state from a stack's template resources.

        Args:
            resources: The Resources section of the CFN template.
            stack_name: Name of the stack.
            physical_ids: Mapping of logical ID → physical resource ID.

        Returns:
            List of ExpectedDynamoDBState for each DynamoDB table in the template.
        """
        # Collect scaling targets and policies grouped by table logical ID
        scaling_targets_by_table: dict[str, list[str]] = {}
        scaling_policies_by_table: dict[str, list[str]] = {}
        self._collect_scaling_resources(
            resources, scaling_targets_by_table, scaling_policies_by_table, physical_ids
        )

        results: list[ExpectedDynamoDBState] = []
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::DynamoDB::Table":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                properties = {}

            # Physical ID for DynamoDB tables is the table name
            table_name = physical_ids.get(logical_id, logical_id)

            gsi_names = self._extract_gsi_names(properties)
            scaling_targets = (
                scaling_targets_by_table.get(logical_id, [])
                + scaling_targets_by_table.get(table_name, [])
            )
            scaling_policies = (
                scaling_policies_by_table.get(logical_id, [])
                + scaling_policies_by_table.get(table_name, [])
            )

            results.append(
                ExpectedDynamoDBState(
                    table_name=table_name,
                    logical_id=logical_id,
                    stack_name=stack_name,
                    gsi_names=tuple(gsi_names),
                    scaling_target_ids=tuple(dict.fromkeys(scaling_targets)),
                    scaling_policy_names=tuple(dict.fromkeys(scaling_policies)),
                )
            )

        return results

    def _extract_gsi_names(self, properties: dict[str, Any]) -> list[str]:
        """Extract GSI names from table properties."""
        gsis = properties.get("GlobalSecondaryIndexes", [])
        if not isinstance(gsis, list):
            return []
        names: list[str] = []
        for gsi in gsis:
            if not isinstance(gsi, dict):
                continue
            name = gsi.get("IndexName", "")
            if isinstance(name, str) and name:
                names.append(name)
        return names

    def _collect_scaling_resources(
        self,
        resources: dict[str, Any],
        scaling_targets_by_table: dict[str, list[str]],
        scaling_policies_by_table: dict[str, list[str]],
        physical_ids: dict[str, str],
    ) -> None:
        """Collect scaling targets and policies and map them to DynamoDB tables."""
        # First pass: collect scalable targets
        scalable_target_logical_ids: dict[str, str] = {}  # logical_id → table_key
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::ApplicationAutoScaling::ScalableTarget":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            service_namespace = properties.get("ServiceNamespace", "")
            if service_namespace != "dynamodb":
                continue

            resource_id = properties.get("ResourceId", "")
            table_key = self._extract_table_key_from_resource_id(
                resource_id, physical_ids
            )
            if not table_key:
                continue

            # The ResourceId value (resolved) is what we track
            resolved_resource_id = self._resolve_value(resource_id, physical_ids)
            if isinstance(resolved_resource_id, str) and resolved_resource_id:
                scaling_targets_by_table.setdefault(table_key, []).append(
                    resolved_resource_id
                )
                scalable_target_logical_ids[logical_id] = table_key

        # Second pass: collect scaling policies
        for _logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::ApplicationAutoScaling::ScalingPolicy":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            policy_name = properties.get("PolicyName", "")
            if not isinstance(policy_name, str) or not policy_name:
                continue

            # Find which table this policy belongs to via ScalingTargetId
            scaling_target_ref = properties.get("ScalingTargetId")
            table_key = self._resolve_scaling_target_ref(
                scaling_target_ref, scalable_target_logical_ids, physical_ids
            )
            if table_key:
                scaling_policies_by_table.setdefault(table_key, []).append(policy_name)

    def _extract_table_key_from_resource_id(
        self, resource_id: Any, physical_ids: dict[str, str]
    ) -> str | None:
        """Extract the table logical or physical ID from a ResourceId value.

        ResourceId for DynamoDB is like "table/MyTable" or
        "table/MyTable/index/MyIndex". We extract the table name part.
        """
        resolved = self._resolve_value(resource_id, physical_ids)
        if isinstance(resolved, str):
            # "table/MyTable" → "MyTable"
            if resolved.startswith("table/"):
                parts = resolved.split("/")
                if len(parts) >= 2:
                    return parts[1]
            return resolved
        # If it's still a dict (unresolved intrinsic), try to get the logical ID
        if isinstance(resource_id, dict) and "Fn::Sub" in resource_id:
            sub_val = resource_id["Fn::Sub"]
            if isinstance(sub_val, str) and "table/" in sub_val:
                # Extract the ${LogicalId} reference
                import re
                match = re.search(r"table/\$\{([^}]+)\}", sub_val)
                if match:
                    return match.group(1)
        return None

    def _resolve_scaling_target_ref(
        self,
        scaling_target_ref: Any,
        scalable_target_logical_ids: dict[str, str],
        physical_ids: dict[str, str],
    ) -> str | None:
        """Resolve a ScalingTargetId reference to a table key."""
        if isinstance(scaling_target_ref, dict) and "Ref" in scaling_target_ref:
            ref = scaling_target_ref["Ref"]
            if isinstance(ref, str):
                return scalable_target_logical_ids.get(ref)
        return None

    def _resolve_value(self, value: Any, physical_ids: dict[str, str]) -> Any:
        """Resolve a simple intrinsic (Ref, Fn::Sub) to a string."""
        if not isinstance(value, dict):
            return value
        if "Ref" in value:
            ref = value["Ref"]
            if isinstance(ref, str):
                return physical_ids.get(ref, ref)
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
