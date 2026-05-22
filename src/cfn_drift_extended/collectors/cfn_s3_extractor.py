"""Extract expected S3 bucket state from CloudFormation stack templates.

Handles:
- AWS::S3::Bucket resources (lifecycle rules, CORS rules)
- AWS::S3::BucketPolicy resources (bucket policy statements)

Required IAM permissions (least privilege):
- cloudformation:GetTemplate (already required by CfnCollector)
- cloudformation:DescribeStackResource (already required by CfnCollector)
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExpectedS3State:
    """What CloudFormation declares for an S3 bucket."""

    bucket_name: str
    logical_id: str
    stack_name: str
    # Normalized JSON strings of each declared policy statement
    policy_statements: tuple[str, ...] = field(default_factory=tuple)
    # Declared lifecycle rule IDs
    lifecycle_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    # Normalized JSON strings of each declared CORS rule
    cors_rules: tuple[str, ...] = field(default_factory=tuple)


class CfnS3Extractor:
    """Extracts expected S3 bucket state from CFN template resources."""

    def extract_buckets(
        self,
        resources: dict[str, Any],
        stack_name: str,
        physical_ids: dict[str, str],
    ) -> list[ExpectedS3State]:
        """Extract expected S3 state from a stack's template resources.

        Args:
            resources: The Resources section of the CFN template.
            stack_name: Name of the stack.
            physical_ids: Mapping of logical ID → physical resource ID.

        Returns:
            List of ExpectedS3State for each S3 bucket in the template.
        """
        # Collect bucket policies (separate resources that target buckets)
        bucket_policies: dict[str, list[dict[str, Any]]] = {}
        self._collect_bucket_policies(resources, bucket_policies, physical_ids)

        results: list[ExpectedS3State] = []
        for logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::S3::Bucket":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                properties = {}

            # Physical ID for S3 buckets is the bucket name
            bucket_name = physical_ids.get(logical_id, logical_id)

            lifecycle_rule_ids = self._extract_lifecycle_rule_ids(properties)
            cors_rules = self._extract_cors_rules(properties)

            # Gather policy statements from associated BucketPolicy resources
            raw_statements = (
                bucket_policies.get(logical_id, [])
                + bucket_policies.get(bucket_name, [])
            )
            # Deduplicate while preserving order
            seen: set[str] = set()
            policy_statements: list[str] = []
            for stmt in raw_statements:
                normalized = json.dumps(stmt, sort_keys=True)
                if normalized not in seen:
                    seen.add(normalized)
                    policy_statements.append(normalized)

            results.append(
                ExpectedS3State(
                    bucket_name=bucket_name,
                    logical_id=logical_id,
                    stack_name=stack_name,
                    policy_statements=tuple(policy_statements),
                    lifecycle_rule_ids=tuple(lifecycle_rule_ids),
                    cors_rules=tuple(cors_rules),
                )
            )

        return results

    def _collect_bucket_policies(
        self,
        resources: dict[str, Any],
        bucket_policies: dict[str, list[dict[str, Any]]],
        physical_ids: dict[str, str],
    ) -> None:
        """Collect AWS::S3::BucketPolicy resources and map to target buckets."""
        for _logical_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            if resource_def.get("Type") != "AWS::S3::BucketPolicy":
                continue

            properties = resource_def.get("Properties", {})
            if not isinstance(properties, dict):
                continue

            policy_doc = properties.get("PolicyDocument")
            if not isinstance(policy_doc, dict):
                continue

            statements = policy_doc.get("Statement", [])
            if not isinstance(statements, list):
                continue

            bucket_ref = properties.get("Bucket")
            bucket_key = self._resolve_ref(bucket_ref, physical_ids)
            if not bucket_key:
                continue

            bucket_policies.setdefault(bucket_key, []).extend(
                stmt for stmt in statements if isinstance(stmt, dict)
            )
            # Also store under physical ID if bucket_key is a logical ID
            if bucket_key in physical_ids:
                physical_bucket = physical_ids[bucket_key]
                bucket_policies.setdefault(physical_bucket, []).extend(
                    stmt for stmt in statements if isinstance(stmt, dict)
                )

    def _extract_lifecycle_rule_ids(self, properties: dict[str, Any]) -> list[str]:
        """Extract lifecycle rule IDs from bucket properties."""
        lifecycle_config = properties.get("LifecycleConfiguration", {})
        if not isinstance(lifecycle_config, dict):
            return []
        rules = lifecycle_config.get("Rules", [])
        if not isinstance(rules, list):
            return []
        ids: list[str] = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("Id", "")
            if isinstance(rule_id, str) and rule_id:
                ids.append(rule_id)
        return ids

    def _extract_cors_rules(self, properties: dict[str, Any]) -> list[str]:
        """Extract normalized JSON strings of CORS rules from bucket properties."""
        cors_config = properties.get("CorsConfiguration", {})
        if not isinstance(cors_config, dict):
            return []
        rules = cors_config.get("CorsRules", [])
        if not isinstance(rules, list):
            return []
        return [
            json.dumps(rule, sort_keys=True)
            for rule in rules
            if isinstance(rule, dict)
        ]

    def _resolve_ref(self, value: Any, physical_ids: dict[str, str]) -> str | None:
        """Resolve a Ref or plain string value."""
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            if "Ref" in value:
                ref = value["Ref"]
                if isinstance(ref, str):
                    # Return logical ID so caller can look up by both logical and physical
                    return ref
            if "Fn::GetAtt" in value:
                get_att = value["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) >= 1:
                    logical_id = get_att[0]
                    if isinstance(logical_id, str):
                        return physical_ids.get(logical_id, logical_id)
        return None
