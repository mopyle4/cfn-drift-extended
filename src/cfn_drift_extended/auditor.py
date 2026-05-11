"""Core audit orchestrator that ties collectors and comparators together.

Follows the Single Responsibility Principle: this module only orchestrates
the audit pipeline (collect → compare → aggregate). It delegates all
AWS interaction to collectors and all comparison logic to comparators.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cfn_drift_extended import __version__
from cfn_drift_extended.collectors.cfn_collector import CfnCollector, ExpectedRoleState
from cfn_drift_extended.collectors.iam_collector import IamCollector
from cfn_drift_extended.comparators.iam_comparator import IamComparator
from cfn_drift_extended.exceptions import AWSPermissionError
from cfn_drift_extended.models import AuditReport, ResourceAudit

logger = logging.getLogger(__name__)

# Default concurrency for parallel role auditing
_DEFAULT_MAX_WORKERS = 10

_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
)


class Auditor:
    """Orchestrates the full audit pipeline: collect → compare → report.

    Supports parallel role auditing for performance on stacks with many roles.
    Thread safety: the mutable AuditReport is NOT passed into parallel workers.
    Workers return immutable ResourceAudit objects; errors are collected separately.
    """

    def __init__(
        self,
        region: str,
        session: boto3.Session | None = None,
        max_workers: int = _DEFAULT_MAX_WORKERS,
        profile: str | None = None,
    ) -> None:
        if profile and session is None:
            self._session = boto3.Session(
                region_name=region, profile_name=profile
            )
        else:
            self._session = session or boto3.Session(region_name=region)

        self._region = region
        self._cfn_collector = CfnCollector(region=region, session=self._session)
        self._iam_collector = IamCollector(region=region, session=self._session)
        self._iam_comparator = IamComparator()
        self._max_workers = max_workers

    def audit_stacks(
        self,
        stack_prefix: str = "",
        stack_names: list[str] | None = None,
        tag_filter: dict[str, str] | None = None,
    ) -> AuditReport:
        """Run the full IAM additive drift audit.

        Args:
            stack_prefix: Only stacks whose names start with this prefix are audited.
            stack_names: Explicit list of stack names (overrides prefix).
            tag_filter: Only audit stacks with these tags.

        Returns:
            An AuditReport summarizing all findings.

        Raises:
            AWSPermissionError: If the caller lacks required permissions.
        """
        report = AuditReport(
            tool_version=__version__,
            region=self._region,
            timestamp=datetime.now(UTC).isoformat(),
        )

        # Resolve account ID for report metadata
        report.account_id = self._get_account_id()

        # Discover stacks
        try:
            matched_stacks = self._cfn_collector.list_stacks_by_prefix(
                stack_prefix, stack_names=stack_names, tag_filter=tag_filter
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "AccessDeniedException"):
                raise AWSPermissionError(
                    "Cannot list CloudFormation stacks. "
                    "Ensure the IAM principal has cloudformation:ListStacks permission.",
                    details=str(e),
                ) from e
            raise

        report.stacks_scanned = len(matched_stacks)

        if not matched_stacks:
            logger.warning("No stacks found matching the filter criteria")
            return report

        # Collect all expected roles across stacks (including nested)
        all_expected_roles: list[ExpectedRoleState] = []
        for stack_name in matched_stacks:
            roles = self._cfn_collector.get_iam_roles_from_stack(stack_name)
            all_expected_roles.extend(roles)

        report.resources_scanned = len(all_expected_roles)

        if not all_expected_roles:
            logger.info("No IAM roles found in matched stacks")
            return report

        # Audit roles in parallel for performance
        # Note: report is NOT passed to workers — thread safety by design
        audits, errors = self._audit_roles_parallel(all_expected_roles)

        report.audits = audits
        report.findings = [f for audit in audits for f in audit.findings]
        report.resources_with_drift = sum(1 for audit in audits if not audit.in_sync)
        report.errors = errors

        return report

    def _audit_roles_parallel(
        self, expected_roles: list[ExpectedRoleState]
    ) -> tuple[list[ResourceAudit], list[str]]:
        """Audit multiple roles concurrently using a thread pool.

        Thread-safe: each worker returns an immutable ResourceAudit.
        Errors are collected in a separate list, not mutated on a shared object.

        Returns:
            Tuple of (audits, errors).
        """
        audits: list[ResourceAudit] = []
        errors: list[str] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_role = {
                executor.submit(self._audit_single_role, expected): expected
                for expected in expected_roles
            }

            for future in as_completed(future_to_role):
                expected = future_to_role[future]
                try:
                    audit = future.result()
                    if audit is not None:
                        audits.append(audit)
                except Exception as e:
                    error_msg = (
                        f"Error auditing role '{expected.role_name}' "
                        f"in stack '{expected.stack_name}': {e}"
                    )
                    logger.error(error_msg)
                    errors.append(error_msg)

        return audits, errors

    def _audit_single_role(self, expected: ExpectedRoleState) -> ResourceAudit | None:
        """Audit a single IAM role against its expected state."""
        actual = self._iam_collector.get_role_state(expected.role_name)
        if actual is None:
            logger.warning(
                "Role '%s' declared in stack '%s' not found in IAM — skipping",
                expected.role_name,
                expected.stack_name,
            )
            return None

        return self._iam_comparator.compare(expected, actual)

    def _get_account_id(self) -> str:
        """Get the AWS account ID for report metadata."""
        try:
            sts = self._session.client("sts", config=_BOTO_CONFIG)
            return sts.get_caller_identity()["Account"]
        except Exception:
            logger.debug("Could not determine account ID")
            return "unknown"
