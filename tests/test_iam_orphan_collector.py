"""Unit tests for the IAM orphan collector."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from cfn_drift_extended.collectors.iam_orphan_collector import IamOrphanCollector
from cfn_drift_extended.models import OrphanType, Severity

_TRUST_POLICY = "{}"


def _make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "ListRoles")


@mock_aws
def test_detect_orphaned_roles_returns_empty_when_all_managed() -> None:
    """An account whose only role is in the managed index yields no findings."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    role = iam.create_role(
        RoleName="managed-role", AssumeRolePolicyDocument=_TRUST_POLICY
    )["Role"]
    role_arn = role["Arn"]

    collector = IamOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_roles(frozenset({role_arn}))

    assert findings == []


@mock_aws
def test_detects_orphaned_resource() -> None:
    """A role not in the managed index is flagged as orphaned."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    role = iam.create_role(
        RoleName="orphaned-role", AssumeRolePolicyDocument=_TRUST_POLICY
    )["Role"]
    role_arn = role["Arn"]

    collector = IamOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_roles(frozenset())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.orphan_type == OrphanType.IAM_ROLE_ORPHANED
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "AWS::IAM::Role"
    assert finding.resource_id == role_arn
    assert "orphaned-role" in finding.description


@mock_aws
def test_detects_orphaned_resource_matched_by_name() -> None:
    """A role whose name (not ARN) is in the managed index is NOT flagged."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_role(
        RoleName="name-managed-role", AssumeRolePolicyDocument=_TRUST_POLICY
    )

    collector = IamOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_roles(frozenset({"name-managed-role"}))

    assert findings == []


@mock_aws
def test_exclusion_filter_applied() -> None:
    """Service-linked roles are excluded via is_excluded_iam_role."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    # Service-linked roles live under /aws-service-role/ and must be excluded.
    iam.create_role(
        RoleName="AWSServiceRoleForAutoScaling",
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Path="/aws-service-role/autoscaling.amazonaws.com/",
    )
    # A CDK bootstrap role should also be excluded.
    iam.create_role(
        RoleName="cdk-hnb659fds-deploy-role",
        AssumeRolePolicyDocument=_TRUST_POLICY,
    )

    collector = IamOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_roles(frozenset())

    assert findings == []


@mock_aws
def test_staleness_detection() -> None:
    """A role unused for more than 90 days is described as stale."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_role(
        RoleName="stale-role", AssumeRolePolicyDocument=_TRUST_POLICY
    )

    stale_date = datetime.now(UTC) - timedelta(days=120)
    collector = IamOrphanCollector(session=session, region="us-east-1")

    # moto does not populate RoleLastUsed, so inject it via the list_roles call.
    real_list_roles = collector._list_all_roles

    def _patched_list() -> list[dict]:
        roles = real_list_roles()
        for role in roles:
            role["RoleLastUsed"] = {"LastUsedDate": stale_date}
        return roles

    with patch.object(collector, "_list_all_roles", side_effect=_patched_list):
        findings = collector.detect_orphaned_roles(frozenset())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.last_used is not None
    assert "unused for 120 days" in finding.description


@mock_aws
def test_staleness_recent_not_flagged() -> None:
    """A recently used role is not described as stale or never-used."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_role(
        RoleName="fresh-role", AssumeRolePolicyDocument=_TRUST_POLICY
    )

    recent_date = datetime.now(UTC) - timedelta(days=3)
    collector = IamOrphanCollector(session=session, region="us-east-1")
    real_list_roles = collector._list_all_roles

    def _patched_list() -> list[dict]:
        roles = real_list_roles()
        for role in roles:
            role["RoleLastUsed"] = {"LastUsedDate": recent_date}
        return roles

    with patch.object(collector, "_list_all_roles", side_effect=_patched_list):
        findings = collector.detect_orphaned_roles(frozenset())

    assert len(findings) == 1
    assert "unused for" not in findings[0].description
    assert "never used" not in findings[0].description


@mock_aws
def test_never_used_role_described() -> None:
    """A role with no RoleLastUsed is described as never used."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_role(
        RoleName="never-used-role", AssumeRolePolicyDocument=_TRUST_POLICY
    )

    collector = IamOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_roles(frozenset())

    assert len(findings) == 1
    assert findings[0].last_used is None
    assert "never used" in findings[0].description


@mock_aws
def test_empty_account() -> None:
    """An account with no roles yields no findings."""
    session = boto3.Session(region_name="us-east-1")

    collector = IamOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_roles(frozenset())

    assert findings == []


@mock_aws
def test_access_denied() -> None:
    """A permission error during ListRoles is handled gracefully."""
    session = boto3.Session(region_name="us-east-1")
    collector = IamOrphanCollector(session=session, region="us-east-1")

    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = _make_client_error("AccessDenied")

    with patch.object(
        collector._iam, "get_paginator", return_value=mock_paginator
    ):
        findings = collector.detect_orphaned_roles(frozenset())

    # Should not raise; returns empty list on permission error.
    assert findings == []
