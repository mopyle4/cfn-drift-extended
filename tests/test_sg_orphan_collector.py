"""Unit tests for the Security Group orphan collector."""

from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from cfn_drift_extended.collectors.sg_orphan_collector import SgOrphanCollector
from cfn_drift_extended.models import OrphanType, Severity


def _make_client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "test"}}, "DescribeSecurityGroups"
    )


def _default_vpc_id(ec2) -> str:
    vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}]
    )["Vpcs"]
    return vpcs[0]["VpcId"]


@mock_aws
def test_detect_orphaned_security_groups_returns_empty_when_all_managed() -> None:
    """A group present in the managed index yields no findings."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    vpc_id = _default_vpc_id(ec2)
    group_id = ec2.create_security_group(
        GroupName="managed-sg", Description="managed", VpcId=vpc_id
    )["GroupId"]

    collector = SgOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_security_groups(frozenset({group_id}))

    assert findings == []


@mock_aws
def test_detects_orphaned_resource() -> None:
    """A security group not in the managed index is flagged as orphaned."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    vpc_id = _default_vpc_id(ec2)
    group_id = ec2.create_security_group(
        GroupName="orphaned-sg", Description="orphaned", VpcId=vpc_id
    )["GroupId"]

    collector = SgOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_security_groups(frozenset())

    # Only the orphaned group — the default group is excluded by the filter.
    assert len(findings) == 1
    finding = findings[0]
    assert finding.orphan_type == OrphanType.SECURITY_GROUP_ORPHANED
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "AWS::EC2::SecurityGroup"
    assert finding.resource_id == group_id
    assert "orphaned-sg" in finding.description


@mock_aws
def test_exclusion_filter_applied() -> None:
    """The default security group is excluded via is_excluded_security_group."""
    session = boto3.Session(region_name="us-east-1")
    # Do not create any extra groups — only the VPC's default group exists.

    collector = SgOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_security_groups(frozenset())

    # The default group must be filtered out.
    assert findings == []


@mock_aws
def test_empty_account() -> None:
    """When no non-default groups exist, no findings are returned."""
    session = boto3.Session(region_name="us-east-1")

    collector = SgOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_security_groups(frozenset())

    assert findings == []


@mock_aws
def test_mixed_managed_and_orphaned() -> None:
    """Only unmanaged, non-default groups are flagged."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    vpc_id = _default_vpc_id(ec2)
    managed_id = ec2.create_security_group(
        GroupName="managed-sg", Description="m", VpcId=vpc_id
    )["GroupId"]
    ec2.create_security_group(
        GroupName="orphan-sg", Description="o", VpcId=vpc_id
    )

    collector = SgOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_security_groups(frozenset({managed_id}))

    assert len(findings) == 1
    assert "orphan-sg" in findings[0].description


@mock_aws
def test_access_denied() -> None:
    """A permission error during DescribeSecurityGroups is handled gracefully."""
    session = boto3.Session(region_name="us-east-1")
    collector = SgOrphanCollector(session=session, region="us-east-1")

    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = _make_client_error(
        "UnauthorizedOperation"
    )

    with patch.object(
        collector._ec2, "get_paginator", return_value=mock_paginator
    ):
        findings = collector.detect_orphaned_security_groups(frozenset())

    assert findings == []


@mock_aws
def test_get_default_vpc_id_returns_none_when_no_default_vpc() -> None:
    """When the account has no default VPC, _get_default_vpc_id returns None."""
    session = boto3.Session(region_name="us-east-1")
    collector = SgOrphanCollector(session=session, region="us-east-1")

    # Stub describe_vpcs to simulate an account with no default VPC.
    with patch.object(
        collector._ec2, "describe_vpcs", return_value={"Vpcs": []}
    ):
        assert collector._get_default_vpc_id() is None


@mock_aws
def test_get_default_vpc_id_returns_none_on_client_error() -> None:
    """A ClientError from describe_vpcs is handled and returns None."""
    session = boto3.Session(region_name="us-east-1")
    collector = SgOrphanCollector(session=session, region="us-east-1")

    error = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "test"}},
        "DescribeVpcs",
    )
    with patch.object(collector._ec2, "describe_vpcs", side_effect=error):
        assert collector._get_default_vpc_id() is None
