"""Tests for the orphan detection orchestrator wiring."""

import boto3
from moto import mock_aws

from cfn_drift_extended.orphan_auditor import ALL_ORPHAN_SERVICES, OrphanAuditor


def test_build_detector_tasks_registers_all_services() -> None:
    """All five services are wired up when no filter is supplied."""
    auditor = OrphanAuditor(region="us-east-1")
    tasks = auditor._build_detector_tasks(frozenset())

    assert set(tasks) == set(ALL_ORPHAN_SERVICES)
    assert set(tasks) == {"iam", "sg", "lambda", "sqs", "sns"}


def test_build_detector_tasks_respects_service_filter() -> None:
    """Only requested services get a detector task."""
    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"iam", "sg", "lambda"})
    )
    tasks = auditor._build_detector_tasks(frozenset())

    assert set(tasks) == {"iam", "sg", "lambda"}


@mock_aws
def test_detect_orphans_runs_new_detectors() -> None:
    """End-to-end: IAM, SG, and Lambda orphans are detected with empty index."""
    session = boto3.Session(region_name="us-east-1")

    # An unmanaged IAM role.
    session.client("iam").create_role(
        RoleName="loose-role", AssumeRolePolicyDocument="{}"
    )

    # An unmanaged security group (in addition to the default group).
    ec2 = session.client("ec2")
    vpc_id = ec2.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}]
    )["Vpcs"][0]["VpcId"]
    ec2.create_security_group(
        GroupName="loose-sg", Description="loose", VpcId=vpc_id
    )

    auditor = OrphanAuditor(
        region="us-east-1", services=frozenset({"iam", "sg", "lambda"})
    )
    report = auditor.detect_orphans()

    orphan_types = {f.orphan_type.value for f in report.findings}
    assert "iam_role_orphaned" in orphan_types
    assert "security_group_orphaned" in orphan_types
    assert report.orphans_found >= 2
    assert not report.errors
