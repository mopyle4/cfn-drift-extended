"""Tests for console and JSON reporters."""

import json
from pathlib import Path

from cfn_drift_extended.models import (
    AuditReport,
    DriftFinding,
    DriftType,
    OrphanFinding,
    OrphanReport,
    OrphanType,
    Severity,
)
from cfn_drift_extended.reporters.console import ConsoleReporter
from cfn_drift_extended.reporters.json_report import JsonReporter


def _make_finding(
    drift_type: DriftType = DriftType.INLINE_POLICY_ADDED,
    severity: Severity = Severity.HIGH,
    extra: str = "extra-policy",
) -> DriftFinding:
    return DriftFinding(
        resource_type="AWS::IAM::Role",
        resource_id="my-role",
        stack_name="my-stack",
        drift_type=drift_type,
        severity=severity,
        description=f"Test finding for {extra}",
        extra=extra,
    )


def _make_orphan(
    orphan_type: OrphanType = OrphanType.IAM_ROLE_ORPHANED,
    severity: Severity = Severity.HIGH,
    created_date: str | None = "2024-01-01T00:00:00+00:00",
    last_used: str | None = "2024-02-01T00:00:00+00:00",
) -> OrphanFinding:
    return OrphanFinding(
        resource_type="AWS::IAM::Role",
        resource_id="arn:aws:iam::123456789012:role/orphan",
        orphan_type=orphan_type,
        severity=severity,
        description="Orphaned IAM role 'orphan'",
        created_date=created_date,
        last_used=last_used,
        region="us-east-1",
    )


class TestConsoleReporter:
    def test_render_no_drift(self) -> None:
        report = AuditReport(stacks_scanned=2, resources_scanned=5)
        ConsoleReporter().render(report)

    def test_render_with_drift(self) -> None:
        report = AuditReport(
            stacks_scanned=1, resources_scanned=1, resources_with_drift=1,
            findings=[_make_finding()],
        )
        ConsoleReporter().render(report)

    def test_render_finding_without_extra(self) -> None:
        finding = DriftFinding(
            resource_type="AWS::IAM::Role",
            resource_id="my-role",
            stack_name="my-stack",
            drift_type=DriftType.INLINE_POLICY_ADDED,
            severity=Severity.HIGH,
            description="Test",
            extra=None,
        )
        report = AuditReport(
            stacks_scanned=1, resources_scanned=1, resources_with_drift=1,
            findings=[finding],
        )
        ConsoleReporter().render(report)


class TestJsonReporter:
    def test_render_returns_valid_json(self) -> None:
        report = AuditReport(stacks_scanned=3, resources_scanned=10)
        result = JsonReporter().render(report)
        data = json.loads(result)
        assert data["stacks_scanned"] == 3

    def test_render_writes_to_file(self, tmp_path: Path) -> None:
        report = AuditReport(stacks_scanned=1, findings=[_make_finding()])
        output_file = tmp_path / "report.json"
        JsonReporter().render(report, output_path=output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["findings"][0]["extra"] == "extra-policy"

    def test_render_creates_parent_directories(self, tmp_path: Path) -> None:
        output_file = tmp_path / "nested" / "dir" / "report.json"
        JsonReporter().render(AuditReport(), output_path=output_file)
        assert output_file.exists()

    def test_render_includes_metadata(self) -> None:
        report = AuditReport(
            tool_version="0.1.0",
            account_id="123456789012",
            region="us-east-1",
        )
        result = JsonReporter().render(report)
        data = json.loads(result)
        assert data["tool_version"] == "0.1.0"
        assert data["account_id"] == "123456789012"
        assert data["region"] == "us-east-1"
        assert "timestamp" in data


class TestConsoleOrphanReporter:
    def test_render_no_orphans(self) -> None:
        report = OrphanReport(resources_scanned=5, orphans_found=0)
        ConsoleReporter().render_orphans(report)

    def test_render_with_orphans(self) -> None:
        report = OrphanReport(
            resources_scanned=10,
            orphans_found=1,
            findings=[_make_orphan()],
            filters_applied=["Excluded service-linked roles"],
        )
        ConsoleReporter().render_orphans(report)

    def test_render_orphan_without_dates(self) -> None:
        finding = _make_orphan(created_date=None, last_used=None)
        report = OrphanReport(
            resources_scanned=1, orphans_found=1, findings=[finding]
        )
        ConsoleReporter().render_orphans(report)

    def test_render_counts_distinct_services(self) -> None:
        sg_orphan = OrphanFinding(
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-123",
            orphan_type=OrphanType.SECURITY_GROUP_ORPHANED,
            severity=Severity.MEDIUM,
            description="Orphaned SG",
            region="us-east-1",
        )
        report = OrphanReport(
            resources_scanned=5,
            orphans_found=2,
            findings=[_make_orphan(), sg_orphan],
        )
        ConsoleReporter().render_orphans(report)


class TestJsonOrphanReporter:
    def test_render_orphans_returns_valid_json(self) -> None:
        report = OrphanReport(resources_scanned=7, orphans_found=1, findings=[_make_orphan()])
        result = JsonReporter().render_orphans(report)
        data = json.loads(result)
        assert data["resources_scanned"] == 7
        assert data["orphans_found"] == 1
        assert data["findings"][0]["orphan_type"] == "iam_role_orphaned"

    def test_render_orphans_writes_to_file(self, tmp_path: Path) -> None:
        report = OrphanReport(orphans_found=1, findings=[_make_orphan()])
        output_file = tmp_path / "orphans.json"
        JsonReporter().render_orphans(report, output_path=output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["findings"][0]["resource_type"] == "AWS::IAM::Role"

    def test_render_orphans_creates_parent_directories(self, tmp_path: Path) -> None:
        output_file = tmp_path / "nested" / "orphans.json"
        JsonReporter().render_orphans(OrphanReport(), output_path=output_file)
        assert output_file.exists()
