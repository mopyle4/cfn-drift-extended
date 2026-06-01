"""Unit tests for the Lambda orphan collector."""

import io
import zipfile
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from cfn_drift_extended.collectors.lambda_orphan_collector import (
    LambdaOrphanCollector,
)
from cfn_drift_extended.models import OrphanType, Severity


def _make_client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "test"}}, "ListFunctions"
    )


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return 'ok'\n")
    return buf.getvalue()


def _create_function(session: boto3.Session, name: str) -> str:
    """Create a Lambda function and return its ARN."""
    iam = session.client("iam")
    role_arn = iam.create_role(
        RoleName=f"{name}-role", AssumeRolePolicyDocument="{}"
    )["Role"]["Arn"]
    lam = session.client("lambda")
    result = lam.create_function(
        FunctionName=name,
        Runtime="python3.11",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_bytes()},
    )
    return result["FunctionArn"]


def _patch_recent_invocation(collector: LambdaOrphanCollector) -> None:
    """Make _get_last_invocation report a fresh invocation for all functions."""
    recent = datetime.now(UTC) - timedelta(days=1)
    collector._get_last_invocation = MagicMock(return_value=recent)  # type: ignore[method-assign]


@mock_aws
def test_detect_orphaned_functions_returns_empty_when_all_managed() -> None:
    """A function present in the managed index yields no findings."""
    session = boto3.Session(region_name="us-east-1")
    function_arn = _create_function(session, "managed-func")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_functions(frozenset({function_arn}))

    assert findings == []


@mock_aws
def test_detect_orphaned_functions_skips_function_matched_by_name() -> None:
    """A function whose name is in the managed index is NOT flagged."""
    session = boto3.Session(region_name="us-east-1")
    _create_function(session, "name-managed-func")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_functions(frozenset({"name-managed-func"}))

    assert findings == []


@mock_aws
def test_detects_orphaned_resource() -> None:
    """A function not in the managed index is flagged as orphaned."""
    session = boto3.Session(region_name="us-east-1")
    function_arn = _create_function(session, "orphaned-func")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    _patch_recent_invocation(collector)
    findings = collector.detect_orphaned_functions(frozenset())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.orphan_type == OrphanType.LAMBDA_FUNCTION_ORPHANED
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "AWS::Lambda::Function"
    assert finding.resource_id == function_arn
    assert "orphaned-func" in finding.description


@mock_aws
def test_exclusion_filter_applied() -> None:
    """CDK custom-resource handlers are excluded via is_excluded_lambda."""
    session = boto3.Session(region_name="us-east-1")
    _create_function(session, "LogRetentionaae0aa3c5b4d")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_functions(frozenset())

    assert findings == []


@mock_aws
def test_staleness_detection() -> None:
    """A function not modified for more than 90 days is described as stale."""
    session = boto3.Session(region_name="us-east-1")
    _create_function(session, "stale-func")

    stale_ts = (
        (datetime.now(UTC) - timedelta(days=200))
        .strftime("%Y-%m-%dT%H:%M:%S.%f")
        + "+0000"
    )
    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    _patch_recent_invocation(collector)
    real_list = collector._list_all_functions

    def _patched_list() -> list[dict]:
        functions = real_list()
        for fn in functions:
            fn["LastModified"] = stale_ts
        return functions

    with patch.object(collector, "_list_all_functions", side_effect=_patched_list):
        findings = collector.detect_orphaned_functions(frozenset())

    assert len(findings) == 1
    assert "not modified for 200 days" in findings[0].description


@mock_aws
def test_staleness_recent_not_flagged() -> None:
    """A recently modified, recently invoked function is not described as stale."""
    session = boto3.Session(region_name="us-east-1")
    _create_function(session, "fresh-func")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    _patch_recent_invocation(collector)
    findings = collector.detect_orphaned_functions(frozenset())

    assert len(findings) == 1
    description = findings[0].description
    assert "not modified for" not in description
    assert "not invoked" not in description
    assert "last invoked" not in description


@mock_aws
def test_never_invoked_described() -> None:
    """A function with no CloudWatch invocation datapoints is described as never invoked."""
    session = boto3.Session(region_name="us-east-1")
    _create_function(session, "never-invoked")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    # Force the CloudWatch lookup to report no datapoints.
    collector._get_last_invocation = MagicMock(return_value=None)  # type: ignore[method-assign]

    findings = collector.detect_orphaned_functions(frozenset())

    assert len(findings) == 1
    finding = findings[0]
    assert "not invoked in the last" in finding.description
    # last_used falls back to LastModified when there is no invocation data.
    assert finding.last_used is not None


@mock_aws
def test_recently_modified_but_never_invoked_is_flagged() -> None:
    """A function modified yesterday but never invoked is still flagged as never invoked."""
    session = boto3.Session(region_name="us-east-1")
    _create_function(session, "modified-not-invoked")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    collector._get_last_invocation = MagicMock(return_value=None)  # type: ignore[method-assign]

    findings = collector.detect_orphaned_functions(frozenset())

    assert len(findings) == 1
    description = findings[0].description
    # Modified recently, so no "not modified" suffix.
    assert "not modified for" not in description
    # But the invocation gap should still surface.
    assert "not invoked in the last" in description


@mock_aws
def test_last_invocation_uses_latest_nonzero_datapoint() -> None:
    """_get_last_invocation returns the timestamp of the latest non-zero datapoint."""
    session = boto3.Session(region_name="us-east-1")
    collector = LambdaOrphanCollector(session=session, region="us-east-1")

    older = datetime.now(UTC) - timedelta(days=10)
    newer = datetime.now(UTC) - timedelta(days=2)
    response = {
        "Datapoints": [
            {"Timestamp": older, "Sum": 5.0},
            {"Timestamp": newer, "Sum": 3.0},
            # Zero-sum datapoint must be ignored even if it is newest.
            {"Timestamp": datetime.now(UTC), "Sum": 0.0},
        ]
    }
    with patch.object(
        collector._cloudwatch, "get_metric_statistics", return_value=response
    ):
        result = collector._get_last_invocation("any-func")

    assert result == newer


@mock_aws
def test_last_invocation_returns_none_when_no_datapoints() -> None:
    """_get_last_invocation returns None when CloudWatch has no datapoints."""
    session = boto3.Session(region_name="us-east-1")
    collector = LambdaOrphanCollector(session=session, region="us-east-1")

    with patch.object(
        collector._cloudwatch,
        "get_metric_statistics",
        return_value={"Datapoints": []},
    ):
        assert collector._get_last_invocation("any-func") is None


@mock_aws
def test_last_invocation_returns_none_on_client_error() -> None:
    """A ClientError from CloudWatch is handled gracefully."""
    session = boto3.Session(region_name="us-east-1")
    collector = LambdaOrphanCollector(session=session, region="us-east-1")

    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "test"}},
        "GetMetricStatistics",
    )
    with patch.object(
        collector._cloudwatch, "get_metric_statistics", side_effect=error
    ):
        assert collector._get_last_invocation("any-func") is None


@mock_aws
def test_invocation_stale_described() -> None:
    """A function last invoked more than 90 days ago is described as such."""
    session = boto3.Session(region_name="us-east-1")
    _create_function(session, "stale-invoke")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    stale_invocation = datetime.now(UTC) - timedelta(days=120)
    collector._get_last_invocation = MagicMock(return_value=stale_invocation)  # type: ignore[method-assign]

    findings = collector.detect_orphaned_functions(frozenset())

    assert len(findings) == 1
    assert "last invoked 120 days ago" in findings[0].description


@mock_aws
def test_empty_account() -> None:
    """An account with no functions yields no findings."""
    session = boto3.Session(region_name="us-east-1")

    collector = LambdaOrphanCollector(session=session, region="us-east-1")
    findings = collector.detect_orphaned_functions(frozenset())

    assert findings == []


@mock_aws
def test_access_denied() -> None:
    """A permission error during ListFunctions is handled gracefully."""
    session = boto3.Session(region_name="us-east-1")
    collector = LambdaOrphanCollector(session=session, region="us-east-1")

    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = _make_client_error("AccessDeniedException")

    with patch.object(
        collector._lambda, "get_paginator", return_value=mock_paginator
    ):
        findings = collector.detect_orphaned_functions(frozenset())

    assert findings == []
