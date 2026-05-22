"""Unit tests for the Lambda collector."""

import json

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.lambda_collector import LambdaCollector

_ROLE_NAME = "lambda-role"
_LAYER_ARN = "arn:aws:lambda:us-east-1:123456789012:layer:my-layer:1"

_TRUST_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}"""


def _create_role(session: boto3.Session) -> str:
    """Create an IAM role that Lambda can assume and return its ARN."""
    iam = session.client("iam")
    resp = iam.create_role(
        RoleName=_ROLE_NAME,
        AssumeRolePolicyDocument=_TRUST_POLICY,
    )
    return resp["Role"]["Arn"]


def _create_function(
    lam,
    role_arn: str,
    name: str = "my-function",
    env_vars: dict | None = None,
    layers: list[str] | None = None,
) -> None:
    kwargs: dict = {
        "FunctionName": name,
        "Runtime": "python3.11",
        "Role": role_arn,
        "Handler": "index.handler",
        "Code": {"ZipFile": b"def handler(e, c): pass"},
    }
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    if layers:
        kwargs["Layers"] = layers
    lam.create_function(**kwargs)


@mock_aws
def test_get_function_state_basic() -> None:
    session = boto3.Session(region_name="us-east-1")
    lam = session.client("lambda")
    role_arn = _create_role(session)
    _create_function(lam, role_arn)

    collector = LambdaCollector(region="us-east-1", session=session)
    state = collector.get_function_state("my-function")

    assert state is not None
    assert state.function_name == "my-function"
    assert state.environment_variables == {}
    assert state.layer_arns == ()
    assert state.resource_policy_statements == ()


@mock_aws
def test_get_function_state_with_env_vars() -> None:
    session = boto3.Session(region_name="us-east-1")
    lam = session.client("lambda")
    role_arn = _create_role(session)
    _create_function(lam, role_arn, env_vars={"DB_HOST": "localhost", "LOG_LEVEL": "INFO"})

    collector = LambdaCollector(region="us-east-1", session=session)
    state = collector.get_function_state("my-function")

    assert state is not None
    assert state.environment_variables == {"DB_HOST": "localhost", "LOG_LEVEL": "INFO"}


@mock_aws
def test_get_function_state_with_layers() -> None:
    session = boto3.Session(region_name="us-east-1")
    lam = session.client("lambda")
    role_arn = _create_role(session)

    # Create a layer version first
    lam.publish_layer_version(
        LayerName="my-layer",
        Content={"ZipFile": b"layer content"},
        CompatibleRuntimes=["python3.11"],
    )
    _create_function(lam, role_arn, layers=[_LAYER_ARN])

    collector = LambdaCollector(region="us-east-1", session=session)
    state = collector.get_function_state("my-function")

    assert state is not None
    assert len(state.layer_arns) == 1
    assert _LAYER_ARN in state.layer_arns


@mock_aws
def test_get_function_state_with_resource_policy() -> None:
    session = boto3.Session(region_name="us-east-1")
    lam = session.client("lambda")
    role_arn = _create_role(session)
    _create_function(lam, role_arn)

    # Add a resource-based policy statement
    lam.add_permission(
        FunctionName="my-function",
        StatementId="AllowS3Invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn="arn:aws:s3:::my-bucket",
    )

    collector = LambdaCollector(region="us-east-1", session=session)
    state = collector.get_function_state("my-function")

    assert state is not None
    assert len(state.resource_policy_statements) == 1
    stmt = json.loads(state.resource_policy_statements[0])
    assert stmt["Sid"] == "AllowS3Invoke"


@mock_aws
def test_get_function_state_not_found() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = LambdaCollector(region="us-east-1", session=session)
    state = collector.get_function_state("nonexistent-function")
    assert state is None


@mock_aws
def test_get_function_state_no_policy_returns_empty_tuple() -> None:
    """A function with no resource policy should return empty tuple, not None."""
    session = boto3.Session(region_name="us-east-1")
    lam = session.client("lambda")
    role_arn = _create_role(session)
    _create_function(lam, role_arn)

    collector = LambdaCollector(region="us-east-1", session=session)
    state = collector.get_function_state("my-function")

    assert state is not None
    assert state.resource_policy_statements == ()


@mock_aws
def test_get_function_state_returns_immutable_state() -> None:
    session = boto3.Session(region_name="us-east-1")
    lam = session.client("lambda")
    role_arn = _create_role(session)

    # Publish the layer so it exists before attaching it
    lam.publish_layer_version(
        LayerName="my-layer",
        Content={"ZipFile": b"layer content"},
        CompatibleRuntimes=["python3.11"],
    )
    _create_function(lam, role_arn, env_vars={"KEY": "val"}, layers=[_LAYER_ARN])

    collector = LambdaCollector(region="us-east-1", session=session)
    state = collector.get_function_state("my-function")

    assert state is not None
    assert isinstance(state.layer_arns, tuple)
    assert isinstance(state.resource_policy_statements, tuple)
