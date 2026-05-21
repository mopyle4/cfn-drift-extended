"""Unit tests for the DynamoDB collector."""

import boto3
from moto import mock_aws

from cfn_drift_extended.collectors.dynamodb_collector import DynamoDBCollector

_TABLE = "my-table"


def _create_table(dynamodb, table_name: str = _TABLE, with_gsi: bool = False) -> None:
    kwargs: dict = {
        "TableName": table_name,
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    }
    if with_gsi:
        kwargs["AttributeDefinitions"].append(
            {"AttributeName": "sk", "AttributeType": "S"}
        )
        kwargs["GlobalSecondaryIndexes"] = [
            {
                "IndexName": "sk-index",
                "KeySchema": [{"AttributeName": "sk", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ]
    dynamodb.create_table(**kwargs)


@mock_aws
def test_get_table_state_basic() -> None:
    session = boto3.Session(region_name="us-east-1")
    dynamodb = session.client("dynamodb")
    _create_table(dynamodb)

    collector = DynamoDBCollector(region="us-east-1", session=session)
    state = collector.get_table_state(_TABLE)

    assert state is not None
    assert state.table_name == _TABLE
    assert state.gsi_names == ()
    assert state.scaling_target_ids == ()
    assert state.scaling_policy_names == ()


@mock_aws
def test_get_table_state_with_gsis() -> None:
    session = boto3.Session(region_name="us-east-1")
    dynamodb = session.client("dynamodb")
    _create_table(dynamodb, with_gsi=True)

    collector = DynamoDBCollector(region="us-east-1", session=session)
    state = collector.get_table_state(_TABLE)

    assert state is not None
    assert "sk-index" in state.gsi_names


@mock_aws
def test_get_table_state_with_scaling() -> None:
    session = boto3.Session(region_name="us-east-1")
    dynamodb = session.client("dynamodb")
    _create_table(dynamodb)

    autoscaling = session.client("application-autoscaling")
    autoscaling.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=f"table/{_TABLE}",
        ScalableDimension="dynamodb:table:ReadCapacityUnits",
        MinCapacity=1,
        MaxCapacity=100,
    )
    autoscaling.put_scaling_policy(
        PolicyName="my-scaling-policy",
        ServiceNamespace="dynamodb",
        ResourceId=f"table/{_TABLE}",
        ScalableDimension="dynamodb:table:ReadCapacityUnits",
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 70.0,
            "PredefinedMetricSpecification": {
                "PredefinedMetricType": "DynamoDBReadCapacityUtilization"
            },
        },
    )

    collector = DynamoDBCollector(region="us-east-1", session=session)
    state = collector.get_table_state(_TABLE)

    assert state is not None
    assert f"table/{_TABLE}" in state.scaling_target_ids
    assert "my-scaling-policy" in state.scaling_policy_names


@mock_aws
def test_get_table_state_not_found() -> None:
    session = boto3.Session(region_name="us-east-1")
    collector = DynamoDBCollector(region="us-east-1", session=session)
    state = collector.get_table_state("nonexistent-table")
    assert state is None


@mock_aws
def test_get_table_state_returns_immutable_state() -> None:
    session = boto3.Session(region_name="us-east-1")
    dynamodb = session.client("dynamodb")
    _create_table(dynamodb, with_gsi=True)

    collector = DynamoDBCollector(region="us-east-1", session=session)
    state = collector.get_table_state(_TABLE)

    assert state is not None
    assert isinstance(state.gsi_names, tuple)
    assert isinstance(state.scaling_target_ids, tuple)
    assert isinstance(state.scaling_policy_names, tuple)


@mock_aws
def test_get_table_state_multiple_gsis() -> None:
    session = boto3.Session(region_name="us-east-1")
    dynamodb = session.client("dynamodb")
    dynamodb.create_table(
        TableName=_TABLE,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsi1pk", "AttributeType": "S"},
            {"AttributeName": "gsi2pk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi1-index",
                "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "gsi2-index",
                "KeySchema": [{"AttributeName": "gsi2pk", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )

    collector = DynamoDBCollector(region="us-east-1", session=session)
    state = collector.get_table_state(_TABLE)

    assert state is not None
    assert set(state.gsi_names) == {"gsi1-index", "gsi2-index"}
