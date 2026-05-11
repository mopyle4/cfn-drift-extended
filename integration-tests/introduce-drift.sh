#!/usr/bin/env bash
set -euo pipefail

# Introduce known drift scenarios outside of CloudFormation.
# Run this AFTER deploy.sh to create detectable drift.

REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "=== Introducing Known Drift Scenarios ==="
echo "Account: ${ACCOUNT_ID}"
echo "Region:  ${REGION}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1: Add an extra inline policy to BasicLambdaRole
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 1: Adding extra inline policy to drift-test-basic-lambda..."
aws iam put-role-policy \
    --role-name drift-test-basic-lambda \
    --policy-name ManualS3Access \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::some-manual-bucket/*"
        }]
    }'
echo "  ✓ Added inline policy 'ManualS3Access'"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2: Attach an extra managed policy to BasicLambdaRole
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 2: Attaching extra managed policy to drift-test-basic-lambda..."
aws iam attach-role-policy \
    --role-name drift-test-basic-lambda \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
echo "  ✓ Attached 'AmazonS3ReadOnlyAccess'"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3: Modify existing inline policy on ProcessorRole (add statement)
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 3: Modifying existing inline policy on drift-test-processor..."
aws iam put-role-policy \
    --role-name drift-test-processor \
    --policy-name SQSAccess \
    --policy-document "{
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Effect\": \"Allow\",
                \"Action\": [\"sqs:ReceiveMessage\", \"sqs:DeleteMessage\"],
                \"Resource\": \"arn:aws:sqs:${REGION}:${ACCOUNT_ID}:drift-test-queue\"
            },
            {
                \"Effect\": \"Allow\",
                \"Action\": [\"sqs:SendMessage\"],
                \"Resource\": \"arn:aws:sqs:${REGION}:${ACCOUNT_ID}:drift-test-output-queue\"
            }
        ]
    }"
echo "  ✓ Added extra statement to 'SQSAccess' policy"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6: Add multiple policies to MultiDriftRole
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 6: Adding multiple policies to drift-test-multi-drift..."
aws iam put-role-policy \
    --role-name drift-test-multi-drift \
    --policy-name UnauthorizedEC2Access \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*"
        }]
    }'
aws iam put-role-policy \
    --role-name drift-test-multi-drift \
    --policy-name UnauthorizedIAMAccess \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        }]
    }'
aws iam attach-role-policy \
    --role-name drift-test-multi-drift \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
echo "  ✓ Added 2 inline policies + AdministratorAccess"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 7: Add a policy to the bare role
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 7: Adding inline policy to drift-test-bare..."
aws iam put-role-policy \
    --role-name drift-test-bare \
    --policy-name SneakyPolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*"
        }]
    }'
echo "  ✓ Added inline policy 'SneakyPolicy'"

# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4 & 5: NO changes to CdkStyleRole or NestedRole
# These should remain IN_SYNC
# ─────────────────────────────────────────────────────────────────────────────
echo "→ Scenario 4 & 5: No changes to CdkStyleRole or NestedRole (should be in sync)"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Drift introduced successfully!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Expected findings when running cfn-drift-extended:"
echo ""
echo "  drift-test-basic-lambda:"
echo "    - INLINE_POLICY_ADDED: ManualS3Access"
echo "    - MANAGED_POLICY_ATTACHED: AmazonS3ReadOnlyAccess"
echo ""
echo "  drift-test-processor:"
echo "    - INLINE_POLICY_MODIFIED: SQSAccess (extra sqs:SendMessage statement)"
echo ""
echo "  drift-test-cdk-style:"
echo "    - IN_SYNC (no drift expected)"
echo ""
echo "  drift-test-nested-role:"
echo "    - IN_SYNC (no drift expected)"
echo ""
echo "  drift-test-multi-drift:"
echo "    - INLINE_POLICY_ADDED: UnauthorizedEC2Access"
echo "    - INLINE_POLICY_ADDED: UnauthorizedIAMAccess"
echo "    - MANAGED_POLICY_ATTACHED: AdministratorAccess"
echo ""
echo "  drift-test-bare:"
echo "    - INLINE_POLICY_ADDED: SneakyPolicy"
echo ""
echo "Total expected findings: 8"
echo ""
echo "Next step: Run ./validate.sh"
