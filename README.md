# cfn-drift-extended

Detect **additive drift** in CloudFormation-managed resources that native drift detection misses.

## The Problem

CloudFormation drift detection only catches modifications or deletions to resources it manages. It completely misses **additive changes** — for example, a manually attached IAM policy on a CDK-managed role. This tool fills that gap.

**Real-world example:** A Lambda function failed in QA but worked in Dev. Root cause: someone had manually attached a broader IAM policy to a CDK-managed role in Dev. CloudFormation showed "IN_SYNC" because the manual addition wasn't a modification — it was an extra policy CFN didn't know about.

## What It Does (v0.1 — MVP)

- Finds all CloudFormation-managed IAM roles by scanning stack resources
- Compares what CFN declares (from the stack template) vs what actually exists in IAM
- Reports **additions**: policies that exist on the role but aren't in the CFN template
  - Extra inline policies
  - Extra attached managed policies
- Outputs as console report + JSON for CI/CD integration
- Exits non-zero when drift is detected (configurable for CI gates)

## Installation

```bash
pip install cfn-drift-extended
```

## Usage

```bash
# Audit all stacks starting with "my-app"
cfn-drift-extended audit --stack-prefix my-app --region us-east-1

# Write JSON report for CI/CD
cfn-drift-extended audit --stack-prefix my-app --output-json report.json

# Don't fail on drift (just report)
cfn-drift-extended audit --stack-prefix my-app --no-fail-on-drift

# Verbose mode for debugging
cfn-drift-extended audit --stack-prefix my-app -v

# Control concurrency
cfn-drift-extended audit --stack-prefix my-app --max-workers 5
```

## Required IAM Permissions (Least Privilege)

This tool uses **read-only** AWS API calls. Here's the minimal IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CfnDriftExtendedReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudformation:ListStacks",
        "cloudformation:GetTemplate",
        "cloudformation:DescribeStackResource",
        "iam:GetRole",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

For tighter scoping, restrict `Resource` to specific stack ARNs and role ARNs.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | No drift detected (or `--no-fail-on-drift` used) |
| 1    | Additive drift detected |
| 2    | Error (permission denied, invalid input, unexpected failure) |

## Example Output

```
════════════════════════════════════════════════════════════════
  cfn-drift-extended — Additive Drift Report
════════════════════════════════════════════════════════════════
  Stacks scanned:    2
  Resources scanned: 5
  Resources drifted: 1

⚠ Found 1 drift finding(s) across 1 resource(s):

  [HIGH] my-app-service-role (my-app-dev)
         Managed policy 'arn:aws:iam::123456789012:policy/ManualBroadAccess'
         is attached to role but is not declared in the CloudFormation template
         + arn:aws:iam::123456789012:policy/ManualBroadAccess
```

## GitHub Action Usage

```yaml
- uses: your-org/cfn-drift-extended@v0.1
  with:
    stack-prefix: "my-app"
    region: "us-east-1"
    fail-on-drift: "true"
    output-json: "drift-report.json"
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  CLI (Click)│────▶│   Auditor    │────▶│  Reporters  │
└─────────────┘     └──────┬───────┘     └─────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
       ┌────────────┐ ┌────────────┐ ┌────────────┐
       │CfnCollector│ │IamCollector│ │IamComparator│
       │(expected)  │ │(actual)    │ │(diff)       │
       └────────────┘ └────────────┘ └────────────┘
```

- **Collectors** gather state (expected from CFN templates, actual from IAM API)
- **Comparators** diff expected vs actual using set operations (O(n))
- **Reporters** format results for different output targets
- **Auditor** orchestrates the pipeline with parallel execution

## Design Principles

- **Least Privilege**: Only read-only API calls; no write operations
- **SOLID**: Single responsibility per module; dependency injection via constructor
- **Immutable Models**: Frozen Pydantic models prevent accidental mutation
- **Graceful Degradation**: Individual role failures don't crash the entire audit
- **Performance**: Parallel role auditing via ThreadPoolExecutor; set operations for O(n) comparison
- **CI/CD Ready**: Exit codes, JSON output, and `--fail-on-drift` flag

## Development

```bash
# Clone and install in dev mode
git clone https://github.com/your-org/cfn-drift-extended.git
cd cfn-drift-extended
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests with coverage
pytest --cov=cfn_drift_extended --cov-report=term-missing

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## Roadmap (v0.2+)

- Lambda environment variable comparison
- DynamoDB GSI permission detection
- Multi-account support via AWS Organizations
- Remediation suggestions ("add this to your CDK code")
- GitHub Action annotations (inline PR comments)

## License

MIT
