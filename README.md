# InfraGuard

InfraGuard is an evidence-first remediation planner for Terraform-managed cloud security
findings. Its first supported slice detects an AWS security group rule that exposes SSH to the
internet, proves which Terraform resource owns that rule, proposes a source-CIDR replacement,
and returns a validated patch plus review evidence.

**Status: alpha production baseline.** The deterministic planning core and read-only API are
implemented and locally tested. InfraGuard does **not** yet clone repositories, create branches,
publish pull requests, run `terraform plan`, or verify a finding after deployment. Do not describe
this repository as production-ready until the release gates in
[`docs/production-readiness.md`](docs/production-readiness.md) are closed.

## Why PR #1 must not merge

The original remediation PR adds a restricted SSH allow rule but leaves the existing
`0.0.0.0/0` rule in place. AWS security group rules are additive, so the effective exposure is
unchanged. That is not a remediation. The replacement baseline changes the source on the
Terraform resource that owns the public rule and proves the target rule no longer contains a
public SSH source.

## Implemented scope

| Capability | Current behavior |
|---|---|
| Provider/finding | AWS security group ingress, TCP port range containing 22 |
| Public sources | `0.0.0.0/0` and `::/0` |
| Standalone resources | `aws_security_group_rule` and `aws_vpc_security_group_ingress_rule` |
| Inline `aws_security_group.ingress` | Ownership classification only; always `manual_review` |
| Ownership proof | Exact literal security-group ID, matching rule state, or a simple root-module security-group reference proven by state |
| Replacement policy | Exact deployment allowlist entry that is RFC1918 IPv4 or IPv6 ULA |
| Patch validation | Targeted one-line source change, HCL parse, target-rule semantic checks |
| Publication | Not implemented; API always returns `publication: not_attempted` |
| Infrastructure mutation | Never performed |

`decision: auto_pr` means the proposal is eligible for a future publisher. It does not mean a
branch or pull request exists. Only `can_open_pr: true` indicates that decision, patch, validation,
and evidence are all present in the returned planning result.

## Quick start

Python 3.12 is the tested runtime.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --requirement requirements-dev.txt
```

Copy `.env.example` values into your process environment. At minimum, configure:

```bash
export INFRAGUARD_API_KEY='replace-with-a-random-secret-at-least-32-characters'
export INFRAGUARD_TERRAFORM_ROOT='/absolute/path/to/a/trusted/terraform-checkout'
export INFRAGUARD_ALLOWED_SSH_CIDRS='10.20.30.40/32,fd00:1234::/64'
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

If the security group is referenced rather than written as a literal ID, set
`INFRAGUARD_TERRAFORM_STATE_PATH` to a matching local state JSON file. Terraform state can contain
secrets; mount it read-only and do not log, commit, or return it.

Example request:

```bash
curl --fail-with-body \
  --request POST http://127.0.0.1:8000/v1/remediation-plans \
  --header "X-API-Key: ${INFRAGUARD_API_KEY}" \
  --header 'Content-Type: application/json' \
  --data '{
    "alert_id": "finding-001",
    "provider": "aws",
    "account_id": "123456789012",
    "region": "us-east-1",
    "resource_type": "aws_security_group",
    "resource_id": "sg-1234567890abcdef0",
    "rule": {
      "direction": "ingress",
      "protocol": "tcp",
      "from_port": 22,
      "to_port": 22,
      "source": "0.0.0.0/0"
    },
    "replacement_source": "10.20.30.40/32"
  }'
```

The Terraform root must contain exactly one supported resource matching the finding. Unknown or
ambiguous ownership returns `manual_review` or a sanitized `422`; it does not guess.

## Verification

```bash
python -m ruff check api infraguard tests
python -m pytest -q
git diff --check
```

CI repeats lint, tests, Terraform fixture formatting, and a container build. HCL parsing is not a
substitute for `terraform validate` or `terraform plan`; those contextual checks remain a release
gate. HashiCorp documents that `terraform validate` checks syntax and internal consistency, while
`terraform plan` includes the current configuration and state context:
[Terraform validate](https://developer.hashicorp.com/terraform/cli/commands/validate).

## Repository map

- `api/`: authenticated, rate-limited, read-only planning API.
- `infraguard/`: deterministic ownership, policy, patching, validation, and evidence core.
- `tests/`: unit and component tests plus Terraform fixtures.
- `k8s/`: hardened single-replica planning deployment contract.
- `docs/`: architecture, contracts, operations, threat model, and release gates.
- The unsafe hackathon publisher/model prototype has been removed from the shipping tree. It
  remains available in Git history for archaeology.

Start with the [architecture](docs/architecture.md), [security model](SECURITY.md), and
[production-readiness verdict](docs/production-readiness.md).

## Product direction

The preferred end state is to remove inbound SSH entirely where AWS Systems Manager Session
Manager is viable. AWS documents that Session Manager can provide instance access without opening
inbound ports, maintaining bastion hosts, or managing SSH keys:
[AWS Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html).
The current engine only narrows a CIDR and does not prove Session Manager readiness.

## License

MIT. See [`LICENSE`](LICENSE).
