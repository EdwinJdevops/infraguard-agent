# InfraGuard

InfraGuard is an evidence-first remediation planner for Terraform-managed cloud security
findings. Its first narrow slice can validate a Security Hub CSPM EC2.13 event against live,
read-only EC2 rule evidence, prove a supported Terraform owner, propose a source-CIDR replacement,
and return a validated patch plus review evidence.

**Status: alpha production baseline.** The deterministic planning core and read-only API are
implemented and locally tested. The AWS verifier is a library boundary and is not connected to
runtime AWS clients or a queue worker. InfraGuard does **not** yet clone repositories, create
branches, publish pull requests, run `terraform plan`, or verify a finding after deployment. Do
not describe this repository as production-ready until the release gates in
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
| Trusted finding | Strict Security Hub CSPM ASFF `EC2.13` parser plus independent EC2 rule verification core |
| Runtime AWS intake | Not implemented; no EventBridge/SQS worker, STS composition, or cloud credentials |
| Provider/finding | AWS security group ingress, TCP port range containing 22 |
| Public sources | `0.0.0.0/0` and `::/0` |
| Standalone resources | `aws_security_group_rule` and `aws_vpc_security_group_ingress_rule` |
| Inline `aws_security_group.ingress` | Ownership classification only; always `manual_review` |
| Ownership proof | Automatic standalone remediation requires one root-module `.tf` declaration, one matching state instance, exact security-group/rule semantics, and the verified AWS rule ID in state; source text alone is insufficient |
| Replacement policy | Exact deployment allowlist entry that is RFC1918 IPv4 or IPv6 ULA |
| Patch validation | Targeted one-line source change, HCL parse, target-rule semantic checks |
| Bound analysis core | Git-object snapshot at an expected SHA; source/state/lock/finding manifest; input and completion freshness; conservative Terraform JSON plan policy |
| Production analysis worker | Not implemented; no sandbox executor or authenticated backend acquisition |
| Publication | Not implemented; API always returns `publication: not_attempted` |
| Infrastructure mutation | Never performed |

`decision: auto_pr` means the local planning gates passed. It does not mean a
branch or pull request exists. Only `can_open_pr: true` indicates that decision, patch, validation,
and evidence are all present in the returned planning result. The current HTTP request schema
cannot carry trusted provenance, so direct JSON claims return `manual_review` and no patch.

The internal [bound analysis contract](docs/bound-analysis.md) adds plan evidence gates. It
accepts only a source-only update as an `update_candidate`; a legacy delete/create plan becomes
`replacement_review`. Neither result authorizes publication. Coordinator-supplied expectations
and hashes are integrity checks, not authentication of repository, backend, workspace, or executor.

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

Set `INFRAGUARD_TERRAFORM_STATE_PATH` to a matching local raw state JSON file for any trusted
finding. Automatic standalone remediation is refused without state, and the state must contain
lineage, serial, one unindexed instance at the exact root resource address, matching rule
attributes, and the verified AWS security-group-rule ID. The supported source must use a literal
security group ID, one CIDR source, and no provider override, lifecycle, or provisioner. Indexed,
deposed, tainted, aliased, and conflicting-source state is ineligible. Raw state version 4 is
required; duplicate JSON keys and malformed instances are errors. Roots with `.tf.json` or
override files are rejected. Terraform state can contain secrets;
mount it read-only and do not log, commit, or return it. State authenticity, backend lineage, and
freshness are not established by this local path contract; production intake must acquire and bind
state through a trusted backend workflow.

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

This request demonstrates the authenticated triage contract. Because it is self-reported JSON and
the API has no AWS client, the response is `manual_review`; it cannot produce a patch. Automatic
eligibility is currently reachable only through the internal verified-finding interface exercised
by tests. See [trusted AWS finding provenance](docs/trusted-finding-provenance.md).

The Terraform root must contain exactly one supported resource matching the finding. Unknown or
ambiguous ownership returns `manual_review` or a sanitized `422`; it does not guess.

## Verification

```bash
python -m ruff check api infraguard tests
python -m pytest -q
git diff --check
```

CI repeats lint, tests, Terraform fixture formatting, a container build, and a separate real AWS
provider plan suite. To run that suite with Terraform **1.9.8** installed:

```bash
INFRAGUARD_TERRAFORM_INTEGRATION=1 python -m pytest -q -s tests/integration
```

It pins AWS provider **6.10.0** and verifies the committed dependency lock file. It uses synthetic
state, test-only credentials, loopback EC2/STS endpoints, and `-refresh=false`; it never applies.
It checks the generated patch against the actual provider, including the legacy resource's
replacement behavior. This is integration evidence for these fixtures, not live AWS evidence or
production execution evidence. The suite also evaluates the bound plan policy and rejects
tampered provider JSON. The library gate is not connected to the API or a runtime worker.
HCL parsing alone remains insufficient. HashiCorp documents that
`terraform validate` checks syntax and internal consistency, while
`terraform plan` includes the current configuration and state context:
[Terraform validate](https://developer.hashicorp.com/terraform/cli/commands/validate).
See the [ownership audit](docs/ownership-audit.md) for reproduced defects and remaining blockers.

## Repository map

- `api/`: authenticated, rate-limited, read-only planning API.
- `infraguard/`: deterministic AWS verification, ownership, policy, patching, validation, and
  evidence core.
- `tests/`: unit and component tests plus Terraform fixtures.
- `k8s/`: hardened single-replica planning deployment contract.
- `docs/`: architecture, contracts, operations, threat model, and release gates.
- The unsafe hackathon publisher/model prototype has been removed from the shipping tree. It
  remains available in Git history for archaeology.

Start with the [architecture](docs/architecture.md),
[trusted-finding contract](docs/trusted-finding-provenance.md), [security model](SECURITY.md), and
[production-readiness verdict](docs/production-readiness.md).

## Product direction

The preferred end state is to remove inbound SSH entirely where AWS Systems Manager Session
Manager is viable. AWS documents that Session Manager can provide instance access without opening
inbound ports, maintaining bastion hosts, or managing SSH keys:
[AWS Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html).
The current engine only narrows a CIDR and does not prove Session Manager readiness.

## License

MIT. See [`LICENSE`](LICENSE).
