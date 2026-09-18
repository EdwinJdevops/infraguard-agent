# Operations runbook

This runbook covers the current read-only API. It does not cover a publisher or a deployed AWS
verification worker because neither exists. A pure AWS verification core exists but is not wired to
runtime clients, IAM, EventBridge, SQS, or durable state.

## Preconditions

- Python 3.12 or an image built from this repository.
- A trusted, read-only Terraform checkout.
- Optional matching Terraform state acquired through an approved confidential path.
- A random API key of at least 32 characters.
- A deployment-owned replacement CIDR allowlist.
- TLS and client identity controls at the ingress/API gateway for any non-local deployment.

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `INFRAGUARD_API_KEY` | Yes | Baseline shared-secret authentication |
| `INFRAGUARD_TERRAFORM_ROOT` | Yes | Absolute path to trusted Terraform source |
| `INFRAGUARD_ALLOWED_SSH_CIDRS` | Yes | Comma-separated exact CIDR allowlist |
| `INFRAGUARD_TERRAFORM_STATE_PATH` | No | Local state JSON for identity correlation |
| `INFRAGUARD_ENVIRONMENT` | No | Environment label; defaults to `development` |
| `INFRAGUARD_DOCS_ENABLED` | No | Enables `/docs` and OpenAPI; defaults to false |

The state file may contain secrets. Never mount a developer's broad workspace or home directory.

## Startup and checks

Run:

```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --no-access-log
```

Probe behavior:

- `GET /livez`: process liveness only.
- `GET /readyz`: required configuration and local file readiness.
- `GET /health`: alias of readiness.

A ready response does not prove source freshness, AWS truth, GitHub access, or Terraform plan
safety.

## Expected request outcomes

| HTTP/result | Operator meaning | Action |
|---|---|---|
| `200 manual_review` | Direct claim lacks AWS provenance, or ownership/edit support is insufficient | Route to trusted intake/human review; do not force automation |
| `200 reject` | Finding/replacement violates capability or policy | Correct the input/policy through controlled change |
| `401` | API key missing or invalid | Check caller identity/secret rotation; investigate repeated failures |
| `422` | Invalid request; future trusted callers may also use it for unsafe Terraform evidence | Inspect trusted internal logs using request ID; do not expose parser internals to caller |
| `429` | Per-process rate limit exceeded | Apply backoff; investigate abuse or caller loops |
| `503` | Required configuration unavailable | Check `/readyz`; keep traffic out until corrected |

## Incident procedures

### Suspected API-key compromise

1. Remove service traffic at the ingress.
2. Rotate `INFRAGUARD_API_KEY` and restart the pod/process.
3. Review request logs by request ID and source identity/address.
4. Check whether sensitive diffs or evidence were returned.
5. Record the incident. The current key has no GitHub/AWS privilege, which limits impact to reading
   generated planning output, but Terraform details may still be sensitive.

### Incorrect or unsafe proposal

1. Stop serving the affected Terraform workspace.
2. Preserve request ID, finding payload, repository/base commit, policy configuration, and returned
   evidence without storing real state in an insecure location.
3. Reproduce against an isolated copy and add a regression test before any fix.
4. Treat an ownership false positive or unrelated diff as a security incident.
5. Do not manually publish the proposal merely because local HCL checks passed.

### Terraform source/state mismatch

1. Mark the request `manual_review`; do not refresh or modify state from the API pod.
2. Verify workspace, backend, account, region, state lineage/serial, and base commit through the
   owning IaC pipeline.
3. Re-run only after a consistent immutable snapshot is available.

### Resource pressure or request flood

1. Throttle or block at the ingress/API gateway.
2. Keep one replica; adding replicas bypasses the aggregate in-memory rate limit.
3. Capture CPU/memory/request-size evidence.
4. Implement shared limiting and bounded worker execution before scaling.

## Deployment and rollback

The repository does not yet publish a verified image. Before deployment, CI must build, scan, sign,
and publish an immutable digest. Pin the Kubernetes deployment to that digest, validate manifests
against the target cluster, and exercise probes and NetworkPolicy enforcement.

Rollback is a normal deployment rollback to the last verified digest. Because the current API does
not write external systems, rollback does not require reverting created branches, PRs, or AWS
changes. That statement will change when a publisher is introduced.

## Logging and telemetry gaps

The code emits limited standard logs and request IDs but does not provide structured audit events,
metrics, traces, dashboards, SLOs, or durable retention. Avoid logging bodies, API keys, state, or
full Terraform source. Production observability is an open release gate.

## Kubernetes-specific notes

The supplied manifests use one non-root replica, a read-only source PVC, no service-account token,
read-only root filesystem, dropped Linux capabilities, RuntimeDefault seccomp, and deny-all egress.
See [`../k8s/README.md`](../k8s/README.md) for required resources and limitations.
