# Kubernetes Deployment Contract

These manifests deploy the read-only remediation planning API. They do not publish pull requests
or apply Terraform.

## Required operator-provided resources

- `Secret/infraguard-secrets` with an `api-key` value of at least 32 characters.
- `PersistentVolumeClaim/infraguard-terraform-workspace` containing a trusted Terraform checkout.
- `ConfigMap/infraguard-policy` with an `allowed-ssh-cidrs` comma-separated allowlist.
- An ingress controller in the `ingress-nginx` namespace, or an adjusted NetworkPolicy.
- The example `ghcr.io/edwinjdevops/infraguard-agent:0.2.0` image reference must be replaced with
  a built, scanned, signed, and published digest before production use. A version tag is not
  immutable.

The pod has no Kubernetes API permissions and does not mount a service-account token. The Terraform
workspace is mounted read-only. Network egress is denied because the current planning API has no
outbound dependency.

The in-memory rate limiter is per process. Keep one replica until a shared limiter is implemented,
or enforce distributed rate limits at the ingress/API gateway.

These manifests have only been checked as YAML in the current development environment. They have
not yet passed target-cluster schema validation, admission policy, probe, storage, ingress, or
NetworkPolicy enforcement tests.
