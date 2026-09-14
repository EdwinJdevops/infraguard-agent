# Kubernetes Deployment Contract

These manifests deploy the read-only remediation planning API. They do not publish pull requests
or apply Terraform.

## Required operator-provided resources

- `Secret/infraguard-secrets` with an `api-key` value of at least 32 characters.
- `PersistentVolumeClaim/infraguard-terraform-workspace` containing a trusted Terraform checkout.
- `ConfigMap/infraguard-policy` with an `allowed-ssh-cidrs` comma-separated allowlist.
- An ingress controller in the `ingress-nginx` namespace, or an adjusted NetworkPolicy.
- The immutable `ghcr.io/edwinjdevops/infraguard-agent:0.2.0` image after it has been built,
  scanned, signed, and published by the release pipeline.

The pod has no Kubernetes API permissions and does not mount a service-account token. The Terraform
workspace is mounted read-only. Network egress is denied because the current planning API has no
outbound dependency.

The in-memory rate limiter is per process. Keep one replica until a shared limiter is implemented,
or enforce distributed rate limits at the ingress/API gateway.
