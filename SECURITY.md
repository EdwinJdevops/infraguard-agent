# InfraGuard Security Architecture

## Zero Static Credentials Design

InfraGuard is built on the principle that **no static credentials should ever exist**
in the runtime environment. This is enforced at the architecture level, not policy level.

## Authentication Stack

### Azure AI Foundry Access
- Method: Azure Workload Identity (OIDC)
- The AKS pod ServiceAccount is federated with Azure AD
- Short-lived tokens are automatically injected by the Azure AD webhook
- Token lifetime: 1 hour, auto-rotated
- No API keys stored anywhere

### GitHub Access
- Method: GitHub App installation token (short-lived)
- Scoped to single repository: EdwinJdevops/infraguard-agent
- Permissions: contents:write, pull-requests:write only
- Token expires after 1 hour

### API Authentication
- Method: API key via X-API-Key header
- Stored in Kubernetes Secret (not ConfigMap)
- Rate limited: 10 req/min analyze, 5 req/min remediate

## Kubernetes Security Controls

| Control | Implementation |
|---------|---------------|
| Non-root container | runAsUser: 1000 |
| Read-only filesystem | readOnlyRootFilesystem: true |
| No privilege escalation | allowPrivilegeEscalation: false |
| Dropped capabilities | capabilities.drop: ALL |
| Network isolation | NetworkPolicy: deny-by-default |
| RBAC | Least-privilege Role/RoleBinding |
| Secret management | Kubernetes Secrets only |

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Credential theft | No static credentials exist |
| Container escape | Non-root + read-only filesystem |
| Lateral movement | NetworkPolicy isolation |
| API abuse | Rate limiting + API key auth |
| Prompt injection | Input validation + length limits |
| Hallucinated Terraform | Confidence score threshold (>80 only) |

## Least Privilege IAM

InfraGuard only needs:
- Azure: Cognitive Services User (read model, call inference)
- GitHub: contents:write on one repo, pull-requests:write on one repo
- Kubernetes: get/list configmaps and secrets in own namespace only
