# 🛡️ InfraGuard Agent

> **Autonomous cloud infrastructure security agent that detects threats, reasons with AI, generates Terraform fixes, and opens GitOps-compliant Pull Requests — zero human intervention required.**

[![Live API](https://img.shields.io/badge/API-Live-green)](https://infraguard-agent.onrender.com)
[![Track](https://img.shields.io/badge/Track-Reasoning%20Agents-blue)](https://github.com/EdwinJdevops/infraguard-agent)
[![IQ Layer](https://img.shields.io/badge/IQ%20Layer-Foundry%20IQ-purple)](https://ai.azure.com)
[![Model](https://img.shields.io/badge/Model-Phi--4--reasoning-orange)](https://ai.azure.com)

**Microsoft AI Skill Fest — Agents League Hackathon 2026**
**Track:** Reasoning Agents | **IQ Layer:** Foundry IQ | **Model:** Phi-4-reasoning

---

## The Problem

Every cloud security team shares the same nightmare: alerts fire at 2AM, engineers scramble to understand what happened, manually write Terraform fixes, open PRs, wait for review cycles. The average time from alert to remediation is **4-6 hours**.

Meanwhile the attack surface stays open.

**InfraGuard collapses that window to under 30 seconds.**

---

## What InfraGuard Does

InfraGuard is a fully autonomous reasoning agent that runs a closed-loop remediation cycle:
Cloud Alert → Phi-4-reasoning → Root Cause Analysis → Terraform Fix → GitOps PR → Teams Notification

The agent detects, thinks, generates, and acts. No dashboards. No tickets. No waiting.

---

## Live Demo

🌐 **API:** https://infraguard-agent.onrender.com  
📖 **Docs:** https://infraguard-agent.onrender.com/docs

```bash
# Health check
curl https://infraguard-agent.onrender.com/health   -H "X-API-Key: infraguard-demo-key-2026"

# Analyze a threat
curl -X POST https://infraguard-agent.onrender.com/analyze   -H "Content-Type: application/json"   -H "X-API-Key: infraguard-demo-key-2026"   -d '{
    "id": "alert-001",
    "severity": "high",
    "resource": "aws_security_group",
    "issue": "Security group allows unrestricted inbound access on port 22",
    "region": "us-east-1",
    "account": "production"
  }'

# Full autonomous remediation — creates GitHub PR automatically
curl -X POST https://infraguard-agent.onrender.com/remediate   -H "Content-Type: application/json"   -H "X-API-Key: infraguard-demo-key-2026"   -d '{
    "id": "alert-002",
    "severity": "critical",
    "resource": "aws_s3_bucket",
    "issue": "S3 bucket has public read access enabled",
    "region": "us-east-1",
    "account": "production"
  }'
```

---

## Architecture
┌─────────────────────────────────────────────────────────────────┐
│                      InfraGuard Agent                           │
│                                                                  │
│  Alert Input (JSON API)                                         │
│       ↓                                                          │
│  Input Validation + Rate Limiting + API Key Auth                │
│       ↓                                                          │
│  Azure AI Foundry — Foundry IQ                                  │
│  Phi-4-reasoning (multi-step reasoning chain)                   │
│       ↓                                                          │
│  Structured Analysis                                             │
│  • Root cause identification                                     │
│  • Blast radius assessment                                       │
│  • Confidence scoring (threshold: 70%)                          │
│       ↓                                                          │
│  Confidence Gate — rejects hallucinated output                  │
│       ↓                                                          │
│  Terraform HCL Generator                                        │
│  • Resource-specific remediation code                           │
│  • Security best practice enforcement                           │
│       ↓                                                          │
│  GitOps PR Engine                                               │
│  • Branch creation with timestamp                               │
│  • Audit artifact commit                                        │
│  • PR with full compliance checklist                            │
│  • NO direct infrastructure changes                             │
│       ↓                                                          │
│  Microsoft Teams Webhook Notification                           │
│  • Instant alert to security channel                            │
│  • PR link + confidence score + blast radius                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

---

## Microsoft IQ Integration

InfraGuard uses **Foundry IQ** — the agentic knowledge retrieval layer in Azure AI Foundry.

| Component | Implementation |
|-----------|---------------|
| Model | Phi-4-reasoning (Microsoft frontier reasoning model) |
| Platform | Azure AI Foundry |
| IQ Layer | Foundry IQ |
| Capability | Multi-step reasoning over infrastructure security context |
| Output | Grounded remediation decisions with confidence scores |

---

## Security Architecture

InfraGuard is built on zero-trust principles with no static credentials in the runtime.

| Control | Implementation |
|---------|---------------|
| Authentication | API key via X-API-Key header |
| Rate limiting | 10/min analyze, 5/min remediate |
| Input validation | Pydantic validators, length limits |
| Confidence gate | Rejects output below 70% confidence |
| GitOps compliance | Zero direct infrastructure changes |
| Kubernetes | Non-root, read-only filesystem, NetworkPolicy |
| Secrets | Kubernetes Secrets + Azure Workload Identity OIDC |
| Credentials | No static keys — OIDC token exchange |

See [SECURITY.md](SECURITY.md) for full threat model.

---

## GitOps Compliance

**The agent never applies changes directly to infrastructure.**

Every remediation creates a Pull Request containing:
- Full audit trail with timestamp and model version
- Terraform artifact with compliance header
- Root cause and blast radius analysis
- Confidence score and reasoning chain
- Pre-merge checklist for human review
- GitOps compliance statement

Human approval is the only path to production.

---

## API Reference

| Endpoint | Method | Auth | Rate Limit | Description |
|----------|--------|------|------------|-------------|
| `/` | GET | ✗ | — | Agent status |
| `/health` | GET | ✗ | — | Health check |
| `/docs` | GET | ✗ | — | Interactive API explorer |
| `/analyze` | POST | ✓ | 10/min | Analyze single alert |
| `/remediate` | POST | ✓ | 5/min | Analyze + create GitHub PR + Teams notification |
| `/analyze/bulk` | POST | ✓ | 2/min | Process all mock alerts |

---

## Supported Resources

| Resource | Threat Detected | Terraform Fix |
|----------|----------------|---------------|
| `aws_security_group` | Unrestricted SSH/RDP | Ingress restriction to internal CIDR |
| `aws_s3_bucket` | Public read/write access | S3 public access block |
| `aws_iam_role` | Wildcard permissions | Least-privilege policy |
| `aws_rds_instance` | Publicly accessible DB | Network isolation |

---

## Kubernetes Deployment

```bash
# Deploy to AKS with Workload Identity (no static credentials)
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/networkpolicy.yaml
```

---

## Quick Start (Local)

```bash
git clone https://github.com/EdwinJdevops/infraguard-agent
cd infraguard-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your Azure AI Foundry and GitHub credentials
uvicorn api.main:app --reload --port 8000
# Visit http://localhost:8000/docs
```

---

## Example Output

**Input:** Security group with unrestricted SSH access

**InfraGuard Analysis:**
```json
{
  "alert_id": "alert-001",
  "root_cause": "Security group ingress rule uses 0.0.0.0/0 CIDR allowing unrestricted internet access to SSH port 22, violating least-privilege network access principle",
  "blast_radius": "All EC2 instances attached to this security group in us-east-1 are exposed to SSH brute force and unauthorized remote access from the entire internet",
  "terraform_fix": "resource aws_security_group_rule restrict_ssh { type = ingress, cidr_blocks = [10.0.0.0/8] }",
  "confidence_score": 92,
  "pr_title": "fix: remediate aws_security_group misconfiguration [alert-001]",
  "status": "approved"
}
```

---

## Built By

**Edwin Jonathan** — Cloud & DevOps Engineer  
ALX Africa Cloud DevOps Engineering Programme | AZ-900 Certified  
[GitHub](https://github.com/EdwinJdevops) | [LinkedIn](https://linkedin.com/in/edwinjonathan)

> *"The future of cloud security is not more dashboards. It is agents that think and act."*

---

*Microsoft AI Skill Fest — Agents League Hackathon 2026*
*InfraGuard Agent v1.0.0 | Phi-4-reasoning | Azure AI Foundry | Foundry IQ*
