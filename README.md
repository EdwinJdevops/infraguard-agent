# 🛡️ InfraGuard Agent

> **The world's first autonomous cloud infrastructure security agent that thinks, decides, and acts — without waiting for a human.**

Built for the Microsoft AI Skill Fest — Agents League Hackathon 2026  
**Track:** Reasoning Agents | **IQ Layer:** Foundry IQ (Phi-4-reasoning)

---

## The Problem Nobody Talks About

Every cloud security team has the same nightmare: alerts fire at 2AM, engineers scramble to understand what happened, manually write Terraform fixes, open PRs, wait for review. The average time from alert to remediation is **4-6 hours**.

InfraGuard collapses that to **under 30 seconds.**

---

## What InfraGuard Does

InfraGuard is an autonomous AI agent that runs a closed-loop remediation cycle:
Cloud Alert → Phi-4 Reasoning → Root Cause Analysis → Terraform Fix → GitHub PR

No dashboards. No tickets. No waiting. The agent detects, thinks, and acts.

---

## Live Demo

| Step | What Happens |
|------|-------------|
| 1. Alert arrives | Security misconfiguration detected in AWS infrastructure |
| 2. Agent reasons | Phi-4-reasoning analyzes root cause, blast radius, and impact |
| 3. Fix generated | Real Terraform HCL remediation code produced automatically |
| 4. PR opened | GitHub Pull Request created with fix, description, and confidence score |
| 5. Human reviews | Engineer approves or rejects — agent learns from the decision |

---

## Architecture
┌─────────────────────────────────────────────────────────┐
│                    InfraGuard Agent                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Alert Input (JSON)                                      │
│       ↓                                                  │
│  Azure AI Foundry (Foundry IQ)                          │
│  Phi-4-reasoning model                                   │
│  Multi-step reasoning chain                              │
│       ↓                                                  │
│  Structured Analysis                                     │
│  • Root cause identification                             │
│  • Blast radius assessment                               │
│  • Confidence scoring (0-100)                            │
│       ↓                                                  │
│  Terraform HCL Generator                                 │
│  • Resource-specific fix generation                      │
│  • Security best practice enforcement                    │
│       ↓                                                  │
│  GitHub PR Automation                                    │
│  • Branch creation                                       │
│  • Fix commit                                            │
│  • PR with full context                                  │
│                                                          │
└─────────────────────────────────────────────────────────┘

---

## Microsoft IQ Integration

InfraGuard uses **Foundry IQ** — the agentic knowledge retrieval layer in Azure AI Foundry.

- **Model:** Phi-4-reasoning (Microsoft's frontier reasoning model)
- **Capability:** Multi-step reasoning over infrastructure security context
- **Output:** Grounded, cited remediation decisions with confidence scores

---

## API Reference

```bash
# Health check
GET /health

# Analyze a single alert
POST /analyze
{
  "id": "alert-001",
  "severity": "high",
  "resource": "aws_security_group",
  "issue": "Unrestricted inbound SSH access",
  "region": "us-east-1",
  "account": "production"
}

# Full autonomous remediation (analyze + GitHub PR)
POST /remediate

# Process all alerts in bulk
POST /analyze/bulk
```

---

## Example Agent Output

**Input:** S3 bucket with public read access enabled

**InfraGuard Response:**
```json
{
  "alert_id": "alert-002",
  "root_cause": "S3 bucket ACL configured with public-read permission, exposing all bucket objects to unauthenticated internet access",
  "blast_radius": "All objects in this S3 bucket are publicly readable — potential data exfiltration of sensitive files, credentials, or PII",
  "terraform_fix": "resource aws_s3_bucket_public_access_block fix { block_public_acls = true block_public_policy = true }",
  "confidence_score": 92,
  "pr_title": "fix: remediate aws_s3_bucket misconfiguration [alert-002]",
  "pr_description": "InfraGuard Autonomous Remediation detected and fixed public S3 bucket exposure"
}
```

---

## Supported Resources

| Resource | Issue Detected | Fix Generated |
|----------|---------------|---------------|
| `aws_security_group` | Unrestricted SSH/RDP access | Ingress rule restriction |
| `aws_s3_bucket` | Public read/write access | Public access block |
| `aws_iam_role` | Wildcard permissions | Least-privilege policy |
| `aws_rds_instance` | Publicly accessible database | Network isolation |

---

## Quick Start

```bash
git clone https://github.com/EdwinJdevops/infraguard-agent
cd infraguard-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your Azure AI Foundry and GitHub credentials
uvicorn api.main:app --reload --port 8000
```

Visit `http://localhost:8000/docs` for the interactive API explorer.

---

## Built By

**Edwin Jonathan** — Cloud & DevOps Engineer  
ALX Africa Cloud DevOps Engineering Programme  
[@EdwinJdevops](https://github.com/EdwinJdevops) | [LinkedIn](https://linkedin.com/in/edwinjonathan)

> *"The future of cloud security isn't more dashboards. It's agents that act."*

---

## Hackathon Submission

- **Event:** Microsoft AI Skill Fest — Agents League Hackathon 2026
- **Track:** Reasoning Agents (Microsoft Foundry)
- **IQ Layer:** Foundry IQ
- **Model:** Phi-4-reasoning
- **Submission Deadline:** June 14, 2026
