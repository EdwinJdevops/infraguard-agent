# InfraGuard Agent

> Autonomous cloud infrastructure security reasoning and remediation agent powered by Microsoft Phi-4-reasoning via Azure AI Foundry.

## What It Does

InfraGuard is an AI agent that:
1. **Detects** cloud infrastructure security alerts (AWS, Azure)
2. **Reasons** over them using Phi-4-reasoning (multi-step analysis)
3. **Generates** Terraform remediation code automatically
4. **Opens** a GitHub PR with the fix — no human needed

## Architecture
Alert Input → Phi-4-reasoning (Azure AI Foundry) → JSON Analysis → Terraform Fix → GitHub PR

## Microsoft IQ Layer
- **Foundry IQ** — Phi-4-reasoning model via Azure AI Foundry for grounded, cited multi-step reasoning

## Challenge Track
- **Reasoning Agents** — Microsoft Foundry

## Tech Stack
- Python FastAPI
- Azure AI Foundry (Phi-4-reasoning)
- GitHub API (automated PRs)
- Terraform (IaC remediation)

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Agent status |
| `/health` | GET | Health check |
| `/analyze` | POST | Analyze single alert |
| `/remediate` | POST | Analyze + create GitHub PR |
| `/analyze/bulk` | POST | Process all mock alerts |

## Quick Start

```bash
git clone https://github.com/EdwinJdevops/infraguard-agent
cd infraguard-agent
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Add your keys
uvicorn api.main:app --reload --port 8000
```

## Example Alert Input

```json
{
  "id": "alert-001",
  "severity": "high",
  "resource": "aws_security_group",
  "issue": "Unrestricted inbound access on port 22",
  "region": "us-east-1",
  "account": "production"
}
```

## Example Agent Output

```json
{
  "alert_id": "alert-001",
  "root_cause": "Security group misconfiguration allows 0.0.0.0/0 on SSH",
  "blast_radius": "All production instances exposed to internet SSH brute force",
  "terraform_fix": "resource aws_security_group_rule restrict_ssh { ... }",
  "confidence_score": 95,
  "pr_title": "fix: restrict SSH access on production security group",
  "pr_description": "InfraGuard detected and remediated unrestricted SSH access"
}
```

## Built For
Microsoft AI Skill Fest — Agents League Hackathon 2026
