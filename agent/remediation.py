import os
import json
import base64
import requests
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

def create_github_pr(analysis: dict) -> str:
    """
    GitOps-compliant PR creation.
    
    The agent NEVER applies changes directly.
    Every fix goes through:
    1. Git branch creation
    2. Terraform artifact commit
    3. PR with full audit context
    4. Human approval gate
    5. Only then merged to main
    
    This preserves GitOps source-of-truth principle.
    """
    
    # Reject low confidence or invalid fixes
    if analysis.get("confidence_score", 0) < 70:
        return f"BLOCKED: Confidence {analysis.get('confidence_score')}% below 70% threshold — no PR created"
    
    terraform = analysis.get("terraform_fix", "")
    if len(terraform) < 30 or "Manual review" in terraform:
        return "BLOCKED: Invalid Terraform — no PR created"
    
    alert_id = analysis["alert_id"]
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    branch = f"infraguard/fix-{alert_id}-{timestamp}"
    
    try:
        # Get main branch SHA
        ref_resp = requests.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/git/ref/heads/main",
            headers=HEADERS
        )
        ref_resp.raise_for_status()
        sha = ref_resp.json()["object"]["sha"]
        
        # Create feature branch
        branch_resp = requests.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/git/refs",
            headers=HEADERS,
            json={"ref": f"refs/heads/{branch}", "sha": sha}
        )
        branch_resp.raise_for_status()
        
        # Build full audit artifact — not just terraform code
        audit_content = f"""# InfraGuard Autonomous Remediation Artifact
# Generated: {datetime.utcnow().isoformat()}Z
# Alert ID: {alert_id}
# Confidence Score: {analysis.get("confidence_score")}%
# Agent Version: 1.0.0
# Model: Phi-4-reasoning (Azure AI Foundry - Foundry IQ)
#
# IMPORTANT: This file was generated autonomously by InfraGuard.
# It has NOT been applied to any environment.
# A human must review and merge this PR to trigger deployment.
# This file is the ONLY authorized path to production change.
#
# Root Cause: {analysis.get("root_cause")}
# Blast Radius: {analysis.get("blast_radius")}
#
# GitOps Compliance: ENFORCED
# Direct API calls to infrastructure: NONE
# Source of truth: This PR

{terraform}
"""
        
        # Commit the artifact to the branch
        encoded = base64.b64encode(audit_content.encode()).decode()
        file_resp = requests.put(
            f"https://api.github.com/repos/{GITHUB_REPO}/contents/fixes/{alert_id}-{timestamp}.tf",
            headers=HEADERS,
            json={
                "message": f"fix({alert_id}): autonomous remediation artifact [{analysis.get('confidence_score')}% confidence]",
                "content": encoded,
                "branch": branch
            }
        )
        file_resp.raise_for_status()
        
        # Build PR body with full audit trail
        pr_body = f"""## 🛡️ InfraGuard Autonomous Remediation

> This PR was created automatically by InfraGuard Agent.
> **No changes have been applied to any environment.**
> This PR is the ONLY authorized path to production.

---

### 📋 Alert Summary

| Field | Value |
|-------|-------|
| Alert ID | `{alert_id}` |
| Confidence Score | `{analysis.get("confidence_score")}%` |
| Model | `Phi-4-reasoning via Azure AI Foundry` |
| Generated | `{datetime.utcnow().isoformat()}Z` |

---

### 🔍 Root Cause Analysis

{analysis.get("root_cause")}

---

### 💥 Blast Radius

{analysis.get("blast_radius")}

---

### 🔧 Proposed Terraform Fix

```hcl
{terraform}
```

---

### ✅ Pre-merge Checklist

- [ ] Root cause analysis reviewed and accurate
- [ ] Terraform code reviewed for correctness
- [ ] Blast radius assessment validated
- [ ] Tested in non-production environment
- [ ] Change management ticket created
- [ ] Security team approval obtained

---

### 🚫 GitOps Compliance Statement

This agent operates under strict GitOps principles:
- ❌ No direct infrastructure API calls
- ❌ No kubectl apply
- ❌ No terraform apply
- ✅ All changes via Pull Request only
- ✅ Human approval required before merge
- ✅ Full audit trail preserved in git history

---

*InfraGuard Agent v1.0.0 | Phi-4-reasoning | Azure AI Foundry | Foundry IQ*
"""
        
        # Create PR
        pr_resp = requests.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/pulls",
            headers=HEADERS,
            json={
                "title": f"🛡️ {analysis['pr_title']}",
                "body": pr_body,
                "head": branch,
                "base": "main",
                "draft": False
            }
        )
        pr_resp.raise_for_status()
        pr_url = pr_resp.json().get("html_url", "PR created")
        
        # Add labels to PR
        pr_number = pr_resp.json().get("number")
        requests.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/issues/{pr_number}/labels",
            headers=HEADERS,
            json={"labels": ["infraguard", "autonomous-remediation", "security"]}
        )
        
        return pr_url
        
    except requests.exceptions.HTTPError as e:
        return f"GitHub API error: {e.response.status_code} - {e.response.text[:200]}"
    except Exception as e:
        return f"PR creation failed: {str(e)}"

if __name__ == "__main__":
    test_analysis = {
        "alert_id": "alert-001",
        "pr_title": "fix: restrict SSH access on production security group",
        "pr_description": "InfraGuard detected unrestricted SSH access",
        "blast_radius": "All EC2 instances in production VPC exposed to internet SSH brute force attacks",
        "root_cause": "Security group ingress rule uses 0.0.0.0/0 CIDR allowing unrestricted internet access to SSH port 22",
        "confidence_score": 92,
        "terraform_fix": """resource "aws_security_group_rule" "restrict_ssh_alert_001" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = var.security_group_id
  description       = "InfraGuard: Restrict SSH to internal network only"
}"""
    }
    url = create_github_pr(test_analysis)
    print(f"Result: {url}")
