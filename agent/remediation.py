import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

def create_github_pr(analysis: dict) -> str:
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPO")
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Get default branch SHA
    ref_url = f"https://api.github.com/repos/{repo}/git/ref/heads/main"
    sha = requests.get(ref_url, headers=headers).json()["object"]["sha"]
    
    # Create branch
    branch = f"fix/{analysis['alert_id']}"
    requests.post(f"https://api.github.com/repos/{repo}/git/refs", 
        headers=headers,
        json={"ref": f"refs/heads/{branch}", "sha": sha}
    )
    
    # Create terraform fix file
    tf_content = analysis.get("terraform_fix", "# No fix generated")
    import base64
    encoded = base64.b64encode(tf_content.encode()).decode()
    requests.put(
        f"https://api.github.com/repos/{repo}/contents/fixes/{analysis['alert_id']}.tf",
        headers=headers,
        json={
            "message": f"fix: {analysis['pr_title']}",
            "content": encoded,
            "branch": branch
        }
    )
    
    # Create PR
    pr = requests.post(
        f"https://api.github.com/repos/{repo}/pulls",
        headers=headers,
        json={
            "title": analysis["pr_title"],
            "body": f"{analysis['pr_description']}\n\n**Confidence Score:** {analysis['confidence_score']}%\n**Blast Radius:** {analysis['blast_radius']}",
            "head": branch,
            "base": "main"
        }
    )
    return pr.json().get("html_url", "PR created")

if __name__ == "__main__":
    test_analysis = {
        "alert_id": "alert-001",
        "pr_title": "fix: restrict SSH access on security group",
        "pr_description": "InfraGuard detected unrestricted SSH access",
        "blast_radius": "All instances in production VPC exposed",
        "confidence_score": 95,
        "terraform_fix": """resource "aws_security_group_rule" "restrict_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  security_group_id = var.sg_id
}"""
    }
    url = create_github_pr(test_analysis)
    print(f"PR created: {url}")
