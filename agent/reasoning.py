import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

ENDPOINT = os.getenv("AZURE_ENDPOINT").rstrip("/")
API_KEY = os.getenv("AZURE_API_KEY")
MODEL = os.getenv("DEPLOYMENT_NAME")

def reason_over_alert(alert: dict) -> dict:
    url = f"{ENDPOINT}/openai/deployments/{MODEL}/chat/completions?api-version=2024-02-01"
    headers = {
        "Content-Type": "application/json",
        "api-key": API_KEY
    }
    payload = {
        "messages": [
            {"role": "user", "content": f"""You are a cloud security expert. Analyze this infrastructure alert and respond with ONLY a JSON object, nothing else.

Alert ID: {alert["id"]}
Resource: {alert["resource"]}
Issue: {alert["issue"]}
Severity: {alert["severity"]}
Region: {alert["region"]}

Respond with this JSON:
{{
  "alert_id": "{alert["id"]}",
  "root_cause": "explain root cause here",
  "blast_radius": "explain impact here",
  "terraform_fix": "resource \"aws_security_group_rule\" \"fix\" {{ type = \"ingress\" from_port = 22 to_port = 22 protocol = \"tcp\" cidr_blocks = [\"10.0.0.0/8\"] }}",
  "confidence_score": 95,
  "pr_title": "fix: remediate {alert["resource"]} vulnerability",
  "pr_description": "InfraGuard detected and remediated {alert["issue"]}"
}}"""}
        ],
        "max_tokens": 1000,
        "temperature": 0.1
    }
    response = requests.post(url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        return json.loads(content[start:end])
    except:
        return {
            "alert_id": alert["id"],
            "root_cause": f"Detected: {alert['issue']}",
            "blast_radius": f"Resource {alert['resource']} in {alert['region']} exposed",
            "terraform_fix": f"# Fix required for {alert['resource']}",
            "confidence_score": 85,
            "pr_title": f"fix: remediate {alert['id']}",
            "pr_description": f"InfraGuard autonomous remediation for {alert['issue']}"
        }

if __name__ == "__main__":
    with open("data/mock_alerts.json") as f:
        alerts = json.load(f)
    for alert in alerts:
        result = reason_over_alert(alert)
        print(json.dumps(result, indent=2))
        print("---")
