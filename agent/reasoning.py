import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

ENDPOINT = os.getenv("AZURE_ENDPOINT").rstrip("/")
API_KEY = os.getenv("AZURE_API_KEY")
MODEL = os.getenv("DEPLOYMENT_NAME")

SYSTEM_PROMPT = """You are InfraGuard, an autonomous cloud infrastructure security reasoning agent.
Analyze the alert and respond ONLY in valid JSON with these exact keys:
{
  "alert_id": "string",
  "root_cause": "string",
  "blast_radius": "string",
  "terraform_fix": "string",
  "confidence_score": 0,
  "pr_title": "string",
  "pr_description": "string"
}"""

def reason_over_alert(alert: dict) -> dict:
    url = f"{ENDPOINT}/models/chat/completions?api-version=2024-05-01-preview"
    headers = {
        "Content-Type": "application/json",
        "api-key": API_KEY
    }
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Alert ID: {alert['id']}\nResource: {alert['resource']}\nIssue: {alert['issue']}\nSeverity: {alert['severity']}"}
        ],
        "max_tokens": 2000,
        "temperature": 0.1
    }
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        return json.loads(content[start:end])
    except:
        return {"raw_response": content, "alert_id": alert["id"]}

if __name__ == "__main__":
    with open("data/mock_alerts.json") as f:
        alerts = json.load(f)
    result = reason_over_alert(alerts[0])
    print(json.dumps(result, indent=2))
