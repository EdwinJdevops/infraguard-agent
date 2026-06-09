import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    base_url=os.getenv("AZURE_ENDPOINT") + "/openai/deployments/" + os.getenv("DEPLOYMENT_NAME"),
    api_key=os.getenv("AZURE_API_KEY")
)

SYSTEM_PROMPT = """You are InfraGuard, an autonomous cloud infrastructure security reasoning agent.
When given a cloud infrastructure alert, you must:
1. Analyze the root cause
2. Assess blast radius and business impact  
3. Generate Terraform remediation code
4. Assign confidence score 0-100

Respond ONLY in this JSON format:
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
    prompt = f"Alert ID: {alert['id']}\nResource: {alert['resource']}\nIssue: {alert['issue']}\nSeverity: {alert['severity']}"
    response = client.chat.completions.create(
        model=os.getenv("DEPLOYMENT_NAME"),
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        max_tokens=2000,
        temperature=0.1
    )
    content = response.choices[0].message.content
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
