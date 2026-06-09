from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
import sys
sys.path.append("..")
from agent.reasoning import reason_over_alert
from agent.remediation import create_github_pr

app = FastAPI(
    title="InfraGuard Agent",
    description="Autonomous cloud infrastructure security reasoning and remediation agent",
    version="1.0.0"
)

class Alert(BaseModel):
    id: str
    severity: str
    resource: str
    issue: str
    region: str
    account: str

@app.get("/")
def root():
    return {
        "agent": "InfraGuard",
        "status": "operational",
        "version": "1.0.0",
        "description": "Autonomous cloud infrastructure remediation agent powered by Phi-4-reasoning"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/analyze")
def analyze_alert(alert: Alert):
    try:
        result = reason_over_alert(alert.dict())
        return {"status": "analyzed", "analysis": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/remediate")
def remediate_alert(alert: Alert):
    try:
        analysis = reason_over_alert(alert.dict())
        pr_url = create_github_pr(analysis)
        return {
            "status": "remediated",
            "analysis": analysis,
            "pr_url": pr_url
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/bulk")
def analyze_bulk():
    try:
        with open("data/mock_alerts.json") as f:
            alerts = json.load(f)
        results = []
        for alert in alerts:
            analysis = reason_over_alert(alert)
            results.append(analysis)
        return {"status": "completed", "total": len(results), "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
