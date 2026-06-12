from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import json
import os
import requests
from dotenv import load_dotenv
import sys
sys.path.append("..")
from agent.reasoning import reason_over_alert, get_reasoning_trace
from agent.remediation import create_github_pr

load_dotenv()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="InfraGuard Agent",
    description="Autonomous cloud infrastructure security reasoning and remediation agent powered by Phi-4-reasoning via Azure AI Foundry",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.state.limiter = limiter

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/dashboard")
def dashboard():
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/dashboard")
def dashboard():
    return FileResponse("static/index.html")


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded. Max 10 requests/minute."})

# API Key auth
API_KEY = os.getenv("INFRAGUARD_API_KEY", "infraguard-demo-key-2026")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key. Include X-API-Key header.")
    return api_key

# Input model with validation
class Alert(BaseModel):
    id: str
    severity: str
    resource: str
    issue: str
    region: str
    account: str

    @validator("severity")
    def validate_severity(cls, v):
        allowed = ["low", "medium", "high", "critical"]
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()

    @validator("id", "resource", "issue", "region", "account")
    def validate_not_empty(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Field cannot be empty")
        if len(v) > 500:
            raise ValueError("Field too long")
        return v.strip()

def send_teams_notification(analysis: dict, pr_url: str):
    webhook_url = os.getenv("TEAMS_WEBHOOK_URL")
    if not webhook_url:
        return
    try:
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if analysis.get("confidence_score", 0) > 80 else "FFA500",
            "summary": f"InfraGuard: {analysis.get('pr_title', 'Alert Remediated')}",
            "sections": [{
                "activityTitle": f"🛡️ InfraGuard Autonomous Remediation",
                "activitySubtitle": f"Alert: {analysis.get('alert_id')}",
                "facts": [
                    {"name": "Root Cause", "value": analysis.get("root_cause", "N/A")},
                    {"name": "Blast Radius", "value": analysis.get("blast_radius", "N/A")},
                    {"name": "Confidence Score", "value": f"{analysis.get('confidence_score', 0)}%"},
                    {"name": "PR Created", "value": pr_url}
                ],
                "markdown": True
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View Pull Request",
                "targets": [{"os": "default", "uri": pr_url}]
            }]
        }
        requests.post(webhook_url, json=card, timeout=10)
    except:
        pass

@app.get("/")
def root():
    return {
        "agent": "InfraGuard",
        "status": "operational",
        "version": "1.0.0",
        "model": "Phi-4-reasoning",
        "iq_layer": "Foundry IQ - Azure AI Foundry",
        "track": "Reasoning Agents",
        "capabilities": ["threat-detection", "root-cause-analysis", "terraform-generation", "github-pr-automation", "teams-notifications"],
        "endpoints": {
            "analyze": "POST /analyze",
            "remediate": "POST /remediate",
            "bulk": "POST /analyze/bulk",
            "docs": "GET /docs"
        }
    }

@app.get("/health")
def health():
    return {"status": "healthy", "agent": "InfraGuard", "version": "1.0.0"}

@app.post("/analyze")
@limiter.limit("10/minute")
async def analyze_alert(request: Request, alert: Alert, api_key: str = Depends(verify_api_key)):
    try:
        result = reason_over_alert(alert.dict())
        return {
            "status": "analyzed",
            "alert_id": alert.id,
            "severity": alert.severity,
            "analysis": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/remediate")
@limiter.limit("5/minute")
async def remediate_alert(request: Request, alert: Alert, api_key: str = Depends(verify_api_key)):
    try:
        analysis = reason_over_alert(alert.dict())
        pr_url = create_github_pr(analysis)
        send_teams_notification(analysis, pr_url)
        return {
            "status": "remediated",
            "alert_id": alert.id,
            "pr_url": pr_url,
            "teams_notified": bool(os.getenv("TEAMS_WEBHOOK_URL")),
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation failed: {str(e)}")

@app.post("/analyze/bulk")
@limiter.limit("2/minute")
async def analyze_bulk(request: Request, api_key: str = Depends(verify_api_key)):
    try:
        with open("data/mock_alerts.json") as f:
            alerts = json.load(f)
        results = []
        for alert in alerts:
            analysis = reason_over_alert(alert)
            results.append(analysis)
        return {
            "status": "completed",
            "total_alerts": len(results),
            "critical": len([r for r in results if r.get("confidence_score", 0) > 90]),
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/reasoning-trace")
@limiter.limit("5/minute")
async def reasoning_trace(request: Request, alert: Alert, api_key: str = Depends(verify_api_key)):
    """
    Returns the full multi-step reasoning chain.
    Demonstrates explicit chain-of-thought for the Reasoning Agents track.
    """
    try:
        result = get_reasoning_trace(alert.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
