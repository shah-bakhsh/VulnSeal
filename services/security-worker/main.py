from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from scanners.cookie_scanner import PythonCookieSecurityRule

app = FastAPI(
    title="VulnSeal Security Worker",
    version="1.0.0",
    description="Deterministic defensive security scanner and ShadowFix execution worker"
)

class EvaluateCookieRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str]

@app.get("/health")
def health():
    return {"status": "healthy", "service": "vulnseal-security-worker"}

@app.post("/scan/cookie")
def scan_cookie(req: EvaluateCookieRequest):
    result = PythonCookieSecurityRule.evaluate(req.url, req.method, req.headers)
    return result.dict()
