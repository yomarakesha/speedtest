import os

from fastapi import FastAPI

from app.clients import AuditClient, ScanClient
from app.storage import Storage

app = FastAPI(title="netsec-orchestrator")

audit_client = AuditClient(base_url=os.environ.get("AUDIT_SVC_URL", "http://audit-svc:8081"))
scan_client = ScanClient(base_url=os.environ.get("SCAN_SVC_URL", "http://scan-svc:8082"))
storage = Storage(os.environ.get("ORCHESTRATOR_DB", "orchestrator.db"))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
