import os
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException

from app.clients import AuditClient, ScanClient
from app.models import DiscoverAuditJobRequest
from app.storage import Storage

app = FastAPI(title="netsec-orchestrator")

audit_client = AuditClient(base_url=os.environ.get("AUDIT_SVC_URL", "http://audit-svc:8081"))
scan_client = ScanClient(base_url=os.environ.get("SCAN_SVC_URL", "http://scan-svc:8082"))
storage = Storage(os.environ.get("ORCHESTRATOR_DB", "orchestrator.db"))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


async def _run_discover_and_audit(job_id: str, cidr: str, with_dns: bool, active: bool) -> None:
    hosts_out = []
    try:
        hosts = await scan_client.discover(cidr)
    except Exception as exc:  # noqa: BLE001 - persist the failure, don't crash the background task
        storage.save_job(
            job_id, "discover-and-audit", {"cidr": cidr, "hosts": [], "error": str(exc)}
        )
        return

    for host in hosts:
        ip = host["ip"]
        try:
            report = await audit_client.audit(ip, with_dns=with_dns, active=active)
            hosts_out.append({"ip": ip, "audit": report, "error": None})
        except Exception as exc:  # noqa: BLE001 - one host's audit failing shouldn't drop the rest
            hosts_out.append({"ip": ip, "audit": None, "error": str(exc)})

    storage.save_job(job_id, "discover-and-audit", {"cidr": cidr, "hosts": hosts_out})


@app.post("/jobs/discover-and-audit", status_code=202)
async def create_discover_and_audit_job(
    req: DiscoverAuditJobRequest, background_tasks: BackgroundTasks
):
    if req.active and not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="active=true requires authorized=true — intrusive checks need explicit operator authorization",
        )
    job_id = str(uuid.uuid4())
    background_tasks.add_task(_run_discover_and_audit, job_id, req.cidr, req.with_dns, req.active)
    return {"job_id": job_id}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = storage.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job
