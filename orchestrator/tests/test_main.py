import httpx
import respx
from fastapi.testclient import TestClient

from app.main import app


def test_healthz():
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@respx.mock
def test_discover_and_audit_job_runs_and_can_be_fetched(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.FINDINGS_LOG_PATH", str(tmp_path / "findings.jsonl"))
    respx.post("http://scan-svc:8082/discover").mock(
        return_value=httpx.Response(200, json={"hosts": [{"ip": "10.0.0.5", "open": []}]})
    )
    respx.post("http://audit-svc:8081/audit").mock(
        return_value=httpx.Response(
            200, json={"target": "10.0.0.5", "findings": [], "grade": "A"}
        )
    )

    client = TestClient(app)
    resp = client.post("/jobs/discover-and-audit", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]
    assert job_id

    fetched = client.get(f"/jobs/{job_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["kind"] == "discover-and-audit"
    assert body["result"]["cidr"] == "10.0.0.0/24"
    assert body["result"]["hosts"][0]["ip"] == "10.0.0.5"
    assert body["result"]["hosts"][0]["audit"]["grade"] == "A"


def test_get_unknown_job_returns_404():
    client = TestClient(app)
    resp = client.get("/jobs/does-not-exist")
    assert resp.status_code == 404


def test_active_without_authorized_is_rejected():
    client = TestClient(app)
    resp = client.post("/jobs/discover-and-audit", json={"cidr": "10.0.0.0/24", "active": True})
    assert resp.status_code == 403
    assert "authoriz" in resp.json()["detail"].lower()


@respx.mock
def test_active_with_authorized_is_accepted():
    respx.post("http://scan-svc:8082/discover").mock(
        return_value=httpx.Response(200, json={"hosts": []})
    )
    client = TestClient(app)
    resp = client.post(
        "/jobs/discover-and-audit",
        json={"cidr": "10.0.0.0/24", "active": True, "authorized": True},
    )
    assert resp.status_code == 202
