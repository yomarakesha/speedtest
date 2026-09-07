import httpx
import pytest
import respx

from app.clients import AuditClient, ScanClient


@pytest.mark.asyncio
@respx.mock
async def test_audit_client_posts_target_and_returns_report():
    route = respx.post("http://audit-svc:8081/audit").mock(
        return_value=httpx.Response(200, json={"target": "1.2.3.4", "findings": [], "grade": "A"})
    )
    client = AuditClient(base_url="http://audit-svc:8081")
    report = await client.audit("1.2.3.4")
    assert route.called
    assert report["target"] == "1.2.3.4"
    assert report["grade"] == "A"


@pytest.mark.asyncio
@respx.mock
async def test_audit_client_raises_on_error_status():
    respx.post("http://audit-svc:8081/audit").mock(
        return_value=httpx.Response(400, json={"error": "target is required"})
    )
    client = AuditClient(base_url="http://audit-svc:8081")
    with pytest.raises(httpx.HTTPStatusError):
        await client.audit("")


@pytest.mark.asyncio
@respx.mock
async def test_scan_client_discover_returns_hosts():
    respx.post("http://scan-svc:8082/discover").mock(
        return_value=httpx.Response(200, json={"hosts": [{"ip": "192.168.1.10", "open": []}]})
    )
    client = ScanClient(base_url="http://scan-svc:8082")
    hosts = await client.discover("192.168.1.0/24")
    assert hosts == [{"ip": "192.168.1.10", "open": []}]
