"""Thin async HTTP clients for the audit-svc and scan-svc Go microservices."""
import httpx


class AuditClient:
    def __init__(self, base_url: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def audit(self, target: str, with_dns: bool = False, active: bool = False) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/audit",
                json={"target": target, "with_dns": with_dns, "active": active},
            )
            resp.raise_for_status()
            return resp.json()


class ScanClient:
    def __init__(self, base_url: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def discover(self, cidr: str) -> list[dict]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/discover", json={"cidr": cidr})
            resp.raise_for_status()
            return resp.json()["hosts"]
