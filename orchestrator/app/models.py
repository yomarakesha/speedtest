from pydantic import BaseModel


class AuditJobRequest(BaseModel):
    target: str
    with_dns: bool = False
    active: bool = False
    authorized: bool = False  # must be true when active=True — see the active-scan gate


class DiscoverAuditJobRequest(BaseModel):
    cidr: str
    with_dns: bool = False
    active: bool = False
    authorized: bool = False  # must be true when active=True — see the active-scan gate
