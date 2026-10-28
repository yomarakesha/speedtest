"""Writes audit findings as JSON lines to a log file a Wazuh agent tails
(via a <localfile> block in ossec.conf, log_format json) — see
deploy/wazuh/ossec-localfile-snippet.xml, decoder.xml and rules.xml."""
import json
import os

# internal/audit's Severity marshals as a Russian label (see its MarshalJSON),
# so normalize it back to the underlying 0..4 rank the Wazuh rules match on.
_SEVERITY_BY_LABEL = {
    "инфо": 0,
    "низкая": 1,
    "средняя": 2,
    "высокая": 3,
    "критично": 4,
}


def _severity_rank(value) -> int:
    """Return the numeric severity for either the label or a raw int."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return _SEVERITY_BY_LABEL.get(value.strip().lower(), 0)
    return 0


def forward_findings(log_path: str, cidr: str, hosts: list[dict]) -> int:
    if not hosts:
        return 0
    parent = os.path.dirname(log_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    written = 0
    with open(log_path, "a", encoding="utf-8") as f:
        for host in hosts:
            report = host.get("audit")
            if not report:
                error = host.get("error")
                if not error:
                    continue
                # A host that couldn't be audited is itself worth surfacing in
                # Wazuh — silently dropping it would hide "this host is
                # unreachable/filtering us" from the SIEM.
                line = {
                    "source": "netsec-orchestrator",
                    "cidr": cidr,
                    "ip": host["ip"],
                    "grade": None,
                    "check": "audit.unreachable",
                    "severity": 0,
                    "severity_label": "ошибка",
                    "title": "Не удалось провести аудит хоста",
                    "detail": error,
                }
                f.write(json.dumps(line, ensure_ascii=False) + "\n")
                written += 1
                continue
            for finding in report.get("findings", []):
                severity = finding.get("severity")
                line = {
                    "source": "netsec-orchestrator",
                    "cidr": cidr,
                    "ip": host["ip"],
                    "grade": report.get("grade"),
                    "check": finding.get("check"),
                    "severity": _severity_rank(severity),
                    "severity_label": severity,
                    "title": finding.get("title"),
                    "detail": finding.get("detail"),
                }
                f.write(json.dumps(line, ensure_ascii=False) + "\n")
                written += 1
    return written


def forward_scan_failure(log_path: str, cidr: str, error: str) -> None:
    """A whole-CIDR discover() failure never reaches forward_findings (there
    are no hosts to iterate), but it's a bigger SIEM signal than any single
    unreachable host inside a working scan — surface it explicitly."""
    parent = os.path.dirname(log_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    line = {
        "source": "netsec-orchestrator",
        "cidr": cidr,
        "ip": None,
        "grade": None,
        "check": "scan.failed",
        "severity": 3,
        "severity_label": "высокая",
        "title": "Не удалось выполнить discover по подсети",
        "detail": error,
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")
