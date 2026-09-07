import json

from app.wazuh_forward import forward_findings


def test_forward_findings_writes_one_line_per_finding(tmp_path):
    log_path = str(tmp_path / "findings.jsonl")
    hosts = [
        {
            "ip": "10.0.0.5",
            "audit": {
                "target": "10.0.0.5",
                "grade": "D",
                "findings": [
                    {"check": "tls.weak_protocol", "severity": 3, "title": "TLS 1.0 enabled", "detail": "..."},
                    {"check": "http.missing_hsts", "severity": 1, "title": "No HSTS", "detail": "..."},
                ],
            },
            "error": None,
        },
        {"ip": "10.0.0.9", "audit": None, "error": "connection refused"},
    ]

    count = forward_findings(log_path, "10.0.0.0/24", hosts)

    assert count == 3
    lines = open(log_path, encoding="utf-8").read().splitlines()
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first["source"] == "netsec-orchestrator"
    assert first["cidr"] == "10.0.0.0/24"
    assert first["ip"] == "10.0.0.5"
    assert first["check"] == "tls.weak_protocol"
    assert first["severity"] == 3
    assert first["grade"] == "D"
    third = json.loads(lines[2])
    assert third["ip"] == "10.0.0.9"
    assert third["check"] == "audit.unreachable"
    assert third["detail"] == "connection refused"


def test_forward_findings_maps_audit_severity_labels_to_numbers(tmp_path):
    # internal/audit marshals Severity as a Russian label, not an int, so the
    # forwarder has to normalize it for the Wazuh rules to match on a number.
    log_path = str(tmp_path / "findings.jsonl")
    hosts = [
        {
            "ip": "10.0.0.5",
            "audit": {
                "target": "10.0.0.5",
                "grade": "F",
                "findings": [
                    {"check": "a", "severity": "критично", "title": "t", "detail": "d"},
                    {"check": "b", "severity": "высокая", "title": "t", "detail": "d"},
                    {"check": "c", "severity": "средняя", "title": "t", "detail": "d"},
                    {"check": "d", "severity": "низкая", "title": "t", "detail": "d"},
                    {"check": "e", "severity": "инфо", "title": "t", "detail": "d"},
                ],
            },
            "error": None,
        }
    ]

    assert forward_findings(log_path, "10.0.0.0/24", hosts) == 5
    lines = [json.loads(l) for l in open(log_path, encoding="utf-8").read().splitlines()]
    assert [l["severity"] for l in lines] == [4, 3, 2, 1, 0]
    assert lines[0]["severity_label"] == "критично"


def test_forward_findings_skips_hosts_with_no_audit_and_no_error(tmp_path):
    log_path = str(tmp_path / "findings.jsonl")
    hosts = [{"ip": "10.0.0.9", "audit": None, "error": None}]

    count = forward_findings(log_path, "10.0.0.0/24", hosts)

    assert count == 0
    assert not open(log_path, encoding="utf-8").read()


def test_forward_findings_reports_audit_errors(tmp_path):
    log_path = str(tmp_path / "findings.jsonl")
    hosts = [{"ip": "10.0.0.9", "audit": None, "error": "connection refused"}]

    count = forward_findings(log_path, "10.0.0.0/24", hosts)

    assert count == 1
    line = json.loads(open(log_path, encoding="utf-8").read().splitlines()[0])
    assert line["ip"] == "10.0.0.9"
    assert line["check"] == "audit.unreachable"
    assert line["severity"] == 0
    assert line["detail"] == "connection refused"


def test_forward_findings_appends_across_calls(tmp_path):
    log_path = str(tmp_path / "findings.jsonl")
    host = {"ip": "10.0.0.5", "audit": {"target": "10.0.0.5", "grade": "A", "findings": [
        {"check": "x", "severity": 0, "title": "t", "detail": "d"}
    ]}, "error": None}

    forward_findings(log_path, "10.0.0.0/24", [host])
    forward_findings(log_path, "10.0.0.0/24", [host])

    lines = open(log_path, encoding="utf-8").read().splitlines()
    assert len(lines) == 2
