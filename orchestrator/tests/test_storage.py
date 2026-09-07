from app.storage import Storage


def test_save_and_get_job(tmp_db_path):
    store = Storage(tmp_db_path)
    store.save_job("job-1", "audit", {"target": "1.2.3.4", "grade": "A"})
    got = store.get_job("job-1")
    assert got["kind"] == "audit"
    assert got["result"]["grade"] == "A"


def test_get_missing_job_returns_none(tmp_db_path):
    store = Storage(tmp_db_path)
    assert store.get_job("missing") is None


def test_list_jobs_returns_newest_first(tmp_db_path):
    store = Storage(tmp_db_path)
    store.save_job("job-1", "discover-and-audit", {"status": "done", "cidr": "10.0.0.0/24", "hosts": [{"ip": "10.0.0.1"}]})
    store.save_job("job-2", "discover-and-audit", {"status": "pending", "cidr": "10.0.1.0/24", "hosts": []})

    jobs = store.list_jobs()

    assert [j["job_id"] for j in jobs] == ["job-2", "job-1"]
    assert jobs[0]["status"] == "pending"
    assert jobs[0]["cidr"] == "10.0.1.0/24"
    assert jobs[0]["host_count"] == 0
    assert jobs[1]["host_count"] == 1


def test_list_jobs_respects_limit(tmp_db_path):
    store = Storage(tmp_db_path)
    for i in range(3):
        store.save_job(f"job-{i}", "discover-and-audit", {"status": "done", "cidr": "x", "hosts": []})

    assert len(store.list_jobs(limit=2)) == 2


def test_list_jobs_empty(tmp_db_path):
    store = Storage(tmp_db_path)
    assert store.list_jobs() == []
