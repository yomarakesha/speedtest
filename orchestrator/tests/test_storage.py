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
