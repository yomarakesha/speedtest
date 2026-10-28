import os
import tempfile

import pytest

# app.main builds its Storage at import time from ORCHESTRATOR_DB. Point it at a
# throwaway file so importing the app in tests never writes into the repo.
os.environ.setdefault(
    "ORCHESTRATOR_DB", os.path.join(tempfile.mkdtemp(prefix="orchestrator-test-"), "orchestrator.db")
)


@pytest.fixture
def tmp_db_path(tmp_path):
    return str(tmp_path / "orchestrator.db")
