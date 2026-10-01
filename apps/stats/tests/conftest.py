import pytest


@pytest.fixture(autouse=True)
def enable_stats_api(monkeypatch):
    """Enable the stats API feature flag for all stats tests."""
    monkeypatch.setenv("OSIDB_STATS_ENABLED", "1")
