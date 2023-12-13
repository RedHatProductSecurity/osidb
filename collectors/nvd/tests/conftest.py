import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture()
def snippet_creation_enabled(monkeypatch) -> None:
    monkeypatch.setenv("SNIPPET_CREATION", "1")
    monkeypatch.setenv("SNIPPET_CREATION_ENABLED", "1")
