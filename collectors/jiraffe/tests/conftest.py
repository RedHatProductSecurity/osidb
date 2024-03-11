import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture()
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://squid.corp.redhat.com:3128")
