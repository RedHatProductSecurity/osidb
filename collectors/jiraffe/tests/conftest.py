import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture()
def pin_urls(monkeypatch) -> None:
    """
    the tests should be immune to what .evn you build the testrunner with
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://squid.corp.redhat.com:3128")
