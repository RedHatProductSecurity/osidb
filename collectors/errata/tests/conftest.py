from datetime import datetime, timezone

import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture()
def sample_erratum_with_bz_bugs():
    # A 5-digit interal ID used by Errata Tool
    return "86100"


@pytest.fixture()
def sample_erratum_with_jira_issues():
    # A 5-digit interal ID used by Errata Tool
    return "85800"


@pytest.fixture()
def sample_erratum_with_no_flaws():
    # A 5-digit interal ID used by Errata Tool
    return "85801"


@pytest.fixture()
def sample_erratum_name():
    return "RHSA-2012:340"


@pytest.fixture()
def sample_search_time():
    return datetime(2022, 4, 21, 20, 12, 00, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    import collectors.errata.core as core

    monkeypatch.setattr(
        core, "ERRATA_TOOL_SERVER", "https://errata.stage.engineering.redhat.com"
    )
    monkeypatch.setattr(
        core,
        "ERRATA_TOOL_XMLRPC_BASE_URL",
        "https://errata.stage.engineering.redhat.com/errata/errata_service",
    )
