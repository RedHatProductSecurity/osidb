import pytest

from collectors.ps_constants.constants import PS_CONSTANTS_REPO_BRANCH


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(autouse=True)
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    monkeypatch.setenv(
        "PS_CONSTANTS_URL", "https://example.com/prodsec-dev/ps-constants"
    )


@pytest.fixture()
def ps_constant_base_url():
    return "/".join(
        (
            # pinned PS_CONSTANTS_REPO_URL for tests
            "https://example.com/prodsec-dev/ps-constants",
            "-",
            "raw",
            PS_CONSTANTS_REPO_BRANCH,
            "data",
        )
    )
