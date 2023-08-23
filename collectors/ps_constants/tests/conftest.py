import pytest

from collectors.ps_constants.constants import (
    PS_CONSTANTS_REPO_BRANCH,
    PS_CONSTANTS_REPO_URL,
)


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture()
def ps_constant_base_url():
    return "/".join(
        (
            PS_CONSTANTS_REPO_URL,
            "-",
            "raw",
            PS_CONSTANTS_REPO_BRANCH,
            "data",
        )
    )
