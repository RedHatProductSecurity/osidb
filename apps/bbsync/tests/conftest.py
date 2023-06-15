import pytest

from osidb.tests.factories import FlawFactory


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def test_flaw():
    return FlawFactory(bz_id="2011264")


@pytest.fixture
def sentinel_err_message():
    return "400 Client Error: Bad Request"
