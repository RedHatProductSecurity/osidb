import pytest

from apps.sla.framework import SLAFramework


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(autouse=True)
def clean_policies():
    """
    clean SLA framework before and after every test

        * before so it is not mixed with some leftovers
        * after so we do not leave any leftovers

    if we do it only before or only after the tests might behave differently
    when run in batch than when run alone so better to be safe then sorry
    """
    sla_framework = SLAFramework()
    sla_framework._policies = []
    yield  # run test here
    sla_framework._policies = []
