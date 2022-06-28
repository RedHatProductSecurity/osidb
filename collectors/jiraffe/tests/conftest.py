import json
from datetime import datetime, timezone

import pytest

from osidb.tests.factories import FlawFactory


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def datetime_with_tz():
    return datetime.now(timezone.utc)


@pytest.fixture
def good_cve_id():
    return "CVE-2016-5002"


@pytest.fixture
def good_jira_trackers():
    return ["ENTESB-8726"]


@pytest.fixture
def good_flaw(good_cve_id):
    return FlawFactory(cve_id=good_cve_id)


def _gen_metadata(state_name, state_cat, resolution):
    return {
        "state": {
            "statusCategory": {
                "key": state_cat,
            },
            "name": state_name,
        },
        "resolution": {
            "name": resolution,
        },
    }


@pytest.fixture
def tracker_metadata_affected_fix():
    return {
        "state": json.dumps(
            {
                "statusCategory": {
                    "key": "undefined",
                },
                "name": "In Progress",
            }
        ),
        "resolution": json.dumps(
            {
                "name": "Fixed",
            }
        ),
    }


@pytest.fixture
def tracker_metadata_new_novalue():
    return _gen_metadata("Open", "new", None)


@pytest.fixture
def tracker_metadata_wontfix():
    return _gen_metadata("Can't reproduce", "indeterminate", "Cannot Reproduce")


@pytest.fixture
def tracker_metadata_ooss():
    return _gen_metadata("Outdated", "done", "Out of Date")


@pytest.fixture
def tracker_metadata_notaffected_wontfix():
    return _gen_metadata("Not a Bug", "done", "Not a Bug")


@pytest.fixture
def tracker_metadata_deferred():
    return _gen_metadata("Deferred", "done", "Deferred")


@pytest.fixture
def tracker_metadata_affected_delegated():
    return _gen_metadata("Resolved", "done", "Upstream")


@pytest.fixture
def tracker_metadata_novalue():
    return _gen_metadata(None, None, None)
