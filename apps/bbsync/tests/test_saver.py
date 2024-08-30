import bugzilla
import pytest
import requests

from apps.bbsync.query import FlawBugzillaQueryBuilder
from apps.bbsync.save import BugzillaSaver
from collectors.bzimport.constants import BZ_URL
from osidb.exceptions import DataInconsistencyException
from osidb.models import Flaw

pytestmark = pytest.mark.unit


class TestBugzillaSaver:
    def test_update(self, test_flaw, sentinel_err_message, monkeypatch):
        def update_bugs(*args, **kwargs):
            raise requests.exceptions.HTTPError(sentinel_err_message)

        with monkeypatch.context() as m:
            m.setattr(BugzillaSaver, "model", property(lambda _: Flaw))
            m.setattr(
                BugzillaSaver,
                "query_builder",
                property(lambda _: FlawBugzillaQueryBuilder),
            )

            bs = BugzillaSaver(test_flaw, "foo")
            m.setattr(
                bs,
                "_bz_conn",
                bugzilla.Bugzilla(url=BZ_URL, api_key="foo", force_rest=True),
            )
            m.setattr(bs, "check_collisions", lambda: None)
            m.setattr(bs.bz_conn, "update_bugs", update_bugs)

            with pytest.raises(
                DataInconsistencyException, match="Failed to write back to Bugzilla"
            ):
                bs.save()

    @pytest.mark.parametrize(
        "last_change_time",
        ["2024-06-20T23:08:18Z", "2024-08-29 13:27:08+00:00"],
    )
    def test_stored_last_change(self, last_change_time):
        """
        https://issues.redhat.com/browse/OSIDB-3364 reproducer
        """
        bs = BugzillaSaver(Flaw(meta_attr={"last_change_time": last_change_time}))
        bs.stored_last_change  # no exception here
