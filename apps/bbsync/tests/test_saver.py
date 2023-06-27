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
