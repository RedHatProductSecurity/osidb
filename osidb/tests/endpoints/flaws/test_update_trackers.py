from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from rest_framework import status

from apps.bbsync.save import BugzillaSaver
from osidb.models import Affect, Impact, Tracker
from osidb.sync_manager import BZTrackerDownloadManager
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpointsFlawsUpdateTrackers:
    """
    tests of consecutive tracker update trigger
    which may result from /flaws endpoint PUT calls
    """

    def test_filter(self, auth_client, test_api_uri):
        """
        test that the tracker update is triggered when expected only
        """
        flaw = FlawFactory(impact="LOW")
        ps_product1 = PsProductFactory(business_unit="Corporate")
        ps_module1 = PsModuleFactory(ps_product=ps_product1)
        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module1.name,
        )
        ps_update_stream11 = PsUpdateStreamFactory(ps_module=ps_module1)
        tracker1 = TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream11.name,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        ps_update_stream12 = PsUpdateStreamFactory(ps_module=ps_module1)
        TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream12.name,
            status="CLOSED",  # already resolved
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        # one more community affect-tracker context
        ps_product2 = PsProductFactory(business_unit="Community")
        ps_module2 = PsModuleFactory(ps_product=ps_product2)
        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module2.name,
        )
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module2)
        TrackerFactory(
            affects=[affect2],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream2.name,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module2.bts_name],
        )

        flaw_data = {
            "comment_zero": flaw.comment_zero,
            "embargoed": flaw.embargoed,
            "impact": "MODERATE",  # tracker update trigger
            "title": flaw.title,
            "updated_dt": flaw.updated_dt,
        }

        # enable autospec to get self as part of the method call args
        with patch.object(Tracker, "save", autospec=True) as mock_save:
            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.call_count == 1  # only non-closed and non-community
            assert [tracker1.uuid] == [
                args[0][0].uuid for args in mock_save.call_args_list
            ]

    # Nested pytest necessary despite the performance drawback because the relevant logic
    # has nested complex conditions.
    @pytest.mark.parametrize(
        "btsname, tracker_meta_attr,flaw_to_create_2, flaw_to_update_2, triggered_2",
        [
            ("bugzilla", {"test": "1"}, {}, {}, False),
            ("jboss", {"test": "1"}, {}, {}, False),
            (
                "jboss",
                {"jira_issuetype": "Vulnerability"},
                {"components": ["foo", "bar"]},
                {"components": ["foo", "baRRR"]},
                True,
            ),
            (
                "jboss",
                {"jira_issuetype": "Bug"},
                {"components": ["foo", "bar"]},
                {"components": ["foo", "baRRR"]},
                False,
            ),
            (
                "jboss",
                {"jira_issuetype": "Vulnerability"},
                {"components": ["foo", "bar"]},
                {},
                False,
            ),
            # Shouldn't happen but better be safe than sorry:
            (
                "bugzilla",
                {"jira_issuetype": "Vulnerability"},
                {"components": ["foo", "bar"]},
                {"components": ["foo", "baRRR"]},
                False,
            ),
        ],
    )
    @pytest.mark.parametrize(
        "to_create,to_update,triggered",
        [
            ({"title": "old"}, {"title": "new"}, False),
            ({"comment_zero": "old"}, {"comment_zero": "new"}, False),
            ({"cve_id": "CVE-2000-1111"}, {"cve_id": "CVE-2000-1111"}, False),
            ({"cve_id": "CVE-2000-1111"}, {"cve_id": "CVE-2000-2222"}, True),
            ({"impact": "IMPORTANT"}, {"impact": "LOW"}, True),
            ({"impact": "MODERATE"}, {"impact": "IMPORTANT"}, True),
            ({"source": "DEBIAN"}, {"source": "GENTOO"}, False),
            (
                {"major_incident_state": ""},
                {"major_incident_state": "REQUESTED"},
                False,
            ),
            (
                {"major_incident_state": "REQUESTED"},
                {"major_incident_state": "APPROVED"},
                True,
            ),
            (
                {"major_incident_state": "APPROVED"},
                {"major_incident_state": "CISA_APPROVED"},
                True,
            ),
            (
                # set to embargoed so we cannot fail
                # on past but not performed unembargo
                {
                    "embargoed": False,
                    "unembargo_dt": datetime(2011, 1, 1, tzinfo=timezone.utc),
                },
                {"unembargo_dt": datetime(2012, 1, 1, tzinfo=timezone.utc)},
                True,
            ),
        ],
    )
    def test_trigger(
        self,
        auth_client,
        test_api_uri,
        to_create,
        to_update,
        triggered,
        btsname,
        tracker_meta_attr,
        flaw_to_create_2,
        flaw_to_update_2,
        triggered_2,
    ):
        """
        test that the tracker update is triggered when expected only
        """
        flaw_create_dict = {}
        flaw_create_dict.update(to_create)
        flaw_create_dict.update(flaw_to_create_2)
        flaw = FlawFactory(**flaw_create_dict)
        ps_module = PsModuleFactory(bts_name=btsname)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            meta_attr=tracker_meta_attr,
        )

        flaw_data = {
            "comment_zero": flaw.comment_zero,
            "embargoed": flaw.embargoed,
            "title": flaw.title,
            "updated_dt": flaw.updated_dt,
        }
        flaw_update_dict = {}
        flaw_update_dict.update(to_update)
        flaw_update_dict.update(flaw_to_update_2)
        for attribute, value in flaw_update_dict.items():
            flaw_data[attribute] = value

        with patch.object(Tracker, "save") as mock_save:
            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.called == (triggered or triggered_2)

    def test_skip_non_migrated_trackers(
        self,
        auth_client,
        enable_bz_tracker_sync,
        monkeypatch,
        test_api_uri,
    ):
        """
        test that a Bugzilla tracker which product was migrated
        to Jira project is skipped during a tracker sync
        """
        flaw = FlawFactory(impact="IMPORTANT")
        ps_module1 = PsModuleFactory(bts_name="bugzilla")
        affect1 = AffectFactory(
            flaw=flaw,
            impact=Impact.NOVALUE,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module1.name,
        )
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module1)
        tracker1 = TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        ps_module2 = PsModuleFactory(bts_name="jboss")
        affect2 = AffectFactory(
            flaw=flaw,
            impact=Impact.NOVALUE,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module2.name,
        )
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module2)
        tracker2 = TrackerFactory.build(
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream2.name,
            status="NEW",
            type="BUGZILLA",  # tracker typy and BTS mismatch
        )
        tracker2.save(raise_validation_error=False)
        tracker2.affects.add(affect2)

        flaw_data = {
            "comment_zero": flaw.comment_zero,
            "embargoed": flaw.embargoed,
            "impact": "MODERATE",  # tracker update trigger
            "title": flaw.title,
            "updated_dt": flaw.updated_dt,
        }

        monkeypatch.setattr(BZTrackerDownloadManager, "schedule", lambda x: None)
        # enable autospec to get self as part of the method call args
        with patch.object(BugzillaSaver, "save", autospec=True) as mock_save:
            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert (
                mock_save.call_count == 1
            )  # no mismatched trackers attempted to be saved
            assert tracker1.uuid == mock_save.call_args_list[0][0][0].tracker.uuid
