from unittest.mock import patch

import pytest
from django.utils import timezone
from django.utils.timezone import datetime
from rest_framework import status

from osidb.dmodels.affect import Affect
from osidb.dmodels.tracker import Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
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
        tracker1 = TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
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
        TrackerFactory(
            affects=[affect2],
            embargoed=flaw.embargoed,
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
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
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
