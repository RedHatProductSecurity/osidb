import pytest
from pytest_django.asserts import assertNumQueries

from osidb.models import Affect, Flaw, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.queryset


class TestQuerySetRegression:
    """
    Test that the number of queries executed by a given endpoint
    does not regress over time. This is done by comparing the number of queries
    executed by the endpoint to a known good value.
    """

    def test_flaw_list(self, auth_client, test_api_uri):
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.LOW,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory.create_batch(
                3,
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
            )
        with assertNumQueries(84):  # initial value -> 113
            response = auth_client().get(f"{test_api_uri}/flaws")
            assert response.status_code == 200

    def test_flaw_list_filtered(self, auth_client, test_api_uri):
        """
        Using the same subset of fields as OSIM
        """
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.LOW,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory.create_batch(
                3,
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
            )

        with assertNumQueries(61):  # initial value -> 61
            response = auth_client().get(
                f"{test_api_uri}/flaws?include_fields=cve_id,uuid,impact,source,created_dt,updated_dt,classification,title,unembargo_dt,embargoed,owner,labels"
            )
            assert response.status_code == 200

    def test_empty_flaw(self, auth_client, test_api_uri):
        flaw = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with assertNumQueries(59):  # initial value -> 60
            response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    def test_flaw_with_affects(self, auth_client, test_api_uri):
        flaw = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        AffectFactory.create_batch(
            3,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
        )

        with assertNumQueries(67):  # initial value -> 78
            response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    def test_flaw_with_affects_history(self, auth_client, test_api_uri):
        flaw = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        AffectFactory.create_batch(
            3,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
        )

        with assertNumQueries(68):  # initial value -> 82
            response = auth_client().get(
                f"{test_api_uri}/flaws/{flaw.uuid}?include_history=true"
            )
            assert response.status_code == 200

    def test_flaw_with_affects_trackers(self, auth_client, test_api_uri):
        flaw = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        for _ in range(3):
            ps_module = PsModuleFactory()
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
                ps_module=ps_module.name,
            )
            for _ in range(3):
                ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
                TrackerFactory(
                    affects=[affect],
                    embargoed=False,
                    ps_update_stream=ps_update_stream.name,
                    type=Tracker.BTS2TYPE[ps_module.bts_name],
                )
        with assertNumQueries(76):  # initial value -> 93
            response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    def test_affect_list(self, auth_client, test_api_uri):
        for _ in range(3):
            AffectFactory(
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )

        with assertNumQueries(60):  # initial value -> 69
            response = auth_client().get(f"{test_api_uri}/affects")
            assert response.status_code == 200
