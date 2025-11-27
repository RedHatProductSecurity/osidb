import pytest
from django.test import RequestFactory
from django.urls import resolve

from osidb.api_views import FlawView
from osidb.models import Affect, Flaw, Impact, Tracker
from osidb.serializer import FlawSerializer
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.perf


def test_flaw_details_with_client(auth_client, test_api_v2_uri, performance_audit):
    """
    Sample test to demostrate the overhead introduced by the django client.
    """
    flaw = FlawFactory(
        embargoed=False,
        impact=Impact.LOW,
        major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
    )
    with performance_audit:
        # Django client simulates a browser request, creating a user and setting
        # all the permissions, doing a POST to /login...
        # This is perfect for normal testing scenarios but it adds extra roundtrips
        # when testing performance (time, queries...)
        response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")

    # We should keep the asserts outside of the performance_audit context to
    # not pollute the analysis with pytest code
    assert response.status_code == 200


def test_flaw_details_with_factory(test_api_v2_uri, performance_audit):
    """
    Sample test to demostrate the overhead introduced by the django client.

    Compared to the test above using the client, it should be almost 200ms faster with 3 or for times
    less database queries
    """
    flaw = FlawFactory(
        embargoed=False,
        impact=Impact.LOW,
        major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
    )

    # RequestFactory is a Django helper for creating mock requests
    # bypassing all the user creation/login
    request = RequestFactory().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
    with performance_audit:
        # Using the mock request we can call the view directly, passing the parameters that
        # normally are extracted from the path.
        response = FlawView.as_view({"get": "retrieve"})(request, id=str(flaw.uuid))
    assert response.status_code == 200


@pytest.mark.parametrize(
    "url",
    [
        ("/flaws"),
        ("/flaws?include_history=true"),
        ("/flaws?exclude_fields=affects"),
        (
            "/flaws?include_fields=cve_id,uuid,impact,source,created_dt,updated_dt,classification,title,unembargo_dt,embargoed,owner,labels"
        ),
        ("/affects"),
        ("/affects?include_history=true"),
    ],
)
def test_list_endpoints(url, auth_client, test_api_v2_uri, performance_audit):
    # Setup code that will not be audited for performance
    for _ in range(10):
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

    # We can use the `resolve` function to get the View that would render that path
    view = resolve(f"/osidb/api/v2{url.split('?')[0]}").func
    request = RequestFactory().get(f"{test_api_v2_uri}{url}")

    with performance_audit:
        response = view(request)
    assert response.status_code == 200


def test_fn_call(performance_audit):
    """
    Test to show that we can not only test views, but any function
    """
    flaw = FlawFactory(
        embargoed=False,
        impact=Impact.LOW,
        major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
    )
    for _ in range(3):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
            ps_update_stream=ps_update_stream.name,
        )
        for _ in range(3):
            TrackerFactory(
                affects=[affect],
                embargoed=False,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

    flaw = Flaw.objects.get(pk=flaw.pk)
    flaw_serializer = FlawSerializer(flaw)

    with performance_audit:
        affects = flaw_serializer.get_affects(flaw)
    assert len(affects) == 3


def test_create_flaw(performance_audit):
    flaw = FlawFactory.build(
        embargoed=False,
        impact=Impact.LOW,
        major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
    )

    with performance_audit:
        flaw.save()
    assert Flaw.objects.filter(cve_id=flaw.cve_id).count() == 1
