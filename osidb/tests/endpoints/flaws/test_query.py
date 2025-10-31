import pytest

from osidb.models import Tracker
from osidb.models.affect import Affect
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def test_data():
    community_product = PsProductFactory(business_unit="Community")
    community_module = PsModuleFactory(ps_product=community_product)
    community_update_stream = PsUpdateStreamFactory(ps_module=community_module)

    ps_product = PsProductFactory()
    ps_module = PsModuleFactory(ps_product=ps_product)
    ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

    # Flaw with non-community affects that have trackers
    flaw1 = FlawFactory()
    affect1 = AffectFactory(
        flaw=flaw1,
        ps_update_stream=ps_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )

    TrackerFactory(
        affects=[affect1],
        embargoed=flaw1.embargoed,
        type=Tracker.BTS2TYPE[ps_module.bts_name],
        ps_update_stream=ps_update_stream.name,
    )

    # Flaw with non-community affects that are missing trackers
    flaw2 = FlawFactory()
    AffectFactory(
        flaw=flaw2,
        ps_update_stream=ps_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )

    # Flaw with only community affects
    flaw3 = FlawFactory()
    AffectFactory(
        flaw=flaw3,
        ps_update_stream=community_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )

    # Flaw with community and non-community affects. One of the non-community affect has trackerss
    flaw4 = FlawFactory()

    # Community affect with tracker for flaw4
    AffectFactory(
        flaw=flaw4,
        ps_update_stream=community_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )

    # Non-community affect with tracker for flaw4
    affect4a = AffectFactory(
        flaw=flaw4,
        ps_update_stream=ps_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )
    TrackerFactory(
        affects=[affect4a],
        embargoed=flaw4.embargoed,
        type=Tracker.BTS2TYPE[ps_module.bts_name],
        ps_update_stream=ps_update_stream.name,
    )

    # Non-community affect without tracker for flaw4
    AffectFactory(
        flaw=flaw4,
        ps_update_stream=ps_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )

    # Flaw with community and non-community affects. The non-community affect is missing trackers
    flaw5 = FlawFactory()

    # Community affect with tracker for flaw5
    affect5a = AffectFactory(
        flaw=flaw5,
        ps_update_stream=community_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )

    # Tracker added for community affect. This should not affect the query result
    TrackerFactory(
        affects=[affect5a],
        embargoed=flaw5.embargoed,
        type=Tracker.BTS2TYPE[community_module.bts_name],
        ps_update_stream=community_update_stream.name,
    )

    # Non-community affect without tracker for flaw5
    AffectFactory(
        flaw=flaw5,
        ps_update_stream=ps_update_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
    )

    return {
        "flaw1": flaw1,  # Has trackers for non-community affects
        "flaw2": flaw2,  # Missing trackers for non-community affects
        "flaw3": flaw3,  # Only community affects
        "flaw4": flaw4,  # Community / non-community affects. At least one non-community affect has trackers
        "flaw5": flaw5,  # Community / non-community affects. No non-community affects have trackers
    }


class TestQL(object):
    """Test DjangoQL queries including affects_missing_trackers field."""

    def test_affects_missing_trackers_true(self, auth_client, test_api_uri, test_data):
        """Test query for flaws with non-community affects that are missing trackers."""

        query = "flaw_has_no_non_community_affects_trackers=True"
        response1 = auth_client().get(f"{test_api_uri}/flaws?query={query}")
        response2 = auth_client().get(f"{test_api_uri}/flaws?{query}")

        assert response1.status_code == 200
        body1 = response1.json()

        assert response2.status_code == 200
        body2 = response2.json()

        assert body1["count"] == 2
        assert body2["count"] == 2

        returned_uuids1 = {flaw["uuid"] for flaw in body1["results"]}
        returned_uuids2 = {flaw["uuid"] for flaw in body2["results"]}
        expected_uuids = {str(test_data["flaw2"].uuid), str(test_data["flaw5"].uuid)}

        assert returned_uuids1 == expected_uuids
        assert returned_uuids2 == expected_uuids

    def test_affects_missing_trackers_false(self, auth_client, test_api_uri, test_data):
        """Test query for flaws with non-community affects that are not missing trackers."""

        query = "flaw_has_no_non_community_affects_trackers=False"
        response1 = auth_client().get(f"{test_api_uri}/flaws?query={query}")
        response2 = auth_client().get(f"{test_api_uri}/flaws?{query}")

        assert response1.status_code == 200
        body1 = response1.json()

        assert response2.status_code == 200
        body2 = response2.json()

        assert body1["count"] == 3
        assert body2["count"] == 3

        returned_uuids1 = {flaw["uuid"] for flaw in body1["results"]}
        returned_uuids2 = {flaw["uuid"] for flaw in body2["results"]}
        expected_uuids = {
            str(test_data["flaw1"].uuid),
            str(test_data["flaw3"].uuid),
            str(test_data["flaw4"].uuid),
        }

        assert returned_uuids1 == expected_uuids
        assert returned_uuids2 == expected_uuids

    def test_affects_missing_trackers_not_equals_true(
        self, auth_client, test_api_uri, test_data
    ):
        """Test != True operator (should be equivalent to = False)."""
        query = "flaw_has_no_non_community_affects_trackers!=True"
        response = auth_client().get(f"{test_api_uri}/flaws?query={query}")

        assert response.status_code == 200
        body = response.json()

        assert body["count"] == 3
        returned_uuids = {flaw["uuid"] for flaw in body["results"]}
        expected_uuids = {
            str(test_data["flaw1"].uuid),
            str(test_data["flaw3"].uuid),
            str(test_data["flaw4"].uuid),
        }
        assert returned_uuids == expected_uuids
