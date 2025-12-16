"""
Tests for order parameter to ensure it doesn't create duplicates or change counts

The default ordering filter creates SQL JOINs that cause the same flaw to appear multiple times.
The DistinctOrderingFilter prevents this by using aggregations to remove duplicates.

"""

import pytest

from osidb.models import Affect, PsModule, Tracker
from osidb.tests.factories import AffectFactory, FlawFactory, TrackerFactory
from osidb.tests.test_flaw import tzdatetime

pytestmark = pytest.mark.unit


class TestOrdering:
    """Test that ordering by related fields doesn't create duplicates"""

    def setup_method(self):
        """Create reusable flaws with affects and trackers for testing

        Timeline for affects:
        - CVE-2025-9000 (public): Jan 1, Jan 2, Jan 3 (x2) → earliest: Jan 1, latest: Jan 3
        - CVE-2025-9001 (public): Feb 1, Feb 2 → earliest: Feb 1, latest: Feb 2
        - CVE-2025-9002 (embargoed): Jan 2, Mar 1 → earliest: Jan 2, latest: Mar 1

        Timeline for trackers:
        - CVE-2025-9000: Jan 4, Mar 3
        - CVE-2025-9001: Feb 3
        - CVE-2025-9002: Mar 2

        """

        flaw1 = FlawFactory(cve_id="CVE-2025-9000", embargoed=False)

        _ = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.NEW,
            updated_dt=tzdatetime(2025, 1, 1),
        )
        _ = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
            updated_dt=tzdatetime(2025, 1, 2),
        )
        affect1_3 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            updated_dt=tzdatetime(2025, 1, 3),
        )
        affect1_4 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            updated_dt=tzdatetime(2025, 1, 3),
        )

        ps_module = PsModule.objects.filter(name=affect1_3.ps_module).first()
        TrackerFactory(
            affects=[affect1_3],
            embargoed=flaw1.embargoed,
            ps_update_stream=affect1_3.ps_update_stream,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            updated_dt=tzdatetime(2025, 1, 4),
        )

        ps_module = PsModule.objects.filter(name=affect1_4.ps_module).first()
        TrackerFactory(
            affects=[affect1_4],
            embargoed=flaw1.embargoed,
            ps_update_stream=affect1_4.ps_update_stream,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            updated_dt=tzdatetime(2025, 3, 3),
        )

        flaw2 = FlawFactory(cve_id="CVE-2025-9001", embargoed=False)
        _ = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            updated_dt=tzdatetime(2025, 2, 1),
        )
        affect2_2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            updated_dt=tzdatetime(2025, 2, 2),
        )

        ps_module = PsModule.objects.filter(name=affect2_2.ps_module).first()
        TrackerFactory(
            affects=[affect2_2],
            embargoed=flaw2.embargoed,
            ps_update_stream=affect2_2.ps_update_stream,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            updated_dt=tzdatetime(2025, 2, 3),
        )

        flaw3 = FlawFactory(cve_id="CVE-2025-9002", embargoed=True)
        _ = AffectFactory(
            flaw=flaw3,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            updated_dt=tzdatetime(2025, 1, 2),
        )
        affect3_2 = AffectFactory(
            flaw=flaw3,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            updated_dt=tzdatetime(2025, 3, 1),
        )

        ps_module = PsModule.objects.filter(name=affect3_2.ps_module).first()
        TrackerFactory(
            affects=[affect3_2],
            embargoed=flaw3.embargoed,
            ps_update_stream=affect3_2.ps_update_stream,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            updated_dt=tzdatetime(2025, 3, 2),
        )

    def test_order_count(self, auth_client, test_api_v2_uri):
        """
        Test ordering by affects__updated_dt doesn't create duplicates.
        """

        requests = [
            f"{test_api_v2_uri}/flaws?order=cve_id",
            f"{test_api_v2_uri}/flaws?order=affects__updated_dt",
            f"{test_api_v2_uri}/flaws?order=-affects__updated_dt",
            f"{test_api_v2_uri}/flaws?order=affects__ps_update_stream",
            f"{test_api_v2_uri}/flaws?order=-affects__ps_update_stream",
            f"{test_api_v2_uri}/flaws?order=cve_id,affects__updated_dt,affects__ps_update_stream",
        ]

        for request in requests:
            response = auth_client().get(request)
            assert response.status_code == 200, f"Status code is not 200 for {request}"
            assert response.json()["count"] == 3, f"Count is not 3 for {request}"

    def test_order_count_nested(self, auth_client, test_api_v2_uri):
        """
        Test ordering by nested related fields doesn't create duplicates.
        """

        requests = [
            f"{test_api_v2_uri}/flaws?order=cve_id",
            f"{test_api_v2_uri}/flaws?order=affects__tracker__updated_dt",
            f"{test_api_v2_uri}/flaws?order=-affects__tracker__updated_dt",
            f"{test_api_v2_uri}/flaws?order=affects__tracker__ps_update_stream",
            f"{test_api_v2_uri}/flaws?order=-affects__tracker__ps_update_stream",
            f"{test_api_v2_uri}/flaws?order=cve_id,affects__tracker__updated_dt,affects__tracker__ps_update_stream",
        ]

        for request in requests:
            response = auth_client().get(request)
            assert response.status_code == 200, f"Status code is not 200 for {request}"
            assert response.json()["count"] == 3, f"Count is not 3 for {request}"

    def test_ordering_related_fields(self, auth_client, test_api_v2_uri):
        """
        Test that ordering by related fields works with multiple flaws.

        Timeline:
        - CVE-2025-9000: affects Jan 1-3 (earliest: Jan 1, latest: Jan 3)
        - CVE-2025-9001: affects Feb 1-2 (earliest: Feb 1, latest: Feb 2)
        - CVE-2025-9002: affects Jan 2, Mar 1 (earliest: Jan 2, latest: Mar 1)
        """

        # Test ascending order by affects__updated_dt (earliest affect first)
        # Expected: 9000 (Jan 1), 9002 (Jan 2), 9001 (Feb 1)
        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?order=affects__updated_dt"
        )
        assert response.status_code == 200
        body = response.json()

        cve_ids = [f["cve_id"] for f in body["results"]]
        assert cve_ids == ["CVE-2025-9000", "CVE-2025-9002", "CVE-2025-9001"], (
            f"Expected ascending order by earliest affect, got: {cve_ids}"
        )

        # Test descending order by affects__updated_dt (latest affect first)
        # Expected: 9002 (Mar 1), 9001 (Feb 2), 9000 (Jan 3)
        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?order=-affects__updated_dt"
        )
        assert response.status_code == 200
        body = response.json()

        cve_ids = [f["cve_id"] for f in body["results"]]
        assert cve_ids == ["CVE-2025-9002", "CVE-2025-9001", "CVE-2025-9000"], (
            f"Expected descending order by latest affect, got: {cve_ids}"
        )

    def test_ordering_nested_related_fields(self, auth_client, test_api_v2_uri):
        # Test descending order by affects__tracker__updated_dt (earliest tracker first)
        # Expected: 9000 (Jan 4), 9001 (Feb 3), 9002 (Mar 2)
        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?order=affects__tracker__updated_dt"
        )
        assert response.status_code == 200
        body = response.json()

        cve_ids = [f["cve_id"] for f in body["results"]]
        assert cve_ids == ["CVE-2025-9000", "CVE-2025-9001", "CVE-2025-9002"], (
            f"Expected descending order by latest tracker, got: {cve_ids}"
        )

        # Test ascending order by affects__tracker__updated_dt (latest tracker first)
        # Expected: 9000 (Mar 3), 9001 (Feb 3), 9002 (Mar 2)
        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?order=-affects__tracker__updated_dt"
        )
        assert response.status_code == 200
        body = response.json()
        cve_ids = [f["cve_id"] for f in body["results"]]
        assert cve_ids == ["CVE-2025-9000", "CVE-2025-9002", "CVE-2025-9001"]

    def test_ordering_tied_fields(self, auth_client, test_api_v2_uri):
        # Test ordering by affects__affectedness, then by cve_id
        # 9000 has NEW/NOTAFFECTED/AFFECTED, 9001 has AFFECTED, 9002 has AFFECTED
        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?order=affects__affectedness,-cve_id"
        )
        assert response.status_code == 200
        body = response.json()

        cve_ids = [f["cve_id"] for f in body["results"]]
        # All flaws have AFFECTED affects, so secondary sort by -cve_id applies
        assert cve_ids == ["CVE-2025-9002", "CVE-2025-9001", "CVE-2025-9000"], (
            f"Expected order by affectedness then -cve_id, got: {cve_ids}"
        )

        # Test descending order by -affects__affectedness, then by -cve_id
        # Expected: 9000 (NEW/NOTAFFECTED/AFFECTED), 9001 (AFFECTED), 9002 (AFFECTED)
        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?order=-affects__affectedness,-cve_id"
        )
        assert response.status_code == 200
        body = response.json()
        cve_ids = [f["cve_id"] for f in body["results"]]
        assert cve_ids == ["CVE-2025-9000", "CVE-2025-9002", "CVE-2025-9001"]

    def test_ordering_embargoed(self, client, test_api_v2_uri):
        # Test ordering by cve_id descending on unauthorized client
        response = client.get(f"{test_api_v2_uri}/flaws?order=-cve_id")
        assert response.status_code == 200
        body = response.json()

        # Third flaw is embargoed and should not be returned
        assert body["count"] == 2
        cve_ids = [f["cve_id"] for f in body["results"]]
        assert cve_ids == ["CVE-2025-9001", "CVE-2025-9000"]

        # Test ordering by affects__updated_dt on unauthorized client (earliest affect first)
        # Expected: 9000 (Jan 1), 9001 (Feb 1)
        response = client.get(f"{test_api_v2_uri}/flaws?order=affects__updated_dt")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        cve_ids = [f["cve_id"] for f in body["results"]]
        assert cve_ids == ["CVE-2025-9000", "CVE-2025-9001"]
