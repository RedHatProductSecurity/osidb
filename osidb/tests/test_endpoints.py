from datetime import timedelta
from typing import Set, Union

import pytest

from osidb.filters import FlawFilter

from ..models import Affect, Flaw, FlawMeta, Tracker
from .factories import (
    AffectFactory,
    CVEv5PackageVersionsFactory,
    CVEv5VersionFactory,
    FlawCommentFactory,
    FlawFactory,
    FlawMetaFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


def is_meta_attr_correct(
    meta_attr: Union[Set[str], None], expected_keys: Set[str]
) -> bool:
    """Helper function for meta attr correctness check"""
    if meta_attr is None and not expected_keys:
        return True
    elif set(meta_attr.keys()) == expected_keys:
        return True
    else:
        return False


class TestEndpoints(object):
    def test_osidb_service_health(self, client):
        """test access to osidb service health endpoint"""
        response = client.get("/osidb/healthy")
        assert response.status_code == 200

    def test_status(self, auth_client, test_api_uri):
        """test access to osidb service status endpoint"""

        response = auth_client.get(f"{test_api_uri}/status")
        assert response.status_code == 200
        body = response.json()
        assert body["osidb_data"]["flaw_count"] == 0

    def test_manifest(self, auth_client, test_api_uri):
        """test access to osidb package manifest endpoint"""

        response = auth_client.get(f"{test_api_uri}/manifest")
        assert response.status_code == 200
        packages = response.json()["packages"]
        assert all(
            key in packages[0]
            for key in (
                "pkg_name",
                "project_name",
                "version",
                "source",
                "home_page",
                "purl",
            )
        )

    def test_get_flaw_with_comments(self, auth_client, test_api_uri):
        """retrieve specific flaw with comments from endpoint"""

        flaw1 = FlawFactory()

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200

        flaw = Flaw.objects.get(cve_id=flaw1.cve_id)
        FlawCommentFactory(flaw=flaw)
        FlawCommentFactory(flaw=flaw)

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200

        body = response.json()
        assert len(body["comments"]) == 2

    def test_get_flaw(self, auth_client, test_api_uri):
        """retrieve specific flaw from endpoint"""

        flaw1 = FlawFactory.build(is_major_incident=True)
        flaw1.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=flaw1,
            type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT,
            meta_attr={"status": "+"},
        )
        assert flaw1.save() is None
        FlawCommentFactory(flaw=flaw1)
        response = auth_client.get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["is_major_incident"] is True
        assert len(body["comments"]) == 1

    def test_list_flaws(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""

        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory()

        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

    def test_list_flaws_changed_after(
        self,
        auth_client,
        test_api_uri,
        datetime_with_tz,
    ):
        """retrieve list of flaws from endpoint"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(created_dt=datetime_with_tz)

        future_str = f"{datetime_with_tz + timedelta(days=1)}"  # Set to future date, API should return 0 results
        assert future_str.endswith("+00:00")
        future_str = future_str.replace(
            "+00:00", "Z"
        )  # Plus must be percent-encoded to be parsed correctly by Django
        # The IR Dashboard team uses timestamps ending in Z, test this value to avoid regressions that break dashboard
        response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_str}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    def test_list_flaws_changed_before(
        self,
        auth_client,
        test_api_uri,
        datetime_with_tz,
    ):
        """retrieve list of flaws from endpoint"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(created_dt=datetime_with_tz)

        past_str = f"{datetime_with_tz - timedelta(days=1)}"  # Set to past date, API should return 0 results
        assert past_str.endswith("+00:00")
        past_str = past_str.replace(
            "+00:00", "Z"
        )  # Plus must be percent-encoded to be parsed correctly by Django
        # The IR Dashboard team uses timestamps ending in Z, test this value to avoid regressions that break dashboard
        response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_str}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    # TODO the time stamps are not being set temporarily so this is
    # disabled until it is implemented + also some other tests below
    #
    # def test_list_flaws_changed_before_and_after(
    #     self,
    #     auth_client,
    #     test_api_uri,
    #     datetime_with_tz,
    # ):
    #     """retrieve list of flaws from endpoint"""
    #     response = auth_client.get(f"{test_api_uri}/flaws")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 0

    #     FlawFactory(created_dt=datetime_with_tz)

    #     past_str = f"{datetime_with_tz - timedelta(days=1)}"
    #     future_str = f"{datetime_with_tz + timedelta(days=1)}"
    #     past_str = past_str.replace("+00:00", "Z")
    #     future_str = future_str.replace("+00:00", "Z")
    #     response = auth_client.get(
    #         f"{test_api_uri}/flaws?changed_after={past_str}&changed_before={future_str}"
    #     )
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert (
    #         body["count"] == 1
    #     )  # One Flaw that was changed after a past date AND before a future date

    def test_list_flaws_filters(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory()

        for field_filter in FlawFilter.get_fields():
            response = auth_client.get(f"{test_api_uri}/flaws?{field_filter}=0")
            if response.status_code == 200:
                assert response.json()["count"] == 0 or getattr(flaw, field_filter) == 0
                # There can be either no match or a matching boolean value
                # Note that boolean fields support filtering on True / true / 1, False / false / 0, etc.
                # Any other values cause the parameter to be ignored and all objects to be returned
            elif response.status_code == 400:
                assert field_filter in response.json()
                # Error occurs because 0 is invalid UUID, datetime, etc
                # Response should contain key(s) matching query parameter(s) that had an error
            else:
                raise Exception("Unexpected response code - must be 200 or 400")

    # @freeze_time(datetime(2021, 11, 23))
    # def test_changed_after_from_tracker(self, auth_client, test_api_uri):
    #     affect = AffectFactory()
    #     tracker = TrackerFactory(affects=(affect,))
    #     future_dt = datetime(2021, 11, 27)

    #     # first check that we cannot get anything by querying any flaws changed after future_dt
    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 0

    #     # now let's update the tracker during future_dt and verify that the filter picked up the
    #     # change in the corresponding flaw
    #     with freeze_time(future_dt):
    #         tracker.external_system_id = "foo"
    #         tracker.save()
    #     assert tracker.updated_dt == future_dt.astimezone(
    #         timezone.get_current_timezone()
    #     )

    #     # we should get a result now
    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 1
    #     assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    # @freeze_time(datetime(2021, 11, 23))
    # def test_changed_after_from_affect(self, auth_client, test_api_uri):
    #     affect = AffectFactory()
    #     future_dt = datetime(2021, 11, 27)

    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 0

    #     with freeze_time(future_dt):
    #         affect.ps_component = "foo"
    #         affect.save()
    #     assert affect.updated_dt == future_dt.astimezone(
    #         timezone.get_current_timezone()
    #     )

    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 1
    #     assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    # @freeze_time(datetime(2021, 11, 23))
    # def test_changed_after_from_multi_affect(self, auth_client, test_api_uri):
    #     flaw = FlawFactory()
    #     affect1 = AffectFactory(flaw=flaw)
    #     affect2 = AffectFactory(flaw=flaw)
    #     future_dt = datetime(2021, 11, 27)

    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 0

    #     for affect in [affect1, affect2]:
    #         with freeze_time(future_dt):
    #             affect.ps_component = "foo"
    #             affect.save()
    #         assert affect.updated_dt == future_dt.astimezone(
    #             timezone.get_current_timezone()
    #         )

    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 1
    #     assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    # @freeze_time(datetime(2021, 11, 23))
    # def test_changed_before_from_tracker(self, auth_client, test_api_uri):
    #     affect = AffectFactory()
    #     tracker = TrackerFactory(affects=(affect,))
    #     past_dt = datetime(2019, 11, 27)

    #     # first check that we cannot get anything by querying any flaws changed after future_dt
    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 0

    #     # now let's update the tracker during future_dt and verify that the filter picked up the
    #     # change in the corresponding flaw
    #     with freeze_time(past_dt):
    #         tracker.external_system_id = "foo"
    #         tracker.save()
    #     assert tracker.updated_dt == past_dt.astimezone(timezone.get_current_timezone())

    #     # we should get a result now
    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 1
    #     assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    # @freeze_time(datetime(2021, 11, 23))
    # def test_changed_before_from_affect(self, auth_client, test_api_uri):
    #     affect = AffectFactory()
    #     past_dt = datetime(2019, 11, 27)

    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 0

    #     with freeze_time(past_dt):
    #         affect.ps_component = "foo"
    #         affect.save()
    #     assert affect.updated_dt == past_dt.astimezone(timezone.get_current_timezone())

    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 1
    #     assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    # @freeze_time(datetime(2021, 11, 23))
    # def test_changed_before_from_multi_tracker(self, auth_client, test_api_uri):
    #     flaw = FlawFactory()
    #     affect1 = AffectFactory(flaw=flaw)
    #     affect2 = AffectFactory(flaw=flaw)
    #     tracker1 = TrackerFactory(affects=(affect1,))
    #     tracker2 = TrackerFactory(affects=(affect2,))
    #     past_dt = datetime(2019, 11, 27)

    #     # first check that we cannot get anything by querying any flaws changed after future_dt
    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 0

    #     # now let's update the tracker during future_dt and verify that the filter picked up the
    #     # change in the corresponding flaw
    #     for tracker in [tracker1, tracker2]:
    #         with freeze_time(past_dt):
    #             tracker.resolution = "foo"
    #             tracker.save()
    #         assert tracker.updated_dt == past_dt.astimezone(
    #             timezone.get_current_timezone()
    #         )

    #     # we should get a result now
    #     response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
    #     assert response.status_code == 200
    #     body = response.json()
    #     assert body["count"] == 1
    #     assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    def test_list_flaws_filter_by_bz_id(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        meta_attr = {"bz_id": 123456}

        FlawFactory(meta_attr=meta_attr)

        response = auth_client.get(f"{test_api_uri}/flaws?bz_id={meta_attr['bz_id']}")
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_list_flaws_invalid(self, auth_client, test_api_uri, datetime_with_tz):
        """retrieve list of flaws from endpoint"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(created_dt=datetime_with_tz)

        past_str = f"{datetime_with_tz - timedelta(days=1)}"
        future_str = f"{datetime_with_tz + timedelta(days=1)}"
        past_str = past_str.replace("+00:00", "Z")
        future_str = future_str.replace("+00:00", "Z")
        response = auth_client.get(
            f"{test_api_uri}/flaws?changed_after={future_str}&changed_before={past_str}"
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 0
        )  # No Flaws that were changed after a future date AND before a past date

        response = auth_client.get(f"{test_api_uri}/flaws?changed_after=")
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 1
        )  # Parameter is not used for filtering if no value was provided

        response = auth_client.get(
            f"{test_api_uri}/flaws?changed_not_at_all=&changed2=-1&changed3"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1  # Unrecognized parameters are ignored

        response = auth_client.get(
            f"{test_api_uri}/flaws?changed_after=2021-09-31%2025:70:70XYZ"
        )
        assert response.status_code == 400
        body = response.json()
        assert (
            body["changed_after"][0] == "Enter a valid date/time."
        )  # Invalid datetimes in request parameter cause errors to appear in response body, key names should match
        # Date or time that doesn't exist (2021-09-31, 25:70:70) fails
        # Space instead of T between date and time succeeds, prefer T
        # Offsets like -0005 or +00:05 succeed even if that timezone doesn't exist, but + must be percent-encoded as %2b
        # Z / +00:00 / +0000 / -00:00 / -0000 all succeed, prefer Z
        # Date without time and time without offset succeed, prefer full dateTtime+offset
        # Time without microseconds and all-zero microseconds (from 1 to 12 digits) succeed, prefer seconds only
        # Dot without microseconds value and microseconds longer than 12 digits fail
        # So in other words, Django handles all the above parsing / conversions automatically
        # Prefer 2021-09-01T01:23:45Z, don't advertise support for other formats

    def test_list_flaws_exclude_fields(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint with excluded fields"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(flaw=flaw)
            affect.trackers.set([TrackerFactory()])

        flaw_exclude_fields = ["resolution", "state", "uuid", "impact"]
        affect_exclude_fields = ["ps_module", "ps_component", "type", "affectedness"]
        tracker_exclude_fields = ["type", "external_system_id", "status", "resolution"]

        exclude_fields_param = ",".join(
            flaw_exclude_fields
            + [f"affects.{field}" for field in affect_exclude_fields]
            + [f"affects.trackers.{field}" for field in tracker_exclude_fields]
        )

        response = auth_client.get(
            f"{test_api_uri}/flaws?exclude_fields={exclude_fields_param}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        for field in flaw_exclude_fields:
            assert field not in body["results"][0]

        for affect in body["results"][0]["affects"]:
            for field in affect_exclude_fields:
                assert field not in affect

            for tracker in affect["trackers"]:
                for tracker_field in tracker_exclude_fields:
                    assert tracker_field not in tracker

    def test_list_flaws_include_fields(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(flaw=flaw)
            affect.trackers.set([TrackerFactory()])

        flaw_include_fields = ["resolution", "state", "uuid", "impact"]
        affect_include_fields = ["ps_module", "ps_component", "type", "affectedness"]
        tracker_include_fields = ["type", "external_system_id", "status", "resolution"]

        include_fields_param = ",".join(
            flaw_include_fields
            + [f"affects.{field}" for field in affect_include_fields]
            + [f"affects.trackers.{field}" for field in tracker_include_fields]
        )

        response = auth_client.get(
            f"{test_api_uri}/flaws?include_fields={include_fields_param}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        # length of the include fields plus 1 for "affects" which will be present as well
        assert len(body["results"][0]) == len(flaw_include_fields) + 1

        for field in flaw_include_fields:
            assert field in body["results"][0]

        for affect in body["results"][0]["affects"]:
            # length of the include fields plus 1 for "trackers" which will be present as well
            assert len(affect) == len(affect_include_fields) + 1

            for field in affect_include_fields:
                assert field in affect

            for tracker in affect["trackers"]:
                assert len(tracker) == len(tracker_include_fields)
                for tracker_field in tracker_include_fields:
                    assert tracker_field in tracker

    def test_list_flaws_nested_include_fields_only(self, auth_client, test_api_uri):
        """
        retrieve list of flaws from endpoint with included
        fields only in nested serializers
        """
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(flaw=flaw)
            affect.trackers.set([TrackerFactory()])

        affect_include_fields = ["ps_module", "ps_component", "type", "affectedness"]

        include_fields_param = ",".join(
            [f"affects.{field}" for field in affect_include_fields]
        )

        response = auth_client.get(
            f"{test_api_uri}/flaws?include_fields={include_fields_param}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        flaw = body["results"][0]

        # No include fields on flaw level, only affects field should be present
        assert len(flaw) == 1
        assert "affects" in flaw

        for affect in flaw["affects"]:
            # length of the include fields
            assert len(affect) == len(affect_include_fields)

            for field in affect_include_fields:
                assert field in affect

    def test_list_flaws_include_and_exclude_fields(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(flaw=flaw)
            affect.trackers.set([TrackerFactory()])

        flaw_include_fields = ["resolution", "state", "uuid", "impact"]
        affect_include_fields = ["ps_module", "ps_component", "type", "affectedness"]
        tracker_include_fields = ["type", "external_system_id", "status", "resolution"]

        include_fields_param = ",".join(
            flaw_include_fields
            + [f"affects.{field}" for field in affect_include_fields]
            + [f"affects.trackers.{field}" for field in tracker_include_fields]
        )

        flaw_exclude_fields = ["resolution", "state"]
        affect_exclude_fields = ["ps_module", "ps_component"]
        tracker_exclude_fields = ["type", "external_system_id"]

        exclude_fields_param = ",".join(
            flaw_exclude_fields
            + [f"affects.{field}" for field in affect_exclude_fields]
            + [f"affects.trackers.{field}" for field in tracker_exclude_fields]
        )

        response = auth_client.get(
            f"{test_api_uri}/flaws?include_fields={include_fields_param}&exclude_fields={exclude_fields_param}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        # length of the include fields plus 1 for "affects" which will be present as well
        assert len(body["results"][0]) == len(flaw_include_fields) + 1

        for field in flaw_include_fields:
            assert field in body["results"][0]

        for affect in body["results"][0]["affects"]:
            # length of the include fields plus 1 for "trackers" which will be present as well
            assert len(affect) == len(affect_include_fields) + 1

            for field in affect_include_fields:
                assert field in affect

            for tracker in affect["trackers"]:
                assert len(tracker) == len(tracker_include_fields)
                for tracker_field in tracker_include_fields:
                    assert tracker_field in tracker

    def test_retrieve_specific_flaw(self, auth_client, test_api_uri):
        """retrieve single flaw from endpoint"""
        flaw = FlawFactory()

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == 200

    def test_list_retrieve_multiple_flaws_by_cve_id(self, auth_client, test_api_uri):
        """retrieve multiple flaws from list endpoint using cve_id url param"""
        flaw1 = FlawFactory()
        flaw2 = FlawFactory()

        response = auth_client.get(f"{test_api_uri}/flaws?cve_id={flaw1.cve_id}")
        body = response.json()
        assert body["count"] == 1
        assert "meta" in body["results"][0]
        assert "affects" in body["results"][0]

        response = auth_client.get(
            f"{test_api_uri}/flaws?cve_id={flaw1.cve_id},{flaw2.cve_id}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2

    @pytest.mark.parametrize(
        "query_params,expected_keys",
        [
            ("", set()),
            ("include_meta_attr=test_key_1", {"test_key_1"}),
            ("include_meta_attr=test_key_1,test_key_2", {"test_key_1", "test_key_2"}),
            (
                "include_meta_attr=test_key_1,test_key_2,bad_key",
                {"test_key_1", "test_key_2"},
            ),
            ("include_meta_attr=*", {f"test_key_{i}" for i in range(5)}),
        ],
    )
    def test_list_flaws_include_meta_attr(
        self, query_params, expected_keys, auth_client, test_api_uri
    ):
        """retrieve list of flaws with various meta_attr keys"""
        for _ in range(2):
            FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})

        response = auth_client.get(f"{test_api_uri}/flaws?{query_params}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2

        for result in body["results"]:
            if not query_params:
                assert "meta_attr" not in result
            else:
                assert "meta_attr" in result
                assert set(result["meta_attr"].keys()) == expected_keys

    @pytest.mark.parametrize(
        "query_params,expected_keys",
        [
            ("", {"flaw": set(), "affect": set(), "tracker": set()}),
            (
                "include_meta_attr=test_key_1,affects.test_key_2,affects.trackers.test_key_3",
                {
                    "flaw": {"test_key_1"},
                    "affect": {"test_key_2"},
                    "tracker": {"test_key_3"},
                },
            ),
            (
                "include_meta_attr=affects.test_key_1,affects.test_key_2",
                {
                    "flaw": set(),
                    "affect": {"test_key_1", "test_key_2"},
                    "tracker": set(),
                },
            ),
            (
                "include_meta_attr=affects.test_key_1,affects.bad_key",
                {
                    "flaw": set(),
                    "affect": {"test_key_1"},
                    "tracker": set(),
                },
            ),
            (
                "include_meta_attr=*,affects.*,affects.trackers.*",
                {
                    "flaw": {f"test_key_{i}" for i in range(5)},
                    "affect": {f"test_key_{i}" for i in range(5)},
                    "tracker": {f"test_key_{i}" for i in range(5)},
                },
            ),
        ],
    )
    def test_list_flaws_nested_include_meta_attr(
        self, query_params, expected_keys, auth_client, test_api_uri
    ):
        """retrieve list of flaws with various meta_attr keys in nested serializers"""

        for _ in range(2):
            flaw = FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})
            for _ in range(3):
                affect = AffectFactory(
                    flaw=flaw, meta_attr={f"test_key_{i}": "test" for i in range(5)}
                )
                affect.trackers.set(
                    [
                        TrackerFactory(
                            meta_attr={f"test_key_{i}": "test" for i in range(5)}
                        )
                    ]
                )

        response = auth_client.get(f"{test_api_uri}/flaws?{query_params}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2

        for flaw in body["results"]:
            assert is_meta_attr_correct(flaw.get("meta_attr"), expected_keys["flaw"])

            for affect in flaw["affects"]:
                assert is_meta_attr_correct(
                    affect.get("meta_attr"), expected_keys["affect"]
                )

                for tracker in affect["trackers"]:
                    assert is_meta_attr_correct(
                        tracker.get("meta_attr"), expected_keys["tracker"]
                    )

    @pytest.mark.parametrize(
        "query_params,expected_keys",
        [
            ("", set()),
            ("include_meta_attr=test_key_1", {"test_key_1"}),
            ("include_meta_attr=test_key_1,test_key_2", {"test_key_1", "test_key_2"}),
            (
                "include_meta_attr=test_key_1,test_key_2,bad_key",
                {"test_key_1", "test_key_2"},
            ),
            ("include_meta_attr=*", {f"test_key_{i}" for i in range(5)}),
        ],
    )
    def test_flaw_include_meta_attr(
        self, query_params, expected_keys, auth_client, test_api_uri
    ):
        """retrieve specific flaw with various meta_attr keys"""
        flaw = FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}?{query_params}")
        assert response.status_code == 200
        body = response.json()

        if not query_params:
            assert "meta_attr" not in body
        else:
            assert "meta_attr" in body
            assert set(body["meta_attr"].keys()) == expected_keys

    @pytest.mark.parametrize(
        "query_params,expected_keys",
        [
            ("", {"flaw": set(), "affect": set(), "tracker": set()}),
            (
                "include_meta_attr=test_key_1,affects.test_key_2,affects.trackers.test_key_3",
                {
                    "flaw": {"test_key_1"},
                    "affect": {"test_key_2"},
                    "tracker": {"test_key_3"},
                },
            ),
            (
                "include_meta_attr=affects.test_key_1,affects.test_key_2",
                {
                    "flaw": set(),
                    "affect": {"test_key_1", "test_key_2"},
                    "tracker": set(),
                },
            ),
            (
                "include_meta_attr=affects.test_key_1,affects.bad_key",
                {
                    "flaw": set(),
                    "affect": {"test_key_1"},
                    "tracker": set(),
                },
            ),
            (
                "include_meta_attr=*,affects.*,affects.trackers.*",
                {
                    "flaw": {f"test_key_{i}" for i in range(5)},
                    "affect": {f"test_key_{i}" for i in range(5)},
                    "tracker": {f"test_key_{i}" for i in range(5)},
                },
            ),
        ],
    )
    def test_flaw_nested_include_meta_attr(
        self, query_params, expected_keys, auth_client, test_api_uri
    ):
        """retrieve specific flaw with various meta_attr keys in nested serializers"""

        flaw = FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})
        for _ in range(3):
            affect = AffectFactory(
                flaw=flaw, meta_attr={f"test_key_{i}": "test" for i in range(5)}
            )
            affect.trackers.set(
                [TrackerFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})]
            )

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}?{query_params}")
        assert response.status_code == 200
        flaw = response.json()

        assert is_meta_attr_correct(flaw.get("meta_attr"), expected_keys["flaw"])

        for affect in flaw["affects"]:
            assert is_meta_attr_correct(
                affect.get("meta_attr"), expected_keys["affect"]
            )

            for tracker in affect["trackers"]:
                assert is_meta_attr_correct(
                    tracker.get("meta_attr"), expected_keys["tracker"]
                )

    @pytest.mark.parametrize(
        "query_params,expected_values",
        [
            ("flaw_meta_type=reference", {"REFERENCE"}),
            ("flaw_meta_type=reference,checklist", {"REFERENCE", "CHECKLIST"}),
            (
                "flaw_meta_type=reference,checklist,bad_type",
                {"REFERENCE", "CHECKLIST"},
            ),
            ("", {"REFERENCE", "CHECKLIST", "NEED_INFO"}),
        ],
    )
    def test_list_flaw_meta_type(
        self, query_params, expected_values, auth_client, test_api_uri
    ):

        for _ in range(2):
            flaw = FlawFactory()

            FlawMetaFactory(type=FlawMeta.FlawMetaType.REFERENCE, flaw=flaw)
            FlawMetaFactory(type="CHECKLIST", flaw=flaw)
            FlawMetaFactory(type="NEED_INFO", flaw=flaw)

        response = auth_client.get(f"{test_api_uri}/flaws?{query_params}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2

        for result in body["results"]:
            if not query_params:
                assert "meta" in result
            else:
                assert "meta" in result
                assert set([obj["type"] for obj in result["meta"]]) == expected_values

    @pytest.mark.parametrize(
        "query_params,expected_values",
        [
            ("flaw_meta_type=reference", {"REFERENCE"}),
            ("flaw_meta_type=reference,checklist", {"REFERENCE", "CHECKLIST"}),
            (
                "flaw_meta_type=reference,checklist,bad_type",
                {"REFERENCE", "CHECKLIST"},
            ),
            ("", {"REFERENCE", "CHECKLIST", "NEED_INFO"}),
        ],
    )
    def test_flaw_meta_type(
        self, query_params, expected_values, auth_client, test_api_uri
    ):
        flaw = FlawFactory()

        FlawMetaFactory(type=FlawMeta.FlawMetaType.REFERENCE, flaw=flaw)
        FlawMetaFactory(type="CHECKLIST", flaw=flaw)
        FlawMetaFactory(type="NEED_INFO", flaw=flaw)

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}?{query_params}")
        assert response.status_code == 200
        body = response.json()

        if not query_params:
            assert "meta" in body
        else:
            assert "meta" in body
            assert set([obj["type"] for obj in body["meta"]]) == expected_values

    def test_flaw_including_package_versions(self, auth_client, test_api_uri):
        """retrieve flaw with package_versions"""
        version = CVEv5VersionFactory()
        package_versions = CVEv5PackageVersionsFactory(versions=[version])

        response = auth_client.get(
            f"{test_api_uri}/flaws/{package_versions.flaw.cve_id}"
        )
        assert response.status_code == 200
        body = response.json()

        assert "package_versions" in body
        first_package_version = body["package_versions"][0]
        assert "package" in first_package_version

        assert "versions" in first_package_version
        assert "3.2.1" == first_package_version["versions"][0]["version"]

    def test_flaw_including_classification(self, auth_client, test_api_uri):
        """retrieve flaw with classification data"""
        flaw = FlawFactory()  # random flaw

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == 200
        body = response.json()

        assert "classification" in body
        assert "workflow" in body["classification"]
        assert "state" in body["classification"]
        assert body["classification"]["workflow"] is not None
        assert body["classification"]["state"] is not None

    def test_flaw_including_delegated_resolution(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        delegated_affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        TrackerFactory(affects=(delegated_affect,), status="won't fix")

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert "affects" in body
        affect = body["affects"][0]
        assert "trackers" in affect
        assert affect["delegated_resolution"] == Affect.AffectFix.WONTFIX

        # assert delegated_affect.delegated_resolution == Affect.AffectFix.WONTFIX

    def test_get_flaw_with_token(
        self,
        auth_client,
        client,
        test_api_uri,
        root_url,
        ldap_test_username,
        ldap_test_password,
    ):

        """retrieve specific flaw from endpoint using generated auth token"""

        # get token
        post_data = {"username": ldap_test_username, "password": ldap_test_password}
        response = auth_client.post(f"{root_url}/auth/token", post_data)
        assert response.status_code == 200
        body = response.json()
        assert "access" in body
        assert "refresh" in body
        token = body["access"]

        flaw1 = FlawFactory.build(is_major_incident=True)
        flaw1.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=flaw1,
            type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT,
            meta_attr={"status": "+"},
        )
        assert flaw1.save() is None
        FlawCommentFactory(flaw=flaw1)

        # attempt to access with unauthenticated client using good token value
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.cve_id}", HTTP_AUTHORIZATION=f"Bearer {token}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["is_major_incident"] is True
        assert len(body["comments"]) == 1

    def test_flaw_create(self, auth_client, test_api_uri):
        """
        Test that creating a Flaw by sending a POST request works.
        """
        flaw_data = {
            "cve_id": "CVE-2021-0666",
            "cwe_id": "CWE-1",
            "title": "Foo",
            "type": "VULNERABILITY",
            "state": "NEW",
            "impact": "CRITICAL",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        }
        response = auth_client.post(f"{test_api_uri}/flaws", flaw_data, format="json")
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] == "CVE-2021-0666"

    def test_flaw_draft_create(self, auth_client, test_api_uri):
        """
        Test that creating a Flaw Draft by sending a POST request works.
        """
        # a flaw draft essentially has no CVE
        flaw_data = {
            "cwe_id": "CWE-1",
            "title": "Foo",
            "type": "VULNERABILITY",
            "state": "NEW",
            "impact": "CRITICAL",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        }
        response = auth_client.post(f"{test_api_uri}/flaws", flaw_data, format="json")
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] is None

        # let's try creating another one without cve_id to make sure the
        # unique=True constraint doesn't jump (I don't trust django)
        response = auth_client.post(f"{test_api_uri}/flaws", flaw_data, format="json")
        assert response.status_code == 201
        body = response.json()
        new_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/flaws/{new_uuid}")
        assert response.status_code == 200
        body = response.json()
        assert response.json()["cve_id"] is None
        # verify that they are different flaw drafts
        assert new_uuid != created_uuid

    def test_flaw_update(self, auth_client, test_api_uri):
        """
        Test that updating a Flaw by sending a PUT request works.
        """
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "type": flaw.type,
                "title": f"{flaw.title} appended test title",
                "description": flaw.description,
                "state": flaw.state,
                "resolution": flaw.resolution,
                "impact": flaw.impact,
                "acl_read": flaw.acl_read,
                "acl_write": flaw.acl_write,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["title"] != body["title"]
        assert "appended test title" in body["title"]
        assert original_body["description"] == body["description"]

    def test_flaw_delete(self, auth_client, test_api_uri):
        """
        Test that deleting a Flaw by sending a DELETE request works.
        """
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client.delete(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 204

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 404

    def test_list_flaws_tracker_ids(self, auth_client, test_api_uri):
        """
        retrieve list of flaws that are related to specified trackers
        through affects and ensure that only those affects related to
        specified trackers are visible
        """

        flaw = FlawFactory()
        FlawFactory()

        affects_with_trackers_to_fetch = [AffectFactory(flaw=flaw) for _ in range(5)]
        other_affects = [AffectFactory(flaw=flaw) for _ in range(5)]

        trackers_to_fetch = [TrackerFactory() for _ in range(5)]
        other_trackers = [TrackerFactory() for _ in range(5)]

        for affect, tracker in zip(affects_with_trackers_to_fetch, trackers_to_fetch):
            affect.trackers.set([tracker])

        for affect, tracker in zip(other_affects, other_trackers):
            affect.trackers.set([tracker])

        affect_ids = {str(affect.uuid) for affect in affects_with_trackers_to_fetch}
        tracker_ids = {str(tracker.external_system_id) for tracker in trackers_to_fetch}

        response = auth_client.get(
            f"{test_api_uri}/flaws?tracker_ids={','.join(tracker_ids)}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        flaw = body["results"][0]

        assert {affect["uuid"] for affect in flaw["affects"]} == affect_ids
        fetched_affect_ids = set()
        fetched_tracker_ids = set()
        for affect in flaw["affects"]:
            fetched_affect_ids.add(affect["uuid"])

            for tracker in affect["trackers"]:
                fetched_tracker_ids.add(tracker["external_system_id"])

        assert fetched_affect_ids == affect_ids
        assert fetched_tracker_ids == tracker_ids

    def test_whoami(self, auth_client, root_url):
        res = auth_client.get(f"{root_url}/osidb/whoami").json()
        assert res["username"] == "testuser"
        assert res["email"] == "silenceawarning"
        assert "data-prodsec" in res["groups"]
        assert res["profile"] is None

    def test_affect_create(self, auth_client, test_api_uri):
        """
        Test the creation of Affect records via a REST API POST request.
        """
        flaw = FlawFactory()
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NOVALUE,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_module": "rhacm-2",
            "ps_component": "curl",
        }
        response = auth_client.post(
            f"{test_api_uri}/affects", affect_data, format="json"
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/affects/{created_uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["ps_module"] == "rhacm-2"

    def test_affect_update(self, auth_client, test_api_uri):
        """
        Test the update of Affect records via a REST API PUT request.
        """
        affect = AffectFactory()
        response = auth_client.get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client.put(
            f"{test_api_uri}/affects/{affect.uuid}",
            {
                **original_body,
                "ps_module": f"different {affect.ps_module}",
            },
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["ps_module"] != body["ps_module"]

    def test_affect_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of Affect records via a REST API DELETE request.
        """
        affect = AffectFactory()
        affect_url = f"{test_api_uri}/affects/{affect.uuid}"
        response = auth_client.get(affect_url)
        assert response.status_code == 200

        response = auth_client.delete(affect_url)
        assert response.status_code == 204

        response = auth_client.get(affect_url)
        assert response.status_code == 404

    def test_tracker_create(self, auth_client, test_api_uri):
        """
        Test the creation of Tracker records via a REST API POST request.
        """
        tracker_data = {
            "type": Tracker.TrackerType.JIRA,
            "external_system_id": "PSDEVOPS-0001",
            "status": "foo",
            "resolution": "bar",
        }
        response = auth_client.post(
            f"{test_api_uri}/trackers", tracker_data, format="json"
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/trackers/{created_uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "foo"
        assert body["resolution"] == "bar"

    def test_tracker_update(self, auth_client, test_api_uri):
        """
        Test the update of Tracker records via a REST API PUT request.
        """
        tracker = TrackerFactory()
        response = auth_client.get(f"{test_api_uri}/trackers/{tracker.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client.put(
            f"{test_api_uri}/trackers/{tracker.uuid}",
            {
                **original_body,
                "resolution": "this is different",
            },
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["resolution"] != body["resolution"]

    def test_tracker_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of Tracker records via a REST API DELETE request.
        """
        tracker = TrackerFactory()
        tracker_url = f"{test_api_uri}/trackers/{tracker.uuid}"
        response = auth_client.get(tracker_url)
        assert response.status_code == 200

        response = auth_client.delete(tracker_url)
        assert response.status_code == 204

        response = auth_client.get(tracker_url)
        assert response.status_code == 404
