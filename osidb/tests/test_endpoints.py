import uuid
from datetime import timedelta
from typing import Set, Union

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from django.utils.timezone import datetime
from freezegun import freeze_time
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from osidb.filters import FlawFilter

from ..core import generate_acls
from ..helpers import ensure_list
from ..models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawMeta,
    FlawReference,
    FlawSource,
    Package,
    PackageVer,
    Tracker,
)
from .factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawMetaFactory,
    FlawReferenceFactory,
    PackageFactory,
    PackageVerFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
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

    def test_get_flaw_with_acknowledgments(self, auth_client, test_api_uri):
        """retrieve specific flaw with flawacknowledgments from endpoint"""

        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["acknowledgments"]) == 0

        FlawAcknowledgmentFactory(flaw=flaw)

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["acknowledgments"]) == 1

    def test_get_flaw_with_references(self, auth_client, test_api_uri):
        """retrieve specific flaw with flawreferences from endpoint"""
        flaw = FlawFactory()

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["references"]) == 0

        FlawReferenceFactory(flaw=flaw)

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["references"]) == 1

    @pytest.mark.enable_signals
    def test_get_flaw_with_cvss(self, auth_client, test_api_uri):
        """retrieve specific flaw with flawcvss from endpoint"""
        flaw = FlawFactory()

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 0

        FlawCVSSFactory(flaw=flaw)

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 1

    @pytest.mark.enable_signals
    def test_get_affect_with_cvss(self, auth_client, test_api_uri):
        """retrieve specific affect with affectcvss from endpoint"""
        affect = AffectFactory()

        response = auth_client.get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 0

        AffectCVSSFactory(affect=affect)

        response = auth_client.get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 1

    def test_get_flaw(self, auth_client, test_api_uri):
        """retrieve specific flaw from endpoint"""

        flaw1 = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            requires_summary=Flaw.FlawRequiresSummary.APPROVED,
            nist_cvss_validation=Flaw.FlawNistCvssValidation.NOVALUE,
        )
        flaw1.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=flaw1,
            type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
            meta_attr={"status": "+"},
        )
        FlawReferenceFactory(
            flaw=flaw1,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        AffectFactory(flaw=flaw1)
        assert flaw1.save() is None
        assert flaw1.requires_summary == Flaw.FlawRequiresSummary.APPROVED
        FlawCommentFactory(flaw=flaw1)
        response = auth_client.get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["major_incident_state"] == Flaw.FlawMajorIncident.APPROVED
        assert body["nist_cvss_validation"] == Flaw.FlawNistCvssValidation.NOVALUE
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

        FlawFactory(updated_dt=datetime_with_tz)

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

    def test_list_flaws_changed_before_and_after(
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

        FlawFactory(updated_dt=datetime_with_tz)

        past_str = f"{datetime_with_tz - timedelta(days=1)}"
        future_str = f"{datetime_with_tz + timedelta(days=1)}"
        past_str = past_str.replace("+00:00", "Z")
        future_str = future_str.replace("+00:00", "Z")
        response = auth_client.get(
            f"{test_api_uri}/flaws?changed_after={past_str}&changed_before={future_str}"
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 1
        )  # One Flaw that was changed after a past date AND before a future date

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

    @freeze_time(datetime(2021, 11, 23))
    def test_changed_after_from_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=(affect,),
            embargoed=affect.flaw.embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        future_dt = datetime(2021, 11, 27)

        # first check that we cannot get anything by querying any flaws changed after future_dt
        response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        # now let's update the tracker during future_dt and verify that the filter picked up the
        # change in the corresponding flaw
        with freeze_time(future_dt):
            tracker.external_system_id = "foo"
            tracker.save()
        assert tracker.updated_dt == future_dt.astimezone(
            timezone.get_current_timezone()
        )

        # we should get a result now
        response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    def test_changed_after_from_affect(self, auth_client, test_api_uri):
        affect = AffectFactory()
        future_dt = datetime(2021, 11, 27)

        response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        with freeze_time(future_dt):
            affect.ps_component = "foo"
            affect.save()
        assert affect.updated_dt == future_dt.astimezone(
            timezone.get_current_timezone()
        )

        response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    def test_changed_after_from_multi_affect(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        affect1 = AffectFactory(flaw=flaw)
        affect2 = AffectFactory(flaw=flaw)
        future_dt = datetime(2021, 11, 27)

        response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        for affect in [affect1, affect2]:
            with freeze_time(future_dt):
                affect.ps_component = "foo"
                affect.save()
            assert affect.updated_dt == future_dt.astimezone(
                timezone.get_current_timezone()
            )

        response = auth_client.get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    def test_changed_before_from_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory(updated_dt=datetime(2021, 11, 23))
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            updated_dt=datetime(2021, 11, 23),
        )
        tracker = TrackerFactory(
            affects=(affect,),
            embargoed=affect.flaw.embargoed,
            updated_dt=datetime(2021, 11, 23),
            type=Tracker.TrackerType.BUGZILLA,
        )
        past_dt = datetime(2019, 11, 27)

        # first check that we cannot get anything by querying any flaws changed after future_dt
        response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        # now let's update the tracker during future_dt and verify that the filter picked up the
        # change in the corresponding flaw
        with freeze_time(past_dt):
            tracker.external_system_id = "foo"
            tracker.save()
        assert tracker.updated_dt == past_dt.astimezone(timezone.get_current_timezone())

        # we should get a result now
        response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    def test_changed_before_from_affect(self, auth_client, test_api_uri):
        flaw = FlawFactory(updated_dt=datetime(2021, 11, 23))
        affect = AffectFactory(flaw=flaw, updated_dt=datetime(2021, 11, 23))
        past_dt = datetime(2019, 11, 27)

        response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        with freeze_time(past_dt):
            affect.ps_component = "foo"
            affect.save()
        assert affect.updated_dt == past_dt.astimezone(timezone.get_current_timezone())

        response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    def test_changed_before_from_multi_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory(updated_dt=datetime(2021, 11, 23))
        affect1 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            updated_dt=datetime(2021, 11, 23),
        )
        affect2 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            updated_dt=datetime(2021, 11, 23),
        )
        tracker1 = TrackerFactory(
            affects=(affect1,),
            embargoed=flaw.embargoed,
            updated_dt=datetime(2021, 11, 23),
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker2 = TrackerFactory(
            affects=(affect2,),
            embargoed=flaw.embargoed,
            updated_dt=datetime(2021, 11, 23),
            type=Tracker.TrackerType.BUGZILLA,
        )
        past_dt = datetime(2019, 11, 27)

        # first check that we cannot get anything by querying any flaws changed after future_dt
        response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        # now let's update the tracker during future_dt and verify that the filter picked up the
        # change in the corresponding flaw
        for tracker in [tracker1, tracker2]:
            with freeze_time(past_dt):
                tracker.resolution = "foo"
                tracker.save()
            assert tracker.updated_dt == past_dt.astimezone(
                timezone.get_current_timezone()
            )

        # we should get a result now
        response = auth_client.get(f"{test_api_uri}/flaws?changed_before={past_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

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

        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_module=ps_module.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.FIX,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

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

        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_module=ps_module.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.FIX,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

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

        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_module=ps_module.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.FIX,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

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

        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_module=ps_module.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.FIX,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

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
            ps_module = PsModuleFactory(bts_name="bugzilla")
            flaw = FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})
            for _ in range(3):
                affect = AffectFactory(
                    flaw=flaw,
                    ps_module=ps_module.name,
                    meta_attr={f"test_key_{i}": "test" for i in range(5)},
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                )
                TrackerFactory(
                    affects=[affect],
                    embargoed=flaw.is_embargoed,
                    meta_attr={f"test_key_{i}": "test" for i in range(5)},
                    type=Tracker.TrackerType.BUGZILLA,
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

        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})
        for _ in range(3):
            affect = AffectFactory(
                flaw=flaw,
                ps_module=ps_module.name,
                meta_attr={f"test_key_{i}": "test" for i in range(5)},
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                meta_attr={f"test_key_{i}": "test" for i in range(5)},
                type=Tracker.TrackerType.BUGZILLA,
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
        package_versions = PackageFactory()
        PackageVerFactory(package=package_versions)

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
        ps_module = PsModuleFactory(bts_name="bugzilla")
        PsUpdateStreamFactory(name="rhel-7.0", active_to_ps_module=ps_module)
        flaw = FlawFactory()
        delegated_affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        TrackerFactory(
            affects=(delegated_affect,),
            status="won't fix",
            embargoed=flaw.is_embargoed,
            ps_update_stream="rhel-7.0",
            type=Tracker.TrackerType.BUGZILLA,
        )

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert "affects" in body
        affect = body["affects"][0]
        assert "trackers" in affect
        assert affect["delegated_resolution"] == Affect.AffectFix.WONTFIX
        assert affect["trackers"][0]["ps_update_stream"] == "rhel-7.0"

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

        flaw1 = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            requires_summary=Flaw.FlawRequiresSummary.APPROVED,
        )
        flaw1.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=flaw1,
            type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
            meta_attr={"status": "+"},
        )
        FlawReferenceFactory(
            flaw=flaw1,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        AffectFactory(flaw=flaw1)

        assert flaw1.save() is None
        assert flaw1.requires_summary == Flaw.FlawRequiresSummary.APPROVED
        FlawCommentFactory(flaw=flaw1)

        # attempt to access with unauthenticated client using good token value
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.cve_id}", HTTP_AUTHORIZATION=f"Bearer {token}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["major_incident_state"] == Flaw.FlawMajorIncident.APPROVED
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
            "component": "curl",
            "source": "INTERNET",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        response = auth_client.post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] == "CVE-2021-0666"
        assert response.json()["component"] == "curl"

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
            "component": "curl",
            "source": "INTERNET",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        response = auth_client.post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] is None

        # let's try creating another one without cve_id to make sure the
        # unique=True constraint doesn't jump (I don't trust django)
        response = auth_client.post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
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
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
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
                "impact": flaw.impact,
                "source": flaw.source,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["title"] != body["title"]
        assert "appended test title" in body["title"]
        assert original_body["description"] == body["description"]

    @pytest.mark.parametrize("embargoed", [True, False])
    @pytest.mark.parametrize(
        "old_cve_id,new_cve_id",
        [
            (None, "CVE-2020-12345"),
            ("CVE-2020-12345", None),
            ("CVE-2020-12345", "CVE-2020-54321"),
        ],
    )
    def test_flaw_update_cve(
        self,
        auth_client,
        embargo_access,
        test_api_uri,
        embargoed,
        old_cve_id,
        new_cve_id,
    ):
        """
        Test that updating a Flaw CVE ID by sending a PUT request works.
        """
        flaw = FlawFactory(embargoed=embargoed, cve_id=old_cve_id)
        AffectFactory(flaw=flaw)
        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["embargoed"] == embargoed
        assert body["cve_id"] == old_cve_id

        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "cve_id": new_cve_id,
                "title": flaw.title,
                "description": flaw.description,
                "embargoed": embargoed,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert body["embargoed"] == embargoed
        assert body["cve_id"] == new_cve_id

    @pytest.mark.parametrize(
        "embargoed,old_date,new_date,alerts",
        [
            (
                False,
                datetime(2011, 1, 1, tzinfo=timezone.utc),
                datetime(2012, 1, 1, tzinfo=timezone.utc),
                False,
            ),
            (
                False,
                datetime(2021, 1, 1, tzinfo=timezone.utc),
                datetime(2022, 1, 1, tzinfo=timezone.utc),
                True,
            ),
            (
                False,
                datetime(2011, 1, 1, tzinfo=timezone.utc),
                datetime(2022, 1, 1, tzinfo=timezone.utc),
                True,
            ),
            (
                False,
                datetime(2021, 1, 1, tzinfo=timezone.utc),
                datetime(2012, 1, 1, tzinfo=timezone.utc),
                False,
            ),
            (
                True,
                datetime(2011, 1, 1, tzinfo=timezone.utc),
                datetime(2012, 1, 1, tzinfo=timezone.utc),
                True,
            ),
            (
                True,
                datetime(2021, 1, 1, tzinfo=timezone.utc),
                datetime(2022, 1, 1, tzinfo=timezone.utc),
                False,
            ),
            (
                True,
                datetime(2011, 1, 1, tzinfo=timezone.utc),
                datetime(2022, 1, 1, tzinfo=timezone.utc),
                False,
            ),
            (
                True,
                datetime(2021, 1, 1, tzinfo=timezone.utc),
                datetime(2012, 1, 1, tzinfo=timezone.utc),
                True,
            ),
        ],
    )
    @freeze_time(datetime(2020, 1, 1, tzinfo=timezone.utc))
    def test_flaw_update_enembargo_dt(
        self,
        auth_client,
        embargo_access,
        test_api_uri,
        embargoed,
        old_date,
        new_date,
        alerts,
    ):
        """
        test proper behavior while updating the unembargo_dt

        the failure is expected in either a case when we assign a future public date to an
        already public flaw or when we assign a past public date to a still embargoed flaw
        and it should not matter what was the original public date before the change
        """
        flaw = FlawFactory.build(embargoed=embargoed, unembargo_dt=old_date)
        flaw.save(raise_validation_error=False)
        AffectFactory(flaw=flaw)

        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": flaw.title,
                "description": flaw.description,
                "embargoed": embargoed,
                "unembargo_dt": new_date,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        if alerts:
            assert response.status_code == 400

        else:
            assert response.status_code == 200
            assert Flaw.objects.first().unembargo_dt == new_date

    def test_flaw_update_collision(self, auth_client, test_api_uri):
        """
        test that updating a flaw while sending an outdated updated_dt
        timestamp is correctly recognized as mid-air collision and rejected
        """
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "type": flaw.type,
                "title": f"{flaw.title} appended test title",
                "description": flaw.description,
                "impact": flaw.impact,
                "source": flaw.source,
                "embargoed": flaw.embargoed,
                "updated_dt": flaw.updated_dt - timedelta(days=1),  # outdated timestamp
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        assert response.status_code == 409
        assert "Save operation based on an outdated model instance" in str(
            response.content
        )

    def test_flaw_comment_create(self, auth_client, test_api_uri):
        """
        Test that adding a flaw comment by sending a POST request works.
        """

        def new_flaw():
            flaw = FlawFactory(embargoed=False)
            AffectFactory(flaw=flaw)
            response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200
            assert not FlawComment._base_manager.filter(flaw=flaw).exists()
            return flaw

        def get_response(flaw, new_comment):
            return auth_client.post(
                f"{test_api_uri}/flaws/{flaw.uuid}/comments",
                {
                    "order": 1,
                    "embargoed": False,
                    "text": new_comment,
                },
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
            )

        flaw = new_flaw()
        assert not FlawComment.objects.filter(flaw=flaw).exists()
        response = get_response(flaw, "HELLO WORLD COMMENT")
        assert response.status_code == 201

        # NOTE: In this test, `SYNC_TO_BZ and bz_api_key is not None` is False in BugzillaSyncMixin.
        #       Therefore Flaw.bzsync() is not called, BugzillaQueryBuilder doesn't process the new
        #       pending FlawComment, and new comment is not re-fetched through FlawCollector, and
        #       the temporary pending FlawComment instance isn't updated.
        assert FlawComment.objects.filter(flaw=flaw).exists()
        first_comment = FlawComment.objects.filter(flaw=flaw).first()
        assert first_comment.text == "HELLO WORLD COMMENT"
        # In a real-world non-test scenario, the new comment would not be pending anymore and the
        # following assert would fail:
        assert first_comment == FlawComment.objects.pending().filter(flaw=flaw).first()

        # Behaves like an ordinary non-idempotent POST endpoint. You can just simply post comments.
        response = get_response(flaw, "ANOTHER HELLO WORLD COMMENT")
        assert response.status_code == 201

    def test_flaw_delete(self, auth_client, test_api_uri):
        """
        Test that deleting a Flaw by sending a DELETE request works.
        """
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client.delete(f"{test_api_uri}/flaws/{flaw.uuid}")
        # this HTTP method is not allowed until we leave Bugzilla and
        # define the conditions under which a flaw can be deleted
        assert response.status_code == 405

    def test_list_flaws_tracker_ids(self, auth_client, test_api_uri):
        """
        retrieve list of flaws that are related to specified trackers
        through affects and ensure that only those affects related to
        specified trackers are visible
        """

        flaw = FlawFactory()
        FlawFactory()

        ps_module = PsModuleFactory(bts_name="bugzilla")
        affects_with_trackers_to_fetch = [
            AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.FIX,
                ps_module=ps_module.name,
            )
            for _ in range(5)
        ]
        other_affects = [
            AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.FIX,
                ps_module=ps_module.name,
            )
            for _ in range(5)
        ]

        trackers_to_fetch = [
            TrackerFactory(
                affects=[affects_with_trackers_to_fetch[idx]],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )
            for idx in range(5)
        ]
        for idx in range(5):
            TrackerFactory(
                affects=[other_affects[idx]],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

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

    @pytest.mark.parametrize(
        "flaw_embargo,affect_embargo,fails",
        [
            (False, False, False),
            (True, True, False),
            (False, True, True),
            (True, False, True),
        ],
    )
    def test_affect_create(
        self,
        auth_client,
        embargo_access,
        test_api_uri,
        flaw_embargo,
        affect_embargo,
        fails,
    ):
        """
        test the creation of Affect records via a REST API POST request
        also with respect to the flaw and affect visibility (which should be equal in Buzilla world)
        """
        flaw = FlawFactory(embargoed=flaw_embargo)
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_module": "rhacm-2",
            "ps_component": "curl",
            "embargoed": affect_embargo,
        }
        response = auth_client.post(
            f"{test_api_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        if fails:
            assert response.status_code == 400
            assert "ACLs must correspond to the parrent flaw:" in str(response.content)

        else:
            assert response.status_code == 201
            body = response.json()
            created_uuid = body["uuid"]

            response = auth_client.get(f"{test_api_uri}/affects/{created_uuid}")
            assert response.status_code == 200
            body = response.json()
            assert body["ps_module"] == "rhacm-2"

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_affect_update(self, auth_client, embargo_access, test_api_uri, embargoed):
        """
        Test the update of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(embargoed=embargoed)
        affect = AffectFactory(flaw=flaw)
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
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["ps_module"] != body["ps_module"]

    def test_affect_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of Affect records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        affect_url = f"{test_api_uri}/affects/{affect.uuid}"
        response = auth_client.get(affect_url)
        assert response.status_code == 200

        response = auth_client.delete(affect_url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == 200

        response = auth_client.get(affect_url)
        assert response.status_code == 404

    def test_flawacknowledgment_create(self, auth_client, embargo_access, test_api_uri):
        """
        Test the creation of FlawAcknowledgment records via a REST API POST request.
        """
        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)

        flawacknowledgment_data = {
            "name": "John Doe",
            "affiliation": "Acme Corp.",
            "from_upstream": False,
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/acknowledgments
        response = auth_client.post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments",
            flawacknowledgment_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        acknowledgment_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/acknowledgments
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/acknowledgments/{uuid}
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{acknowledgment_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == acknowledgment_uuid

    def test_flawacknowledgment_update(self, auth_client, embargo_access, test_api_uri):
        """
        Test the update of FlawAcknowledgment records via a REST API PUT request.
        """
        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)
        flawacknowledgment = FlawAcknowledgmentFactory(flaw=flaw)

        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{flawacknowledgment.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["name"] == "John Doe"

        updated_data = response.json().copy()
        updated_data["name"] = "Jon A"

        # Tests "PUT" on flaws/{uuid}/acknowledgments/{uuid}
        response = auth_client.put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{flawacknowledgment.uuid}",
            {**updated_data},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["name"] == "Jon A"

    def test_flawacknowledgment_delete(self, auth_client, embargo_access, test_api_uri):
        """
        Test the deletion of FlawAcknowledgment records via a REST API DELETE request.
        """
        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)
        flawacknowledgment = FlawAcknowledgmentFactory(flaw=flaw)

        # Necessary for Flaw validation
        AffectFactory(flaw=flaw)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{flawacknowledgment.uuid}"
        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/acknowledgments/{uuid}
        response = auth_client.delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert FlawAcknowledgment.objects.count() == 0

    def test_flawreference_create(self, auth_client, embargo_access, test_api_uri):
        """
        Test the creation of FlawReference records via a REST API POST request.
        """
        flaw = FlawFactory()

        flawreference_data = {
            "flaw": str(flaw.uuid),
            "type": "EXTERNAL",
            "url": "https://httpd.apache.org/link123",
            "description": "link description",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/references
        response = auth_client.post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references",
            flawreference_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        reference_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/references
        response = auth_client.get(f"{test_api_uri}/flaws/{str(flaw.uuid)}/references")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/references/{uuid}
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{reference_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == reference_uuid

    def test_flawreference_update(self, auth_client, embargo_access, test_api_uri):
        """
        Test the update of FlawReference records via a REST API PUT request.
        """
        flaw = FlawFactory()
        flawreference = FlawReferenceFactory(flaw=flaw)

        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{flawreference.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["url"] == "https://httpd.apache.org/link123"

        updated_data = response.json().copy()
        updated_data["url"] = "https://httpd.apache.org/link456"

        # Tests "PUT" on flaws/{uuid}/references/{uuid}
        response = auth_client.put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{flawreference.uuid}",
            {**updated_data},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["url"] == "https://httpd.apache.org/link456"

    def test_flawreference_delete(self, auth_client, embargo_access, test_api_uri):
        """
        Test the deletion of FlawReference records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        flawreference = FlawReferenceFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{flawreference.uuid}"
        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/references/{uuid}
        response = auth_client.delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert FlawReference.objects.count() == 0

    @pytest.mark.enable_signals
    def test_flawcvss_create(self, auth_client, embargo_access, test_api_uri):
        """
        Test the creation of FlawCVSS records via a REST API POST request.
        """
        flaw = FlawFactory()
        cvss_data = {
            "issuer": FlawCVSS.CVSSIssuer.REDHAT,
            "cvss_version": FlawCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/cvss_scores
        response = auth_client.post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/cvss_scores
        response = auth_client.get(f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    @pytest.mark.enable_signals
    def test_flawcvss_update(self, auth_client, embargo_access, test_api_uri):
        """
        Test the update of FlawCVSS records via a REST API PUT request.
        """
        flaw = FlawFactory()
        cvss = FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.REDHAT, comment="")

        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client.put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == "text"

    @pytest.mark.enable_signals
    def test_flawcvss_delete(self, auth_client, embargo_access, test_api_uri):
        """
        Test the deletion of FlawCVSS records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)
        cvss = FlawCVSSFactory(flaw=flaw)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client.delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert FlawCVSS.objects.count() == 0

    @pytest.mark.enable_signals
    def test_affectcvss_create(self, auth_client, embargo_access, test_api_uri):
        """
        Test the creation of AffectCVSS records via a REST API POST request.
        """
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss_data = {
            "issuer": AffectCVSS.CVSSIssuer.REDHAT,
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on affects/{uuid}/cvss_scores
        response = auth_client.post(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on affects/{uuid}/cvss_scores
        response = auth_client.get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client.get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    @pytest.mark.enable_signals
    def test_affectcvss_update(self, auth_client, embargo_access, test_api_uri):
        """
        Test the update of AffectCVSS records via a REST API PUT request.
        """
        affect = AffectFactory()
        cvss = AffectCVSSFactory(
            affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT, comment=""
        )

        response = auth_client.get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client.put(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == "text"

    @pytest.mark.enable_signals
    def test_affectcvss_delete(self, auth_client, embargo_access, test_api_uri):
        """
        Test the deletion of AffectCVSS records via a REST API DELETE request.
        """
        affect = AffectFactory()
        cvss = AffectCVSSFactory(affect=affect)

        url = f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client.delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert AffectCVSS.objects.count() == 0

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_tracker_create(self, auth_client, embargo_access, test_api_uri, embargoed):
        """
        Test the creation of Tracker records via a REST API POST request.
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw__embargoed=embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            ps_module=ps_module.name,
        )

        assert Tracker.objects.count() == 0

        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": embargoed,
            "ps_update_stream": ps_update_stream.name,
            "status": "TEST",  # this one is mandatory
        }
        response = auth_client.post(
            f"{test_api_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()
        assert tracker.affects.count() == 1
        assert tracker.affects.first().uuid == affect.uuid

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_tracker_update(self, auth_client, embargo_access, test_api_uri, embargoed):
        """
        Test the update of Tracker records via a REST API PUT request.
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw__embargoed=embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
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
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_tracker_update_link(
        self, auth_client, embargo_access, test_api_uri, embargoed
    ):
        """
        Test the update of Tracker records via a REST API PUT request.
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect1 = AffectFactory(
            flaw__embargoed=embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            ps_module=ps_module.name,
        )
        affect2 = AffectFactory(
            flaw__embargoed=embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect1],
            embargoed=affect1.flaw.embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )

        response = auth_client.get(f"{test_api_uri}/trackers/{tracker.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert affect1.uuid in response.data["affects"]
        assert affect2.uuid not in response.data["affects"]

        response = auth_client.put(
            f"{test_api_uri}/trackers/{tracker.uuid}",
            {
                **original_body,
                "affects": [
                    affect2.uuid
                ],  # remove the first affect and add the second one
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        assert affect1.uuid not in response.data["affects"]
        assert affect2.uuid in response.data["affects"]

    def test_tracker_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of Tracker records via a REST API DELETE request.
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker_url = f"{test_api_uri}/trackers/{tracker.uuid}"
        response = auth_client.get(tracker_url)
        assert response.status_code == 200

        response = auth_client.delete(tracker_url)
        # this HTTP method is not allowed until we integrate
        # with the authoritative sources of the tracker data
        assert response.status_code == 405

    def test_packageversions_filter(self, auth_client, embargo_access, test_api_uri):
        """
        Test the non-trivial parts of FlawPackageVersionFilter via REST API GET requests.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        package_versions1 = PackageFactory(package="foobar", flaw=flaw)
        package_versions2 = PackageFactory(package="bazfoo", flaw=flaw)
        version1a = PackageVerFactory(package=package_versions1, version="1.2.3.4")
        version2a = PackageVerFactory(package=package_versions1, version="2.3.4.5")
        version1b = PackageVerFactory(package=package_versions2, version="1.2.3.4")
        version2b = PackageVerFactory(package=package_versions2, version="2.3.4.5")
        package_versions3 = PackageFactory(package="fobr", flaw=flaw)
        version3 = PackageVerFactory(package=package_versions3, version="3.4.5.6")

        # Only the package matching the filtered version is returned
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions?versions__version={version3.version}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["package"] == package_versions3.package
        assert len(response.data["results"][0]["versions"]) == 1
        assert response.data["results"][0]["versions"][0]["version"] == version3.version

        # The whole Package object including all linked versions is returned for the matching
        # filter, even if the filter is for a single version.
        # Filters are chained with logical AND (only 1 package is returned even though that version
        # matches 2 packages).
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions?package={package_versions1.package}&versions__version={version1a.version}"
        )
        assert response.status_code == status.HTTP_200_OK
        expected_vers = {version1a.version, version2a.version}
        response_vers = set()
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["package"] == package_versions1.package
        assert len(response.data["results"][0]["versions"]) == 2
        response_vers.add(response.data["results"][0]["versions"][0]["version"])
        response_vers.add(response.data["results"][0]["versions"][1]["version"])
        assert response_vers == expected_vers
        assert (
            response.data["results"][0]["versions"]
            == [
                {
                    "version": version1a.version,
                },
                {
                    "version": version2a.version,
                },
            ]
        ) or (
            response.data["results"][0]["versions"]
            == [
                {
                    "version": version2a.version,
                },
                {
                    "version": version1a.version,
                },
            ]
        )

        # All packages that have the specified version are returned, including their other versions.
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions?versions__version={version2b.version}"
        )
        assert response.status_code == status.HTTP_200_OK
        expected_pkgs = set([package_versions1.package, package_versions2.package])
        response_pkgs = set()
        expected_vers = set([version1b.version, version2b.version])
        response_vers1 = set()
        response_vers2 = set()

        assert len(response.data["results"]) == 2
        response_pkgs.add(response.data["results"][0]["package"])
        response_pkgs.add(response.data["results"][1]["package"])
        assert expected_pkgs == response_pkgs

        assert len(response.data["results"][0]["versions"]) == 2
        response_vers1.add(response.data["results"][0]["versions"][0]["version"])
        response_vers1.add(response.data["results"][0]["versions"][1]["version"])
        assert response_vers1 == expected_vers

        assert len(response.data["results"][1]["versions"]) == 2
        response_vers2.add(response.data["results"][1]["versions"][0]["version"])
        response_vers2.add(response.data["results"][1]["versions"][1]["version"])
        assert response_vers2 == expected_vers

    def test_packageversions_create(self, auth_client, embargo_access, test_api_uri):
        """
        Test the creation of Package and PackageVer records via a REST API PUT request.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        packageversions_data = {
            "package": "foobar",
            "versions": [
                {
                    "version": "1",
                },
                {
                    "version": "2.2",
                },
                {
                    "version": "3.3-3.3",
                },
            ],
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/package_versions
        response = auth_client.post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions",
            packageversions_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        packageversion_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/package_versions
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/package_versions/{uuid}
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions/{packageversion_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == packageversion_uuid

        assert response.data["package"] == "foobar"
        expected_vers = {"1", "2.2", "3.3-3.3"}
        response_vers = {v["version"] for v in response.data["versions"]}
        assert expected_vers == response_vers

    @pytest.mark.parametrize(
        "correct_timestamp",
        [
            True,
            False,
        ],
    )
    def test_packageversions_update(
        self, auth_client, embargo_access, test_api_uri, correct_timestamp
    ):
        """
        Test the update of Package and PackageVer records via a REST API PUT request.
        """
        GROUND_STATE = {
            "foobar": {"1.2.3.4", "2.3.4.5"},
            "bazfoo": {"1.2.3.4", "2.3.4.5"},
            "fobr": {"3.4.5.6"},
        }

        def extract_packages_versions(response):
            return {
                response.data["results"][i]["package"]: {
                    x["version"] for x in response.data["results"][i]["versions"]
                }
                for i in range(len(response.data["results"]))
            }

        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        package_versions1 = PackageFactory(package="foobar", flaw=flaw)
        package_versions2 = PackageFactory(package="bazfoo", flaw=flaw)
        PackageVerFactory(package=package_versions1, version="1.2.3.4")
        PackageVerFactory(package=package_versions1, version="2.3.4.5")
        PackageVerFactory(package=package_versions2, version="1.2.3.4")
        PackageVerFactory(package=package_versions2, version="2.3.4.5")
        package_versions3 = PackageFactory(package="fobr", flaw=flaw)
        PackageVerFactory(package=package_versions3, version="3.4.5.6")

        # Ensure that when TrackingMixin.save() runs, db_self is not None.
        flaw.save()
        package_versions1.save()
        package_versions2.save()
        package_versions3.save()

        # Test that the ground state before modifications is correctly represented via API
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 3
        returned_data = extract_packages_versions(response)
        assert returned_data == GROUND_STATE

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions/{package_versions3.uuid}"

        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK

        # Reusing the response for the next query so as to get the correct updated_dt
        updated_data = {
            k: v for k, v in response.json().items() if k in ["embargoed", "updated_dt"]
        }
        if not correct_timestamp:
            updated_data["updated_dt"] = "2023-09-14T11:28:33Z"
        updated_data["package"] = "foobar"  # Note the change of the package name.
        updated_data["versions"] = [
            {
                "version": "4.5.6.7",
            },
        ]

        # Tests "PUT" on flaws/{uuid}/package_versions
        response = auth_client.put(
            url,
            {**updated_data},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        if correct_timestamp:
            assert response.status_code == status.HTTP_200_OK
            packageversion_uuid = response.data["uuid"]

            # Test that the "fobr" package was deleted and the version list
            # of the "foobar" package was replaced according to the request.
            response = auth_client.get(
                f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
            )
            assert response.status_code == status.HTTP_200_OK
            assert len(response.data["results"]) == 2
            returned_data = extract_packages_versions(response)
            assert returned_data == {
                "foobar": {"4.5.6.7"},
                "bazfoo": {"1.2.3.4", "2.3.4.5"},
            }

            # Test that the UUID of the Package changed to the UUID of the foobar package.
            assert packageversion_uuid == str(package_versions1.uuid)
        else:  # if not correct_timestamp:
            assert response.status_code == status.HTTP_400_BAD_REQUEST

            # Test that no changes were made
            response = auth_client.get(
                f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
            )
            assert response.status_code == status.HTTP_200_OK
            assert len(response.data["results"]) == 3
            returned_data = extract_packages_versions(response)
            assert returned_data == GROUND_STATE

    def test_packageversions_delete(self, auth_client, embargo_access, test_api_uri):
        """
        Test the deletion of Package and PackageVer records via a REST API PUT request.
        """
        flaw = FlawFactory()

        # Necessary for Flaw validation
        AffectFactory(flaw=flaw)

        package_versions1 = PackageFactory(package="foobar", flaw=flaw)
        PackageVerFactory(package=package_versions1, version="1.2.3.4")
        PackageVerFactory(package=package_versions1, version="2.3.4.5")

        # Tests "GET" on flaws/{uuid}/package_versions
        response = auth_client.get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        assert Package.objects.all().count() == 1
        assert PackageVer.objects.all().count() == 2

        # Tests "DELETE" on flaws/{uuid}/package_versions/{uuid}
        response = auth_client.delete(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions/{package_versions1.uuid}",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert Package.objects.all().count() == 0
        assert PackageVer.objects.all().count() == 0


class TestEndpointsACLs:
    """
    ACL specific tests
    """

    def hash_acl(self, acl):
        """
        shortcut to get ACL from the group(s)
        """
        return [uuid.UUID(ac) for ac in generate_acls(ensure_list(acl))]

    @pytest.mark.parametrize(
        "embargoed,acl_read,acl_write",
        [
            (False, settings.PUBLIC_READ_GROUPS, settings.PUBLIC_WRITE_GROUP),
            (True, settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP),
        ],
    )
    def test_flaw_create(
        self, auth_client, embargo_access, test_api_uri, embargoed, acl_read, acl_write
    ):
        """
        test proper embargo status and ACLs when creating a flaw by sending a POST request
        """
        flaw_data = {
            "title": "Foo",
            "description": "test",
            "impact": "LOW",
            "component": "curl",
            "source": "DEBIAN",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": None if embargoed else "2000-1-1T22:03:26.065Z",
            "mitigation": "mitigation",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": embargoed,
        }
        response = auth_client.post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        flaw = Flaw.objects.first()
        assert flaw.acl_read == self.hash_acl(acl_read)
        assert flaw.acl_write == self.hash_acl(acl_write)

        response = auth_client.get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["embargoed"] == embargoed
        assert response.json()["mitigation"] == "mitigation"

    @pytest.mark.parametrize(
        "embargoed,acl_read,acl_write",
        [
            (False, settings.PUBLIC_READ_GROUPS, settings.PUBLIC_WRITE_GROUP),
            (True, settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP),
        ],
    )
    def test_flaw_update(
        self, auth_client, embargo_access, test_api_uri, embargoed, acl_read, acl_write
    ):
        """
        test proper embargo status and ACLs when updating a flaw by sending a PUT request
        while the embargo status and ACLs itself are not being changed
        """
        flaw = FlawFactory(embargoed=embargoed)
        AffectFactory(flaw=flaw)

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert original_body["embargoed"] == embargoed

        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "description": flaw.description,
                "embargoed": embargoed,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["title"] != body["title"]
        assert "appended test title" in body["title"]
        assert original_body["embargoed"] == body["embargoed"]

        flaw = Flaw.objects.first()
        assert flaw.acl_read == self.hash_acl(acl_read)
        assert flaw.acl_write == self.hash_acl(acl_write)

    @freeze_time(datetime(2021, 11, 23, tzinfo=timezone.get_current_timezone()))
    def test_flaw_unembargo(self, auth_client, test_api_uri):
        """
        test proper embargo status and ACLs when unembargoing a flaw by sending a PUT request
        """
        future_dt = datetime(2021, 11, 27, tzinfo=timezone.get_current_timezone())
        flaw = FlawFactory(
            embargoed=True,
            unembargo_dt=future_dt,
        )
        AffectFactory(flaw=flaw)

        # the unembargo must happen after the unembargo moment passed
        with freeze_time(future_dt):
            response = auth_client.put(
                f"{test_api_uri}/flaws/{flaw.uuid}",
                {
                    "title": flaw.title.replace("EMBARGOED", "").strip(),
                    "description": flaw.description,
                    "embargoed": False,
                    "updated_dt": flaw.updated_dt,
                },
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
            )

        assert response.status_code == 200
        body = response.json()
        assert body["embargoed"] is False
        assert Flaw.objects.first().embargoed is False

    def test_flaw_create_not_member(self, auth_client, test_api_uri):
        """
        test that creating a Flaw is rejected when the ACL contains a group the user is not a member of
        """
        # restrict the user to the public read and write access
        User.objects.get(username="testuser").groups.exclude(
            name__in=["data-prodsec", "data-prodsec-write"]
        ).delete()

        flaw_data = {
            "title": "EMBARGOED Foo",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": True,
            "bz_api_key": "SECRET",
        }
        response = auth_client.post(f"{test_api_uri}/flaws", flaw_data, format="json")
        assert response.status_code == 400
        assert (
            "Cannot provide access for the LDAP group without being a member: data-topsecret"
            in str(response.content)
        )

    def test_flaw_update_not_member(self, auth_client, test_api_uri):
        """
        test that updating a Flaw is rejected when the ACL contains a group the user is not a member of
        """
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # restrict the user to the public read-only access
        User.objects.get(username="testuser").groups.exclude(
            name="data-prodsec"
        ).delete()

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "description": flaw.description,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
                "bz_api_key": "SECRET",
            },
            format="json",
        )
        assert response.status_code == 400
        assert (
            "Cannot provide access for the LDAP group without being a member: data-prodsec-write"
            in str(response.content)
        )


class TestEndpointsAtomicity:
    """
    API atomicity specific tests
    """

    def test_atomic_api(self, auth_client, monkeypatch, test_api_uri):
        """
        test that the API requests are atomic

        this test attempts to delete an affect via a REST API DELETE request
        as it consits of first deleting the affect and then saving a related
        flaw where the flaw save is mocked to fail and we test that the
        affect delete is not commited to the DB - rolled back on failure
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        assert Affect.objects.count() == 2

        with monkeypatch.context() as m:

            def failure_factory(*args, **kwargs):
                # rest_framework.exceptions.ValidationError
                # is handle by the APIView and translated to Bad Request
                # so we do not end up with an uncaught exception
                raise ValidationError({})

            # make the Flaw.save to fail randomly
            m.setattr(Flaw, "save", failure_factory)

            response = auth_client.delete(
                f"{test_api_uri}/affects/{affect.uuid}", HTTP_BUGZILLA_API_KEY="SECRET"
            )
            assert response.status_code == 400

        # check that no affect was deleted
        assert Affect.objects.count() == 2

    def test_nonatomic_api(self, auth_client, monkeypatch, test_api_uri):
        """
        test that the API requests are not atomic when the settings option is disabled
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        assert Affect.objects.count() == 2

        with monkeypatch.context() as m:

            def failure_factory(*args, **kwargs):
                # rest_framework.exceptions.ValidationError
                # is handle by the APIView and translated to Bad Request
                # so we do not end up with an uncaught exception
                raise ValidationError({})

            # make the Flaw.save to fail randomly
            m.setattr(Flaw, "save", failure_factory)

            # turn of the atomicity option
            db_settings = settings.DATABASES
            db_settings["default"]["ATOMIC_REQUESTS"] = False
            m.setattr(settings, "DATABASES", db_settings)

            response = auth_client.delete(
                f"{test_api_uri}/affects/{affect.uuid}", HTTP_BUGZILLA_API_KEY="SECRET"
            )
            assert response.status_code == 400

        # check that the affect was deleted
        # even though the HTTP request failed
        assert Affect.objects.count() == 1


class TestEndpointsBZAPIKey:
    """
    Bugzilla API key specific tests
    """

    def test_flaw_create_no_bz_api_key(self, auth_client, test_api_uri):
        """
        test that creating a Flaw is rejected when no Bugzilla API key is provided
        """
        flaw_data = {
            "title": "Foo",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        response = auth_client.post(f"{test_api_uri}/flaws", flaw_data, format="json")
        assert response.status_code == 400
        assert '"Bugzilla-Api-Key":"This HTTP header is required."' in str(
            response.content
        )

    def test_flaw_update_no_bz_api_key(self, auth_client, test_api_uri):
        """
        test that updating a Flaw is rejected when no Bugzilla API key is provided
        """
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "description": flaw.description,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
        )
        assert response.status_code == 400
        assert '"Bugzilla-Api-Key":"This HTTP header is required."' in str(
            response.content
        )


class TestCustomExceptionHandling:
    @pytest.mark.urls("osidb.tests.urls")
    def test_custom_exception_serialization(self):
        url = reverse("test-view")
        response = APIClient().get(url)
        assert response.status_code == 409
        assert response.json()["detail"] == "This was a big failure"
