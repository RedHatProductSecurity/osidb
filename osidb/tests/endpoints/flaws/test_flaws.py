from datetime import timedelta
from typing import Set, Union

import pytest
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import datetime, make_aware
from freezegun import freeze_time
from rest_framework import status

from osidb.core import set_user_acls
from osidb.filters import FlawFilter
from osidb.models import Affect, Flaw, FlawComment, FlawReference, FlawSource, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
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


class TestEndpointsFlaws:
    """
    tests specific to /flaws endpoint
    """

    def test_get_flaw_with_comments(self, auth_client, test_api_uri):
        """retrieve specific flaw with comments from endpoint"""

        flaw1 = FlawFactory()

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200

        flaw = Flaw.objects.get(cve_id=flaw1.cve_id)
        FlawCommentFactory(flaw=flaw)
        FlawCommentFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200

        body = response.json()
        assert len(body["comments"]) == 2

    def test_get_flaw_with_acknowledgments(self, auth_client, test_api_uri):
        """retrieve specific flaw with flawacknowledgments from endpoint"""

        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["acknowledgments"]) == 0

        FlawAcknowledgmentFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["acknowledgments"]) == 1

    def test_get_flaw_with_references(self, auth_client, test_api_uri):
        """retrieve specific flaw with flawreferences from endpoint"""
        flaw = FlawFactory()

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["references"]) == 0

        FlawReferenceFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["references"]) == 1

    @pytest.mark.enable_signals
    def test_get_flaw_with_cvss(self, auth_client, test_api_uri):
        """retrieve specific flaw with flawcvss from endpoint"""
        flaw = FlawFactory()

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 0

        FlawCVSSFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 1

    def test_get_flaw(self, auth_client, test_api_uri):
        """retrieve specific flaw from endpoint"""

        flaw1 = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            requires_cve_description=Flaw.FlawRequiresCVEDescription.APPROVED,
            nist_cvss_validation=Flaw.FlawNistCvssValidation.NOVALUE,
        )
        flaw1.save(raise_validation_error=False)
        FlawReferenceFactory(
            flaw=flaw1,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        AffectFactory(flaw=flaw1)
        assert flaw1.save() is None
        assert (
            flaw1.requires_cve_description == Flaw.FlawRequiresCVEDescription.APPROVED
        )
        FlawCommentFactory(flaw=flaw1)
        response = auth_client().get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["major_incident_state"] == Flaw.FlawMajorIncident.APPROVED
        assert body["nist_cvss_validation"] == Flaw.FlawNistCvssValidation.NOVALUE
        assert len(body["comments"]) == 1

    def test_list_flaws(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""

        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory()

        response = auth_client().get(f"{test_api_uri}/flaws")
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
        response = auth_client().get(f"{test_api_uri}/flaws")
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
        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_str}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    @pytest.mark.enable_signals
    def test_list_flaws_changed_before(
        self,
        auth_client,
        test_api_uri,
        datetime_with_tz,
    ):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_uri}/flaws")
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
        response = auth_client().get(f"{test_api_uri}/flaws?changed_before={past_str}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    @pytest.mark.enable_signals
    def test_list_flaws_changed_before_and_after(
        self,
        auth_client,
        test_api_uri,
        datetime_with_tz,
    ):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(updated_dt=datetime_with_tz)

        past_str = f"{datetime_with_tz - timedelta(days=1)}"
        future_str = f"{datetime_with_tz + timedelta(days=1)}"
        past_str = past_str.replace("+00:00", "Z")
        future_str = future_str.replace("+00:00", "Z")
        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_after={past_str}&changed_before={future_str}"
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 1
        )  # One Flaw that was changed after a past date AND before a future date

    def test_list_flaws_filters(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory()

        for field_filter in FlawFilter.get_fields():
            response = auth_client().get(f"{test_api_uri}/flaws?{field_filter}=0")
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

    @pytest.mark.parametrize(
        "is_empty,cve_id",
        [
            (True, None),
            (True, ""),
            (False, "CVE-2024-271828"),
        ],
    )
    def test_list_flaws_empty_cve(self, is_empty, cve_id, auth_client, test_api_uri):
        """Test that filtering by null or empty CVEs works."""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(cve_id=cve_id)

        # Filter is true: matches null and empty strings
        response = auth_client().get(f"{test_api_uri}/flaws?cve_id__isempty=1")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == (1 if is_empty else 0)

        # Filter is false: matches non-null and non-empty strings
        response = auth_client().get(f"{test_api_uri}/flaws?cve_id__isempty=0")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == (0 if is_empty else 1)

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_after_from_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=(affect,),
            embargoed=affect.flaw.embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        future_dt = datetime(2021, 11, 27)

        # first check that we cannot get anything by querying any flaws changed after future_dt
        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_dt}")
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
        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_after_from_affect(self, auth_client, test_api_uri):
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)
        future_dt = datetime(2021, 11, 27)

        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        with freeze_time(future_dt):
            affect.ps_component = "foo"
            affect.save()
        assert affect.updated_dt == future_dt.astimezone(
            timezone.get_current_timezone()
        )

        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_after_from_multi_affect(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        affect1 = AffectFactory(flaw=flaw)
        affect2 = AffectFactory(flaw=flaw)
        future_dt = datetime(2021, 11, 27)

        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_dt}")
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

        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_before_from_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory(
            unembargo_dt=make_aware(datetime(2001, 11, 23)),
            embargoed=False,
            reported_dt=make_aware(datetime(2001, 11, 23)),
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
        )
        tracker = TrackerFactory(
            affects=(affect,),
            embargoed=affect.flaw.embargoed,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
            type=Tracker.TrackerType.BUGZILLA,
        )
        past_dt = datetime(2019, 11, 27, tzinfo=timezone.utc)

        # first check that we cannot get anything by querying any flaws changed after future_dt
        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_before={past_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
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
        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_before={past_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_before_from_affect(self, auth_client, test_api_uri):
        flaw = FlawFactory(
            unembargo_dt=make_aware(datetime(2001, 11, 23)),
            embargoed=False,
            reported_dt=make_aware(datetime(2001, 11, 23)),
        )
        affect = AffectFactory(
            flaw=flaw, updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc)
        )
        past_dt = datetime(2019, 11, 27, tzinfo=timezone.utc)

        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_before={past_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        with freeze_time(past_dt):
            affect.ps_component = "foo"
            affect.save()
        assert affect.updated_dt == past_dt.astimezone(timezone.get_current_timezone())

        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_before={past_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(affect.flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_before_from_multi_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory(
            unembargo_dt=make_aware(datetime(2001, 11, 23)),
            embargoed=False,
            reported_dt=make_aware(datetime(2001, 11, 23)),
        )
        affect1 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
        )
        affect2 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
        )
        tracker1 = TrackerFactory(
            affects=(affect1,),
            embargoed=flaw.embargoed,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker2 = TrackerFactory(
            affects=(affect2,),
            embargoed=flaw.embargoed,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
            type=Tracker.TrackerType.BUGZILLA,
        )
        past_dt = datetime(2019, 11, 27, tzinfo=timezone.utc)

        # first check that we cannot get anything by querying any flaws changed after future_dt
        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_before={past_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
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
        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_before={past_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(tracker.affects.first().flaw.uuid)

    def test_list_flaws_filter_by_components(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(components=["test-component"])
        FlawFactory(components=["test-component", "other-component"])
        FlawFactory(
            components=["test-component", "other-component", "different-component"]
        )

        response = auth_client().get(f"{test_api_uri}/flaws?components=test-component")
        assert response.status_code == 200
        assert response.json()["count"] == 3

        response = auth_client().get(
            f"{test_api_uri}/flaws?components=test-component,other-component"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 2

        response = auth_client().get(f"{test_api_uri}/flaws?components=other-component")
        assert response.status_code == 200
        assert response.json()["count"] == 2

    def test_list_flaws_filter_by_bz_id(self, auth_client, test_api_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        meta_attr = {"bz_id": 123456}

        FlawFactory(meta_attr=meta_attr)

        response = auth_client().get(f"{test_api_uri}/flaws?bz_id={meta_attr['bz_id']}")
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_list_flaws_invalid(self, auth_client, test_api_uri, datetime_with_tz):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(created_dt=datetime_with_tz)

        past_str = f"{datetime_with_tz - timedelta(days=1)}"
        future_str = f"{datetime_with_tz + timedelta(days=1)}"
        past_str = past_str.replace("+00:00", "Z")
        future_str = future_str.replace("+00:00", "Z")
        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_after={future_str}&changed_before={past_str}"
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 0
        )  # No Flaws that were changed after a future date AND before a past date

        response = auth_client().get(f"{test_api_uri}/flaws?changed_after=")
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 1
        )  # Parameter is not used for filtering if no value was provided

        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_not_at_all=&changed2=-1&changed3"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1  # Unrecognized parameters are ignored

        response = auth_client().get(
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
        response = auth_client().get(f"{test_api_uri}/flaws")
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
                resolution=Affect.AffectResolution.DELEGATED,
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

        response = auth_client().get(
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
        response = auth_client().get(f"{test_api_uri}/flaws")
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
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

        flaw_include_fields = ["uuid", "impact"]
        affect_include_fields = ["ps_module", "ps_component", "affectedness"]
        tracker_include_fields = ["type", "external_system_id", "status", "resolution"]

        include_fields_param = ",".join(
            flaw_include_fields
            + [f"affects.{field}" for field in affect_include_fields]
            + [f"affects.trackers.{field}" for field in tracker_include_fields]
        )

        response = auth_client().get(
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
        response = auth_client().get(f"{test_api_uri}/flaws")
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
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

        affect_include_fields = ["ps_module", "ps_component", "affectedness"]

        include_fields_param = ",".join(
            [f"affects.{field}" for field in affect_include_fields]
        )

        response = auth_client().get(
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
        response = auth_client().get(f"{test_api_uri}/flaws")
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
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                type=Tracker.TrackerType.BUGZILLA,
            )

        flaw_include_fields = ["uuid", "impact"]
        affect_include_fields = ["ps_module", "ps_component", "affectedness"]
        tracker_include_fields = ["type", "external_system_id", "status", "resolution"]

        include_fields_param = ",".join(
            flaw_include_fields
            + [f"affects.{field}" for field in affect_include_fields]
            + [f"affects.trackers.{field}" for field in tracker_include_fields]
        )

        flaw_exclude_fields = ["cve_id"]
        affect_exclude_fields = ["ps_module", "ps_component"]
        tracker_exclude_fields = ["type", "external_system_id"]

        exclude_fields_param = ",".join(
            flaw_exclude_fields
            + [f"affects.{field}" for field in affect_exclude_fields]
            + [f"affects.trackers.{field}" for field in tracker_exclude_fields]
        )

        response = auth_client().get(
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

    def test_list_flaws_include_fields_relation(self, auth_client, test_api_uri):
        """
        Test that passing a reverse FK relationship field to include_fields works.

        A reverse FK is when in Model B, a FK to Model A is defined, by default
        the name of such field would be <field_name>_set.

        Since the include_fields filter accepts such fields, we must ensure that
        they are properly tested.
        """
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        affect = AffectFactory()
        AffectFactory(flaw=affect.flaw)

        response = auth_client().get(f"{test_api_uri}/flaws?include_fields=affects")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        # only one key should be present, affects
        assert len(body["results"][0]) == 1
        assert list(body["results"][0].keys()) == ["affects"]

    @pytest.mark.parametrize("filter", ["include_fields", "exclude_fields"])
    @pytest.mark.parametrize("fields", ["__placeholder_field", "cve_id__id"])
    def test_list_flaws_garbage_in_filter(
        self, auth_client, test_api_uri, filter, fields
    ):
        """
        Test that passing invalid fields to the include_fields filter simply
        ignores the invalid fields and still returns a valid response.
        """
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(embargoed=False)

        response = auth_client().get(f"{test_api_uri}/flaws?{filter}={fields}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

    def test_retrieve_specific_flaw(self, auth_client, test_api_uri):
        """retrieve single flaw from endpoint"""
        flaw = FlawFactory()

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == 200

    def test_list_retrieve_multiple_flaws_by_cve_id(self, auth_client, test_api_uri):
        """retrieve multiple flaws from list endpoint using cve_id url param"""
        flaw1 = FlawFactory()
        flaw2 = FlawFactory()

        response = auth_client().get(f"{test_api_uri}/flaws?cve_id={flaw1.cve_id}")
        body = response.json()
        assert body["count"] == 1
        assert "affects" in body["results"][0]

        response = auth_client().get(
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

        response = auth_client().get(f"{test_api_uri}/flaws?{query_params}")
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

        response = auth_client().get(f"{test_api_uri}/flaws?{query_params}")
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

        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw.cve_id}?{query_params}"
        )
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

        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw.cve_id}?{query_params}"
        )
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

    def test_flaw_including_package_versions(self, auth_client, test_api_uri):
        """retrieve flaw with package_versions"""
        package_versions = PackageFactory()
        PackageVerFactory(package=package_versions)

        response = auth_client().get(
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

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
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

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
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
        response = auth_client().post(f"{root_url}/auth/token", post_data)
        assert response.status_code == 200
        body = response.json()
        assert "access" in body
        assert "refresh" in body
        token = body["access"]

        # reset ACLs
        set_user_acls(settings.ALL_GROUPS)
        flaw1 = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            requires_cve_description=Flaw.FlawRequiresCVEDescription.APPROVED,
        )
        flaw1.save(raise_validation_error=False)
        FlawReferenceFactory(
            flaw=flaw1,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        AffectFactory(flaw=flaw1)

        assert flaw1.save() is None
        assert (
            flaw1.requires_cve_description == Flaw.FlawRequiresCVEDescription.APPROVED
        )
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
            "impact": "CRITICAL",
            "components": ["curl"],
            "source": "INTERNET",
            "comment_zero": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "embargoed": False,
        }
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] == "CVE-2021-0666"
        assert "curl" in response.json()["components"]

    def test_flaw_draft_create(self, auth_client, test_api_uri):
        """
        Test that creating a Flaw Draft by sending a POST request works.
        """
        # a flaw draft essentially has no CVE
        flaw_data = {
            "cwe_id": "CWE-1",
            "title": "Foo",
            "impact": "CRITICAL",
            "components": ["curl"],
            "source": "INTERNET",
            "comment_zero": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "embargoed": False,
        }
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] is None

        # let's try creating another one without cve_id to make sure the
        # unique=True constraint doesn't jump (I don't trust django)
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        new_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/flaws/{new_uuid}")
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
        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "impact": flaw.impact,
                "source": flaw.source,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["title"] != body["title"]
        assert "appended test title" in body["title"]
        assert original_body["comment_zero"] == body["comment_zero"]

    @pytest.mark.parametrize("embargoed", [True, False])
    @pytest.mark.parametrize(
        "old_cve_id,new_cve_id",
        [
            (None, "CVE-2020-12345"),
            ("CVE-2020-12345", None),
            ("CVE-2020-12345", "CVE-2020-54321"),
            ("CVE-2020-12345", ""),
        ],
    )
    def test_flaw_update_cve(
        self,
        auth_client,
        test_api_uri,
        embargoed,
        old_cve_id,
        new_cve_id,
    ):
        """
        Test that updating a Flaw CVE ID by sending a PUT request works.
        """
        flaw = FlawFactory(embargoed=embargoed, cve_id=old_cve_id)
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["embargoed"] == embargoed
        assert body["cve_id"] == old_cve_id

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "cve_id": new_cve_id,
                "title": flaw.title,
                "comment_zero": flaw.comment_zero,
                "embargoed": embargoed,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
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

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": flaw.title,
                "comment_zero": flaw.comment_zero,
                "embargoed": embargoed,
                "unembargo_dt": new_date,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
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

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "impact": flaw.impact,
                "source": flaw.source,
                "embargoed": flaw.embargoed,
                "updated_dt": flaw.updated_dt - timedelta(days=1),  # outdated timestamp
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "Save operation based on an outdated model instance" in str(
            response.content
        )
        assert Flaw.objects.get(uuid=flaw.uuid).title == flaw.title

    def test_flaw_comment_create(self, auth_client, test_api_uri):
        """
        Test that adding a flaw comment by sending a POST request works.
        """

        def new_flaw():
            flaw = FlawFactory(embargoed=False)
            AffectFactory(flaw=flaw)
            response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200
            assert not FlawComment._base_manager.filter(flaw=flaw).exists()
            return flaw

        def get_response(flaw, new_comment):
            return auth_client().post(
                f"{test_api_uri}/flaws/{flaw.uuid}/comments",
                {
                    "order": 1,
                    "embargoed": False,
                    "text": new_comment,
                },
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
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
        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client().delete(f"{test_api_uri}/flaws/{flaw.uuid}")
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
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
            )
            for _ in range(5)
        ]
        other_affects = [
            AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
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

        response = auth_client().get(
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
