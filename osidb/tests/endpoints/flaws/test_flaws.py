from datetime import timedelta, timezone
from typing import Set, Union

import pghistory
import pytest
from django.conf import settings
from django.utils.timezone import datetime, make_aware
from freezegun import freeze_time
from rest_framework import status

from apps.workflows.workflow import WorkflowModel
from osidb.core import set_user_acls
from osidb.filters import FlawFilter
from osidb.models import (
    Affect,
    Flaw,
    FlawCollaborator,
    FlawComment,
    FlawCVSS,
    FlawLabel,
    FlawReference,
    FlawSource,
    Impact,
    Tracker,
)
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


def is_meta_attr_correct(meta_attr: Union[dict, None], expected_keys: Set[str]) -> bool:
    """Helper function for meta attr correctness check"""
    if meta_attr is None and not expected_keys:
        return True
    elif meta_attr is not None and set(meta_attr.keys()) == expected_keys:
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

        FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.NIST)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 1

    def test_get_flaw(self, auth_client, test_api_uri):
        """retrieve specific flaw from endpoint"""

        flaw1 = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
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
        assert (
            body["major_incident_state"]
            == Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        )
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

    def test_list_flaws_filters(self, auth_client, test_api_v2_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_v2_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory()

        for field_filter in FlawFilter.get_fields():
            response = auth_client().get(f"{test_api_v2_uri}/flaws?{field_filter}=0")
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
        "field_name",
        [
            ("cve_id"),
            ("cve_description"),
            ("cwe_id"),
            ("statement"),
            ("mitigation"),
            ("owner"),
        ],
    )
    @pytest.mark.parametrize(
        "is_empty,field_content",
        [
            (True, ""),
            (False, "CVE-2024-271828"),
        ],
    )
    def test_list_flaws_empty_text(
        self, field_name, is_empty, field_content, auth_client, test_api_uri
    ):
        """
        Test that filtering by null or empty text works for the text fields that have this filter enabled.
        """
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory.build(**{field_name: field_content})
        # Skip validation error for malformed CVE/CWD, we only care that it has
        # some content not that it is valid
        flaw.save(raise_validation_error=False)

        # Filter is true: matches null and empty strings
        response = auth_client().get(f"{test_api_uri}/flaws?{field_name}__isempty=1")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == (1 if is_empty else 0)

        # Filter is false: matches non-null and non-empty strings
        response = auth_client().get(f"{test_api_uri}/flaws?{field_name}__isempty=0")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == (0 if is_empty else 1)

    @pytest.mark.parametrize(
        "issuer,version,filter_name",
        [
            (FlawCVSS.CVSSIssuer.REDHAT, FlawCVSS.CVSSVersion.VERSION2, "cvss2_rh"),
            (FlawCVSS.CVSSIssuer.REDHAT, FlawCVSS.CVSSVersion.VERSION3, "cvss3_rh"),
            (FlawCVSS.CVSSIssuer.REDHAT, FlawCVSS.CVSSVersion.VERSION4, "cvss4_rh"),
            (FlawCVSS.CVSSIssuer.NIST, FlawCVSS.CVSSVersion.VERSION2, "cvss2_nist"),
            (FlawCVSS.CVSSIssuer.NIST, FlawCVSS.CVSSVersion.VERSION3, "cvss3_nist"),
            (FlawCVSS.CVSSIssuer.NIST, FlawCVSS.CVSSVersion.VERSION4, "cvss4_nist"),
        ],
    )
    def test_list_flaws_empty_cvss(
        self, issuer, version, filter_name, auth_client, test_api_uri
    ):
        """Test that filtering by non-existing CVSS scores works."""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        flaw = FlawFactory(impact=Impact.LOW)

        response = auth_client().get(f"{test_api_uri}/flaws?{filter_name}__isempty=1")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        # RH CVSSv3 needs to match with flaw impact
        if filter_name == "cvss3_rh":
            FlawCVSSFactory(
                flaw=flaw,
                issuer=issuer,
                version=version,
                vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            )
        else:
            FlawCVSSFactory(
                flaw=flaw,
                issuer=issuer,
                version=version,
            )
        response = auth_client().get(f"{test_api_uri}/flaws?{filter_name}__isempty=1")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_after_from_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=(affect,),
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
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
        assert tracker.updated_dt == future_dt.astimezone(timezone.utc)

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
        assert affect.updated_dt == future_dt.astimezone(timezone.utc)

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
            assert affect.updated_dt == future_dt.astimezone(timezone.utc)

        response = auth_client().get(f"{test_api_uri}/flaws?changed_after={future_dt}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(affect1.flaw.uuid)

    @freeze_time(datetime(2021, 11, 23))
    @pytest.mark.enable_signals
    def test_changed_before_from_tracker(self, auth_client, test_api_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(
            unembargo_dt=make_aware(datetime(2001, 11, 23)),
            embargoed=False,
            reported_dt=make_aware(datetime(2001, 11, 23)),
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
        )
        tracker = TrackerFactory(
            affects=(affect,),
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
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
        assert tracker.updated_dt == past_dt.astimezone(timezone.utc)

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
        assert affect.updated_dt == past_dt.astimezone(timezone.utc)

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
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(
            unembargo_dt=make_aware(datetime(2001, 11, 23)),
            embargoed=False,
            reported_dt=make_aware(datetime(2001, 11, 23)),
        )
        affect1 = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream1.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
        )
        affect2 = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream2.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
        )
        tracker1 = TrackerFactory(
            affects=(affect1,),
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            updated_dt=datetime(2021, 11, 23, tzinfo=timezone.utc),
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker2 = TrackerFactory(
            affects=(affect2,),
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream2.name,
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
            assert tracker.updated_dt == past_dt.astimezone(timezone.utc)

        # we should get a result now
        response = auth_client().get(
            f"{test_api_uri}/flaws?changed_before={past_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(tracker1.affects.first().flaw.uuid)

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

    def test_list_flaws_filter_by_labels(self, auth_client, test_api_uri):
        """test multi-label filtering"""
        label_a = FlawLabel.objects.create(
            name="label_a", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )
        label_b = FlawLabel.objects.create(
            name="label_b", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )
        label_c = FlawLabel.objects.create(
            name="label_c", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        flaw1.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw1.save()
        FlawCollaborator.objects.create(
            flaw=flaw1,
            label=label_a.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        flaw2.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw2.save()
        FlawCollaborator.objects.create(
            flaw=flaw2,
            label=label_a.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )
        FlawCollaborator.objects.create(
            flaw=flaw2,
            label=label_b.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        flaw3 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw3)
        flaw3.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw3.save()
        FlawCollaborator.objects.create(
            flaw=flaw3,
            label=label_a.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )
        FlawCollaborator.objects.create(
            flaw=flaw3,
            label=label_b.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )
        FlawCollaborator.objects.create(
            flaw=flaw3,
            label=label_c.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        response = auth_client().get(f"{test_api_uri}/flaws?flaw_labels=label_a")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 3
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw1.cve_id,
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f"{test_api_uri}/flaws?flaw_labels=label_a,label_b"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f"{test_api_uri}/flaws?flaw_labels=label_a,label_b,label_c"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert {flaw["cve_id"] for flaw in body["results"]} == {flaw3.cve_id}

        response = auth_client().get(
            f"{test_api_uri}/flaws?flaw_labels=label_b,label_c"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert {flaw["cve_id"] for flaw in body["results"]} == {flaw3.cve_id}

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
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
            )

        flaw_exclude_fields = ["resolution", "state", "uuid", "impact"]
        affect_exclude_fields = [
            "ps_update_stream",
            "ps_component",
            "type",
            "affectedness",
        ]
        tracker_exclude_fields = ["type", "external_system_id", "status", "resolution"]

        exclude_fields_param = ",".join(
            flaw_exclude_fields
            + [f"affects.{field}" for field in affect_exclude_fields]
            + [f"affects.tracker.{field}" for field in tracker_exclude_fields]
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

            if affect.get("tracker"):
                for tracker_field in tracker_exclude_fields:
                    assert tracker_field not in affect["tracker"]

    def test_list_flaws_include_fields(self, auth_client, test_api_v2_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_v2_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
            )

        flaw_include_fields = ["uuid", "impact"]
        affect_include_fields = ["ps_update_stream", "ps_component", "affectedness"]
        tracker_include_fields = ["type", "external_system_id", "status", "resolution"]

        include_fields_param = ",".join(
            flaw_include_fields
            + [f"affects.{field}" for field in affect_include_fields]
            + [f"affects.tracker.{field}" for field in tracker_include_fields]
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?include_fields={include_fields_param}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        # length of the include fields plus 1 for "affects" which will be present as well
        assert len(body["results"][0]) == len(flaw_include_fields) + 1

        for field in flaw_include_fields:
            assert field in body["results"][0]

        for affect in body["results"][0]["affects"]:
            # length of the include fields plus 1 for "tracker" which will be present as well
            assert len(affect) == len(affect_include_fields) + 1

            for field in affect_include_fields:
                assert field in affect

            if affect.get("tracker"):
                assert len(affect["tracker"]) == len(tracker_include_fields)
                for tracker_field in tracker_include_fields:
                    assert tracker_field in affect["tracker"]

    def test_list_flaws_nested_include_fields_only(self, auth_client, test_api_v2_uri):
        """
        retrieve list of flaws from endpoint with included
        fields only in nested serializers
        """
        response = auth_client().get(f"{test_api_v2_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
            )

        affect_include_fields = ["ps_update_stream", "ps_component", "affectedness"]

        include_fields_param = ",".join(
            [f"affects.{field}" for field in affect_include_fields]
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?include_fields={include_fields_param}"
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

    def test_list_flaws_include_and_exclude_fields(self, auth_client, test_api_v2_uri):
        """retrieve list of flaws from endpoint"""
        response = auth_client().get(f"{test_api_v2_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
        for _ in range(5):
            affect = AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
            )

        flaw_include_fields = ["uuid", "impact"]
        affect_include_fields = ["ps_update_stream", "ps_component", "affectedness"]
        tracker_include_fields = ["type", "external_system_id", "status", "resolution"]

        include_fields_param = ",".join(
            flaw_include_fields
            + [f"affects.{field}" for field in affect_include_fields]
            + [f"affects.tracker.{field}" for field in tracker_include_fields]
        )

        flaw_exclude_fields = ["cve_id"]
        affect_exclude_fields = ["ps_update_stream", "ps_component"]
        tracker_exclude_fields = ["type", "external_system_id"]

        exclude_fields_param = ",".join(
            flaw_exclude_fields
            + [f"affects.{field}" for field in affect_exclude_fields]
            + [f"affects.tracker.{field}" for field in tracker_exclude_fields]
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?include_fields={include_fields_param}&exclude_fields={exclude_fields_param}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        # length of the include fields plus 1 for "affects" which will be present as well
        assert len(body["results"][0]) == len(flaw_include_fields) + 1

        for field in flaw_include_fields:
            assert field in body["results"][0]

        for affect in body["results"][0]["affects"]:
            # length of the include fields plus 1 for "tracker" which will be present as well
            assert len(affect) == len(affect_include_fields) + 1

            for field in affect_include_fields:
                assert field in affect

            if affect.get("tracker"):
                assert len(affect["tracker"]) == len(tracker_include_fields)
                for tracker_field in tracker_include_fields:
                    assert tracker_field in affect["tracker"]

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
                "include_meta_attr=test_key_1,affects.test_key_2,affects.tracker.test_key_3",
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
                "include_meta_attr=*,affects.*,affects.tracker.*",
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
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            flaw = FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})
            for _ in range(3):
                affect = AffectFactory(
                    flaw=flaw,
                    ps_update_stream=ps_update_stream.name,
                    meta_attr={f"test_key_{i}": "test" for i in range(5)},
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                )
                TrackerFactory(
                    affects=[affect],
                    embargoed=flaw.is_embargoed,
                    meta_attr={f"test_key_{i}": "test" for i in range(5)},
                    ps_update_stream=ps_update_stream.name,
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

                if affect.get("tracker"):
                    assert is_meta_attr_correct(
                        affect["tracker"].get("meta_attr"), expected_keys["tracker"]
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
                "include_meta_attr=test_key_1,affects.test_key_2,affects.tracker.test_key_3",
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
                "include_meta_attr=*,affects.*,affects.tracker.*",
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
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(meta_attr={f"test_key_{i}": "test" for i in range(5)})
        for _ in range(3):
            affect = AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                meta_attr={f"test_key_{i}": "test" for i in range(5)},
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.is_embargoed,
                meta_attr={f"test_key_{i}": "test" for i in range(5)},
                ps_update_stream=ps_update_stream.name,
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

            if affect.get("tracker"):
                assert is_meta_attr_correct(
                    affect["tracker"].get("meta_attr"), expected_keys["tracker"]
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

    def test_flaw_including_delegated_resolution(self, auth_client, test_api_v2_uri):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(
            name="rhel-7.0", active_to_ps_module=ps_module, ps_module=ps_module
        )
        flaw = FlawFactory()
        delegated_affect = AffectFactory(
            flaw=flaw,
            impact=Impact.MODERATE,
            ps_update_stream=ps_update_stream.name,
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

        response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert "affects" in body
        affect = body["affects"][0]
        assert "tracker" in affect
        assert affect["delegated_resolution"] == Affect.AffectFix.WONTFIX
        assert affect["tracker"]["ps_update_stream"] == "rhel-7.0"

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
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
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
        assert (
            body["major_incident_state"]
            == Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        )
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
        if new_cve_id:
            assert body["cve_id"] == new_cve_id
        else:
            assert body["cve_id"] is None

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
    def test_flaw_update_unembargo_dt(
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

    @freeze_time(datetime(2025, 1, 1, tzinfo=timezone.utc))
    def test_embargoed_deadlock(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(
            embargoed=True,
            workflow_state=WorkflowModel.WorkflowState.TRIAGE,
            reported_dt=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )

        flaw.unembargo_dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
        flaw.save(raise_validation_error=False)

        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affects_data = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": "NEW",
                "resolution": "",
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "kernel",
                "impact": "MODERATE",
                "embargoed": True,
            }
        ]
        res1 = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert res1.status_code == 200
        assert flaw.affects.count() == 1
        flaw.refresh_from_db()
        res2 = auth_client().put(
            f"{test_api_v2_uri}/flaws/{flaw.uuid}",
            {
                "title": flaw.title,
                "comment_zero": flaw.comment_zero,
                "embargoed": True,
                "unembargo_dt": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
                "updated_dt": flaw.updated_dt.isoformat(),
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        flaw.refresh_from_db()
        assert res2.status_code == 200
        assert flaw.embargoed
        assert flaw.unembargo_dt == datetime(2026, 1, 1, tzinfo=timezone.utc)

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
        # In a real-world non-test scenario, the new comment's external_system_id might or might
        # not get updated by bzimport, but in this test, there's no bzimport.
        assert first_comment == FlawComment.objects.get(external_system_id="")

        # Behaves like an ordinary non-idempotent POST endpoint. You can just simply post comments.
        response = get_response(flaw, "ANOTHER HELLO WORLD COMMENT")
        assert response.status_code == 201
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/comments",
            {
                "creator": "illegal field setting",
                "embargoed": False,
                "text": "shouldn't be able to set creator",
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        body = response.json()
        assert body["creator"] != "illegal field setting"

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

    def test_list_flaws_tracker_ids(self, auth_client, test_api_v2_uri):
        """
        retrieve list of flaws that are related to specified trackers
        through affects and ensure that only those affects related to
        specified trackers are visible
        """

        flaw = FlawFactory()
        FlawFactory()

        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affects_with_trackers_to_fetch = [
            AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream=ps_update_stream.name,
            )
            for _ in range(5)
        ]
        other_affects = [
            AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream=ps_update_stream.name,
            )
            for _ in range(5)
        ]

        trackers_to_fetch = [
            TrackerFactory(
                affects=[affects_with_trackers_to_fetch[idx]],
                embargoed=flaw.is_embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
            )
            for idx in range(5)
        ]
        for idx in range(5):
            TrackerFactory(
                affects=[other_affects[idx]],
                embargoed=flaw.is_embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
            )

        affect_ids = {str(affect.uuid) for affect in affects_with_trackers_to_fetch}
        tracker_ids = {str(tracker.external_system_id) for tracker in trackers_to_fetch}

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?tracker_ids={','.join(tracker_ids)}"
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
            if affect["tracker"]:
                fetched_tracker_ids.add(affect["tracker"]["external_system_id"])
        assert fetched_affect_ids == affect_ids
        assert fetched_tracker_ids == tracker_ids

    def test_flaw_history(self, auth_client, test_api_v2_uri):
        """ """

        with pghistory.context(source="testcase"):
            flaw = FlawFactory()
            FlawFactory()

            ps_module = PsModuleFactory(bts_name="octopus")
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affects = [
                AffectFactory(
                    flaw=flaw,
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                    ps_update_stream=ps_update_stream.name,
                )
                for _ in range(5)
            ]
            assert len(affects) == 5
            affects_other = [
                AffectFactory(
                    flaw=flaw,
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                    ps_update_stream=ps_update_stream.name,
                )
                for _ in range(5)
            ]
            assert len(affects_other) == 5

            response = auth_client().get(
                f"{test_api_v2_uri}/flaws?cve_id={flaw.cve_id}&include_history=True"
            )

            assert response.status_code == 200
            body = response.json()
            assert body["count"] == 1
            flaw_json = body["results"][0]

            assert "history" in flaw_json
            assert len(flaw_json["history"]) == 1
            flaw1_history1 = flaw_json["history"][0]

            assert flaw1_history1["pgh_label"] == "insert"
            assert flaw1_history1["pgh_context"] == {"source": "testcase"}

            assert len(flaw_json["affects"]) == 10

            flaw.title = "Modified Title"
            flaw.save()

            response = auth_client().get(
                f"{test_api_v2_uri}/flaws?cve_id={flaw.cve_id}&include_history=True"
            )

            body = response.json()
            flaw_json = body["results"][0]
            assert len(flaw_json["history"]) == 2
            assert flaw_json["history"][1]["pgh_diff"]
            assert "last_validated_dt" not in flaw_json["history"][1]["pgh_diff"]

    def test_flaw_history_no_history(self, auth_client, test_api_v2_uri):
        with pghistory.context(disable=True):
            flaw = FlawFactory()
            flaw.save()

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws?cve_id={flaw.cve_id}&include_history=True"
        )

        body = response.json()
        flaw_json = body["results"][0]
        assert "pgh_diff" not in flaw_json["history"]

    @pytest.mark.parametrize(
        "workflow_status",
        (
            WorkflowModel.WorkflowState.NEW,
            WorkflowModel.WorkflowState.REJECTED,
            WorkflowModel.WorkflowState.DONE,
        ),
    )
    @pytest.mark.parametrize(
        "embargoed, internal", [(True, False), (False, False), (False, True)]
    )
    def test_flaw_available(
        self,
        workflow_status,
        embargoed,
        internal,
        client,
        test_api_uri,
    ):
        """
        Test that API endpoint reports whether a flaw is available
        based on the following criteria:

        1) Public or work on flaw is done / flaw does not exist: 204 status
        2) Not public and work not done: 404 status
        3) CVE ID is not valid: 400 status
        """

        if internal:
            flaw = FlawFactory(embargoed=False)
            flaw.set_internal()
        else:
            # not embargoed is defaulted to public
            flaw = FlawFactory(embargoed=embargoed)

        AffectFactory(flaw=flaw)

        flaw.workflow_state = workflow_status
        assert flaw.save() is None

        # response should return a state with no data
        response = client.get(f"{test_api_uri}/available-flaws/{flaw.cve_id}")
        assert response.data is None

        if (
            flaw.is_public
            or flaw.workflow_state == WorkflowModel.WorkflowState.REJECTED
            or flaw.workflow_state == WorkflowModel.WorkflowState.DONE
        ):
            assert response.status_code == 204
        else:
            assert response.status_code == 404

        # check for non-existent flaw
        response = client.get(f"{test_api_uri}/available-flaws/CVE-2999-9999")
        assert response.status_code == 204
        assert response.data is None

        # check for invalid flaw id
        response = client.get(f"{test_api_uri}/available-flaws/not-an-id")
        assert response.status_code == 400
        assert response.data is None

    def test_cve_id_case_insensitive(self, auth_client, test_api_uri):
        """
        Test that the API endpoint is case-insensitive when matching CVE IDs
        """

        flaw = FlawFactory(cve_id="CVE-2999-9999")

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id.lower()}")
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/flaws/CvE-2999-9999")
        assert response.status_code == 200

    @pytest.mark.enable_signals
    def test_get_flaw_with_affect_trackers(
        self, auth_client, test_api_uri, refresh_v1_view, transactional_db
    ):
        """
        Regression test for tracker serialization bug in v1 API where UUIDs
        were not being converted to strings when looking up trackers from the
        cached tracker_list_by_uuid dictionary, causing no trackers to be
        returned in affect data within flaw responses.
        """
        flaw = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw.embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        refresh_v1_view()

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK

        # Verify that the flaw has affects
        assert len(response.data["affects"]) == 1

        # Verify that trackers are present in the affect data
        affect_data = response.data["affects"][0]
        assert len(affect_data["trackers"]) == 1

        # Verify the tracker data contains expected fields
        tracker_data = affect_data["trackers"][0]
        assert tracker_data["uuid"] == str(tracker.uuid)
        assert tracker_data["type"] == tracker.type
        assert tracker_data["ps_update_stream"] == tracker.ps_update_stream

    def test_flaw_selected_cve_description(self, auth_client, test_api_uri):
        """
        Test that the selected_cve_description field is returned correctly
        """

        flaw1 = FlawFactory(
            cve_description="Description A", mitre_cve_description="Description B"
        )

        flaw2 = FlawFactory(cve_description="", mitre_cve_description="Description D")

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw1.cve_id}")
        assert response.status_code == 200
        assert response.data["selected_cve_description"] == flaw1.cve_description

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw2.cve_id}")
        assert response.status_code == 200
        assert response.data["selected_cve_description"] == flaw2.mitre_cve_description
