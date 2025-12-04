from datetime import datetime, timezone
from itertools import chain

import pytest
from freezegun import freeze_time
from rest_framework import status

from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawReference,
    Package,
    Tracker,
)
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PackageFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpointsFlawsUnembargo:
    """
    tests of the unembargo logic which may
    result from /flaws endpoint PUT calls
    """

    @freeze_time(datetime(2020, 10, 10, tzinfo=timezone.utc))
    def test_minimal(self, auth_client, test_api_uri):
        """
        test that a minimal flaw context can be correctly unembargoed
        """
        flaw = FlawFactory(
            embargoed=True,
            unembargo_dt=datetime(2030, 10, 10, tzinfo=timezone.utc),
        )
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
            resolution=Affect.AffectResolution.NOVALUE,
            ps_update_stream=ps_update_stream.name,
        )

        assert Affect.objects.first().is_embargoed
        assert Flaw.objects.first().is_embargoed

        with freeze_time(datetime(2030, 10, 10, tzinfo=timezone.utc)):
            flaw_data = {
                "comment_zero": flaw.comment_zero,
                "embargoed": False,
                "title": flaw.title,
                "updated_dt": flaw.updated_dt,
            }

            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert not Affect.objects.first().is_embargoed
            assert not Flaw.objects.first().is_embargoed

    @freeze_time(datetime(2020, 10, 10, tzinfo=timezone.utc))
    def test_complex(
        self,
        auth_client,
        test_api_uri,
        public_read_groups,
        public_write_groups,
        internal_read_groups,
        internal_write_groups,
    ):
        """
        test that a complex flaw context can be correctly unembargoed
        """
        flaw = FlawFactory(
            embargoed=True,
            unembargo_dt=datetime(2030, 10, 10, tzinfo=timezone.utc),
        )
        FlawAcknowledgmentFactory(flaw=flaw, affiliation="Corp1")
        FlawAcknowledgmentFactory(flaw=flaw, affiliation="Corp2")
        FlawCommentFactory(flaw=flaw)
        FlawCommentFactory(flaw=flaw)
        FlawCVSSFactory(flaw=flaw, version=FlawCVSS.CVSSVersion.VERSION4)
        FlawReferenceFactory(flaw=flaw)
        PackageFactory(flaw=flaw)
        ps_module = PsModuleFactory()
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module)

        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream1.name,
        )
        AffectCVSSFactory(affect=affect1)
        AffectCVSSFactory(affect=affect1)

        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream2.name,
        )

        TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        TrackerFactory(
            affects=[affect2],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream2.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        assert all(
            instance.is_embargoed
            for instance in chain(
                Flaw.objects.all(),
                FlawAcknowledgment.objects.all(),
                FlawComment.objects.all(),
                FlawCVSS.objects.all(),
                FlawReference.objects.all(),
                Affect.objects.all(),
                AffectCVSS.objects.all(),
                Package.objects.all(),
                Tracker.objects.all(),
            )
        )

        with freeze_time(datetime(2030, 10, 10, tzinfo=timezone.utc)):
            flaw_data = {
                "comment_zero": flaw.comment_zero,
                "embargoed": False,
                "title": flaw.title,
                "updated_dt": flaw.updated_dt,
            }

            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            models = [
                Flaw,
                FlawAcknowledgment,
                FlawComment,
                FlawCVSS,
                FlawReference,
                Affect,
                AffectCVSS,
                Tracker,
                Package,
            ]
            assert not any(
                instance.is_embargoed
                for instance in chain(*[model.objects.all() for model in models])
            )

            for model in models[:-1]:
                for instance in model.objects.all():
                    for audit_event in instance.events.all():
                        assert audit_event.acl_read == public_read_groups
                        assert audit_event.acl_write == public_write_groups

    @freeze_time(datetime(2020, 10, 10, tzinfo=timezone.utc))
    def test_combined(self, auth_client, test_api_uri):
        """
        test that a combined flaw context of multiple flaws can be correctly unembargoed
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw1 = FlawFactory(
            embargoed=True,
            unembargo_dt=datetime(2030, 10, 10, tzinfo=timezone.utc),
        )
        affect1 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )

        flaw2 = FlawFactory(
            embargoed=flaw1.embargoed,
            unembargo_dt=datetime(2040, 10, 10, tzinfo=timezone.utc),
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component=affect1.ps_component,
        )

        TrackerFactory(
            affects=[affect1, affect2],
            embargoed=flaw1.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        assert all(instance.is_embargoed for instance in Affect.objects.all())
        assert all(instance.is_embargoed for instance in Flaw.objects.all())
        assert all(instance.is_embargoed for instance in Tracker.objects.all())

        with freeze_time(datetime(2030, 10, 10, tzinfo=timezone.utc)):
            flaw_data = {
                "comment_zero": flaw1.comment_zero,
                "embargoed": False,
                "title": flaw1.title,
                "updated_dt": flaw1.updated_dt,
            }

            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw1.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert not Flaw.objects.get(uuid=flaw1.uuid).is_embargoed
            assert not Affect.objects.get(uuid=affect1.uuid).is_embargoed
            assert Flaw.objects.get(uuid=flaw2.uuid).is_embargoed
            assert Affect.objects.get(uuid=affect2.uuid).is_embargoed
            assert all(instance.is_embargoed for instance in Tracker.objects.all())

        with freeze_time(datetime(2040, 10, 10, tzinfo=timezone.utc)):
            flaw_data = {
                "comment_zero": flaw2.comment_zero,
                "embargoed": False,
                "title": flaw2.title,
                "updated_dt": flaw2.updated_dt,
            }

            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw2.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert not any(instance.is_embargoed for instance in Affect.objects.all())
            assert not any(instance.is_embargoed for instance in Flaw.objects.all())
            assert not any(instance.is_embargoed for instance in Tracker.objects.all())
