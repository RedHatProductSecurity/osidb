import threading
from datetime import datetime, timezone
from itertools import chain

import pytest
from django.conf import settings
from django.db import OperationalError, close_old_connections, transaction
from freezegun import freeze_time
from rest_framework import status

from osidb.core import set_user_acls
from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawReference,
    Impact,
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

    @pytest.mark.enable_signals
    @pytest.mark.django_db(transaction=True)
    @freeze_time(datetime(2030, 10, 10, tzinfo=timezone.utc))
    def test_concurrent_shared_tracker_unembargo_does_not_deadlock(
        self, monkeypatch, auth_client, test_api_uri, bugzilla_token, jira_token
    ):
        set_user_acls(settings.ALL_GROUPS)

        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw1 = FlawFactory(
            cve_id="CVE-2030-1111",
            embargoed=True,
            unembargo_dt=datetime(2030, 10, 10, tzinfo=timezone.utc),
        )
        flaw2 = FlawFactory(
            cve_id="CVE-2030-2222",
            embargoed=True,
            unembargo_dt=datetime(2030, 10, 10, tzinfo=timezone.utc),
        )
        affect1 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )
        tracker = TrackerFactory(
            affects=[affect1, affect2],
            embargoed=True,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        original_save = Tracker.save
        wait_timeout = 10
        requests_started = threading.Barrier(2)
        barrier = threading.Barrier(2)
        tracker_unembargo_save_threads = []
        tracker_barrier_completed = threading.Event()
        tracker_barrier_broken = threading.Event()
        thread_state = threading.local()

        def save_with_barrier(self, *args, **kwargs):
            if (
                getattr(thread_state, "flaw_update", False)
                and self.uuid == tracker.uuid
                and kwargs.get("auto_timestamps") is False
            ):
                tracker_unembargo_save_threads.append(thread_state.index)
                try:
                    barrier.wait(timeout=wait_timeout)
                except threading.BrokenBarrierError:
                    tracker_barrier_broken.set()
                else:
                    tracker_barrier_completed.set()
            return original_save(self, *args, **kwargs)

        monkeypatch.setattr(Tracker, "save", save_with_barrier)

        clients = {1: auth_client(), 2: auth_client()}
        responses = {}
        exceptions = {}

        def update_flaw(index, flaw_uuid, updated_dt):
            close_old_connections()
            set_user_acls(settings.ALL_GROUPS)
            thread_state.flaw_update = True
            thread_state.index = index
            try:
                requests_started.wait(timeout=wait_timeout)
                flaw = Flaw.objects.get(uuid=flaw_uuid)
                responses[index] = clients[index].put(
                    f"{test_api_uri}/flaws/{flaw_uuid}",
                    {
                        "title": flaw.title,
                        "comment_zero": flaw.comment_zero,
                        "embargoed": False,
                        "updated_dt": updated_dt,
                    },
                    format="json",
                    HTTP_BUGZILLA_API_KEY=bugzilla_token,
                    HTTP_JIRA_API_KEY=jira_token,
                )
            except Exception as exc:
                exceptions[index] = exc
            finally:
                if (
                    index not in tracker_unembargo_save_threads
                    and not tracker_barrier_completed.is_set()
                ):
                    barrier.abort()
                thread_state.flaw_update = False
                thread_state.index = None
                close_old_connections()

        thread1 = threading.Thread(
            target=update_flaw, args=(1, flaw1.uuid, flaw1.updated_dt)
        )
        thread2 = threading.Thread(
            target=update_flaw, args=(2, flaw2.uuid, flaw2.updated_dt)
        )

        thread1.start()
        thread2.start()
        thread1.join(timeout=20)
        thread2.join(timeout=20)

        set_user_acls(settings.ALL_GROUPS)
        assert not thread1.is_alive()
        assert not thread2.is_alive()
        assert not exceptions, [str(exc) for exc in exceptions.values()]
        assert tracker_unembargo_save_threads
        assert tracker_barrier_completed.is_set() or tracker_barrier_broken.is_set()
        if not tracker_barrier_completed.is_set():
            assert len(set(tracker_unembargo_save_threads)) == 1
        assert len(responses) == 2
        assert all(
            response.status_code == status.HTTP_200_OK
            for response in responses.values()
        )
        assert not any(instance.is_embargoed for instance in Affect.objects.all())
        assert not any(instance.is_embargoed for instance in Flaw.objects.all())
        assert not any(instance.is_embargoed for instance in Tracker.objects.all())

    @pytest.mark.enable_signals
    @pytest.mark.django_db(transaction=True)
    @freeze_time(datetime(2030, 10, 10, tzinfo=timezone.utc))
    def test_concurrent_affect_save_unembargo_does_not_deadlock(
        self, monkeypatch, auth_client, test_api_uri, bugzilla_token, jira_token
    ):
        set_user_acls(settings.ALL_GROUPS)

        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(
            embargoed=True,
            unembargo_dt=datetime(2030, 10, 10, tzinfo=timezone.utc),
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )

        original_affect_save = Affect.save
        unembargo_saving_affect = threading.Event()
        affect_update_checked_affect_lock = threading.Event()
        unembargo_finished = threading.Event()
        thread_state = threading.local()

        def save_affect_with_pause(self, *args, **kwargs):
            if getattr(thread_state, "unembargo", False) and self.uuid == affect.uuid:
                unembargo_saving_affect.set()
                assert affect_update_checked_affect_lock.wait(timeout=10)
            return original_affect_save(self, *args, **kwargs)

        monkeypatch.setattr(Affect, "save", save_affect_with_pause)

        client = auth_client()
        response = None
        exceptions = {}

        def unembargo_flaw():
            nonlocal response
            close_old_connections()
            set_user_acls(settings.ALL_GROUPS)
            thread_state.unembargo = True
            try:
                response = client.put(
                    f"{test_api_uri}/flaws/{flaw.uuid}",
                    {
                        "title": flaw.title,
                        "comment_zero": flaw.comment_zero,
                        "embargoed": False,
                        "updated_dt": flaw.updated_dt,
                    },
                    format="json",
                    HTTP_BUGZILLA_API_KEY=bugzilla_token,
                    HTTP_JIRA_API_KEY=jira_token,
                )
            except Exception as exc:
                exceptions["unembargo"] = exc
            finally:
                thread_state.unembargo = False
                unembargo_finished.set()
                close_old_connections()

        def update_affect():
            close_old_connections()
            set_user_acls(settings.ALL_GROUPS)
            thread_state.affect_update = True
            try:
                assert unembargo_saving_affect.wait(timeout=10)
                try:
                    with transaction.atomic():
                        affect_to_update = Affect.objects.select_for_update(
                            nowait=True
                        ).get(uuid=affect.uuid)
                        affect_update_checked_affect_lock.set()
                        affect_to_update.impact = Impact.LOW
                        affect_to_update.save(
                            auto_timestamps=False,
                            raise_validation_error=False,
                            update_fields=["impact"],
                        )
                except OperationalError as exc:
                    if "could not obtain lock on row" not in str(exc):
                        raise
                    affect_update_checked_affect_lock.set()
                    assert unembargo_finished.wait(timeout=10)
                    with transaction.atomic():
                        affect_to_update = Affect.objects.select_for_update().get(
                            uuid=affect.uuid
                        )
                        affect_to_update.impact = Impact.LOW
                        affect_to_update.save(
                            auto_timestamps=False,
                            raise_validation_error=False,
                            update_fields=["impact"],
                        )
            except Exception as exc:
                exceptions["affect_update"] = exc
            finally:
                thread_state.affect_update = False
                close_old_connections()

        thread1 = threading.Thread(target=unembargo_flaw)
        thread2 = threading.Thread(target=update_affect)

        thread1.start()
        thread2.start()
        thread1.join(timeout=20)
        thread2.join(timeout=20)

        set_user_acls(settings.ALL_GROUPS)
        assert not thread1.is_alive()
        assert not thread2.is_alive()
        assert not exceptions, [str(exc) for exc in exceptions.values()]
        assert response.status_code == status.HTTP_200_OK
        assert not Flaw.objects.get(uuid=flaw.uuid).is_embargoed
        assert not Affect.objects.get(uuid=affect.uuid).is_embargoed
