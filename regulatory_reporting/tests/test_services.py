import pytest
from django.test import override_settings

from osidb.models import FlawSource
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models.upstream import (
    FlawUpstreamMapping,
    UpstreamNotification,
    UpstreamProject,
)
from regulatory_reporting.services import is_flaw_upstream_notifiable


@pytest.mark.django_db
class TestIsFlawUpstreamNotifiable:
    def test_redhat_source_is_notifiable(self):
        flaw = FlawFactory(
            embargoed=False,
            source=FlawSource.REDHAT,
        )
        assert is_flaw_upstream_notifiable(flaw) is True

    def test_public_feed_source_is_not_notifiable(self):
        flaw = FlawFactory(source=FlawSource.NVD)
        assert is_flaw_upstream_notifiable(flaw) is False

    def test_cveorg_source_is_not_notifiable(self):
        flaw = FlawFactory(source=FlawSource.CVEORG)
        assert is_flaw_upstream_notifiable(flaw) is False


@pytest.mark.enable_signals
@pytest.mark.django_db
class TestUpstreamNotificationSignal:
    @override_settings(CRA_NOTIFICATIONS_ENABLED=True)
    def test_redhat_flaw_creates_notification(self):
        flaw = FlawFactory(
            embargoed=False,
            source=FlawSource.REDHAT,
        )
        notification = UpstreamNotification.objects.filter(flaw=flaw).first()
        assert notification is not None
        assert notification.status == UpstreamNotification.NotificationStatus.REQUIRED
        assert notification.upstream_project is None

    @override_settings(CRA_NOTIFICATIONS_ENABLED=True)
    def test_nvd_flaw_does_not_create_notification(self):
        flaw = FlawFactory(source=FlawSource.NVD)
        assert not UpstreamNotification.objects.filter(flaw=flaw).exists()

    def test_flag_disabled_does_not_create_notification(self):
        flaw = FlawFactory(
            embargoed=False,
            source=FlawSource.REDHAT,
        )
        assert not UpstreamNotification.objects.filter(flaw=flaw).exists()


@pytest.mark.enable_signals
class TestMappingNotificationSignal:
    @override_settings(CRA_NOTIFICATIONS_ENABLED=True)
    def test_backfills_existing_blank_notification(self):
        flaw = FlawFactory(embargoed=False, source=FlawSource.REDHAT)
        notification = UpstreamNotification.objects.get(flaw=flaw)
        assert notification.upstream_project is None
        project = UpstreamProject.objects.create(component_name="test-component")
        FlawUpstreamMapping.objects.create(flaw=flaw, upstream_project=project)
        notification.refresh_from_db()
        assert notification.upstream_project == project
        assert UpstreamNotification.objects.filter(flaw=flaw).count() == 1

    @override_settings(CRA_NOTIFICATIONS_ENABLED=True)
    def test_second_mapping_creates_separate_notification(self):
        flaw = FlawFactory(embargoed=False, source=FlawSource.REDHAT)
        project1 = UpstreamProject.objects.create(component_name="comp-1")
        project2 = UpstreamProject.objects.create(component_name="comp-2")
        FlawUpstreamMapping.objects.create(flaw=flaw, upstream_project=project1)
        FlawUpstreamMapping.objects.create(flaw=flaw, upstream_project=project2)
        assert UpstreamNotification.objects.filter(flaw=flaw).count() == 2

    @override_settings(CRA_NOTIFICATIONS_ENABLED=True)
    def test_backfills_even_if_status_already_blocked(self):
        flaw = FlawFactory(embargoed=False, source=FlawSource.REDHAT)
        notification = UpstreamNotification.objects.get(flaw=flaw)
        notification.status = UpstreamNotification.NotificationStatus.BLOCKED
        notification.save()
        project = UpstreamProject.objects.create(component_name="test-component")
        FlawUpstreamMapping.objects.create(flaw=flaw, upstream_project=project)
        notification.refresh_from_db()
        assert notification.upstream_project == project
        assert notification.status == UpstreamNotification.NotificationStatus.BLOCKED

    def test_flag_disabled_does_not_backfill(self):
        flaw = FlawFactory(embargoed=False, source=FlawSource.REDHAT)
        project = UpstreamProject.objects.create(component_name="test-component")
        FlawUpstreamMapping.objects.create(flaw=flaw, upstream_project=project)
        assert not UpstreamNotification.objects.filter(flaw=flaw).exists()
