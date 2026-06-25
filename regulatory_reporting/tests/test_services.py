import pytest
from django.test import override_settings

from osidb.models import FlawSource
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models.upstream import UpstreamNotification
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
