import pytest
from django.utils import timezone
from freezegun import freeze_time

from osidb.mixins import Alert
from osidb.models import Flaw, FlawSource
from osidb.tests.factories import AffectFactory, FlawFactory, PsModuleFactory

pytestmark = pytest.mark.unit


class TestSlateAlertCollector:
    @pytest.mark.vcr
    def test_collect_flaw(self, stale_alert_collector):
        """Test that the collector cleans up stale alerts related to a flaw."""
        flaw = FlawFactory(
            embargoed=False,
            source=FlawSource.REDHAT,
            major_incident_state=Flaw.FlawMajorIncident.MINOR,
        )
        flaw.save()
        alerts = Alert.objects.filter(object_id=flaw.uuid)

        assert alerts.count() == 3

        with freeze_time(timezone.now() + timezone.timedelta(1)):
            flaw.source = FlawSource.INTERNET
            AffectFactory(flaw=flaw, ps_module=PsModuleFactory().name)
            flaw.save()

        alerts = Alert.objects.filter(object_id=flaw.uuid)
        # Stale alerts still exist
        assert alerts.count() == 3

        result = stale_alert_collector.collect()
        alerts = Alert.objects.filter(object_id=flaw.uuid)
        # Stale alerts have been deleted
        assert alerts.count() == 1
        assert result == "Deleted 2 Stale Alerts"

    @pytest.mark.vcr
    def test_collect_affect(self, stale_alert_collector):
        """Test that the collector cleans up stale alerts related to an affect."""
        affect = AffectFactory()
        alerts = Alert.objects.filter(object_id=affect.uuid)

        assert alerts.count() == 1

        with freeze_time(timezone.now() + timezone.timedelta(1)):
            affect.ps_module = PsModuleFactory().name
            affect.save()

        alerts = Alert.objects.filter(object_id=affect.uuid)
        # Stale alerts still exist
        assert alerts.count() == 1

        result = stale_alert_collector.collect()
        alerts = Alert.objects.filter(object_id=affect.uuid)
        # Stale alerts have been deleted
        assert alerts.count() == 0
        assert result == "Deleted 1 Stale Alerts"

    @pytest.mark.vcr
    def test_collect_multi(self, stale_alert_collector):
        """Test that the collector cleans up stale alerts related to multiple objects."""
        flaw = FlawFactory(
            embargoed=False,
            source=FlawSource.REDHAT,
            major_incident_state=Flaw.FlawMajorIncident.MINOR,
        )
        flaw.save()
        alerts = Alert.objects.filter(object_id=flaw.uuid)

        assert alerts.count() == 3

        affect = AffectFactory(flaw=flaw)
        alerts = Alert.objects.filter(object_id=affect.uuid)

        assert alerts.count() == 1

        with freeze_time(timezone.now() + timezone.timedelta(1)):
            flaw.source = FlawSource.INTERNET
            affect.ps_module = PsModuleFactory().name
            flaw.save()
            affect.save()

        alerts = Alert.objects.filter(object_id=flaw.uuid)
        # Stale alerts still exist
        assert alerts.count() == 3

        alerts = Alert.objects.filter(object_id=affect.uuid)
        # Stale alerts still exist
        assert alerts.count() == 1

        result = stale_alert_collector.collect()
        alerts = Alert.objects.filter(object_id=flaw.uuid)
        # Stale alerts have been deleted
        assert alerts.count() == 1

        alerts = Alert.objects.filter(object_id=affect.uuid)
        # Stale alerts have been deleted
        assert alerts.count() == 0

        assert result == "Deleted 3 Stale Alerts"
