from typing import Callable, Optional

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "cra_reporting: connect CRA reporting signal for this test."
    )
    config.addinivalue_line(
        "markers",
        "no_cra_reporting: do not connect CRA reporting signal for this test.",
    )
    config.addinivalue_line(
        "markers", "cra_notifications: connect CRA notification signal for this test."
    )
    config.addinivalue_line(
        "markers",
        "no_cra_notifications: do not connect CRA notification signal for this test.",
    )


@pytest.fixture(autouse=True)
def cra_reporting_signals(request, settings):
    if request.node.get_closest_marker("no_cra_reporting"):
        settings.CRA_REPORTING_ENABLED = False
        yield
        return

    settings.CRA_REPORTING_ENABLED = True

    from django.db.models.signals import post_save

    from osidb.models import Flaw
    from regulatory_reporting.signals import create_srp_report

    post_save.connect(create_srp_report, sender=Flaw)
    yield
    post_save.disconnect(create_srp_report, sender=Flaw)


@pytest.fixture(autouse=True)
def cra_notification_signals(request, settings):
    if request.node.get_closest_marker("no_cra_notifications"):
        settings.CRA_NOTIFICATIONS_ENABLED = False
        yield
        return

    settings.CRA_NOTIFICATIONS_ENABLED = True
    from django.db.models.signals import post_save

    from osidb.models import Flaw
    from regulatory_reporting.models.upstream import FlawUpstreamMapping
    from regulatory_reporting.signals import (
        check_upstream_notifiable,
        link_mapping_to_notification,
    )

    post_save.connect(check_upstream_notifiable, sender=Flaw)
    post_save.connect(link_mapping_to_notification, sender=FlawUpstreamMapping)
    yield
    post_save.disconnect(check_upstream_notifiable, sender=Flaw)
    post_save.disconnect(link_mapping_to_notification, sender=FlawUpstreamMapping)


@pytest.fixture
def api_client():
    """API client for testing."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, django_user_model):
    """Authenticated API client."""
    user = django_user_model.objects.create_user(username="testuser")
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def create_flaw_report() -> Callable[
    [Optional[Flaw], Flaw.FlawMajorIncident], SRPReport
]:
    def _create_report(
        flaw=None,
        incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
    ) -> SRPReport:
        existing_uuids: set = set()
        if flaw:
            existing_uuids = set(flaw.srp_reports.values_list("uuid", flat=True))
            flaw.major_incident_state = incident_state
            flaw.save()
        else:
            flaw = FlawFactory(
                embargoed=False,
                major_incident_state=incident_state,
                major_incident_start_dt=timezone.now(),
            )

        created = flaw.srp_reports.exclude(uuid__in=existing_uuids)
        if created.exists():
            return created.get()

        # Signal used get_or_create; return the report for this event type.
        from regulatory_reporting.signals import REPORTABLE_EVENT_TYPE_MAP

        return flaw.srp_reports.get(
            reportable_event_type=REPORTABLE_EVENT_TYPE_MAP[incident_state]
        )

    return _create_report
