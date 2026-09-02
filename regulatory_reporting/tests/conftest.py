from typing import Callable, Optional

import pytest
from django.conf import settings
from django.contrib.auth.models import Group
from django.utils import timezone
from rest_framework.test import APIClient

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport
from regulatory_reporting.services import create_srp_report


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
def cra_reporting_enabled(request, settings):
    """Enable CRA reporting API unless the test opts out with no_cra_reporting."""
    if request.node.get_closest_marker("no_cra_reporting"):
        settings.CRA_REPORTING_ENABLED = False
        yield
        return

    settings.CRA_REPORTING_ENABLED = True
    yield


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
    """Authenticated API client with public ACL groups."""
    user = django_user_model.objects.create_user(username="testuser")
    for group_name in [*settings.PUBLIC_READ_GROUPS, settings.PUBLIC_WRITE_GROUP]:
        group, _ = Group.objects.get_or_create(name=group_name)
        user.groups.add(group)
    api_client.force_login(user)
    api_client.force_authenticate(user=user)
    return api_client


def _set_report_attrs(report, report_attrs):
    if report_attrs:
        for k, v in report_attrs.items():
            setattr(report, k, v)
        report.save()


def _set_milestone_attrs(milestones, milestone_attrs):
    if milestone_attrs:
        for milestone in milestones:
            for k, v in milestone_attrs.items():
                setattr(milestone, k, v)
            milestone.save()


@pytest.fixture(autouse=True)
def create_flaw_report() -> Callable[
    [Optional[Flaw], Flaw.FlawMajorIncident], SRPReport
]:
    def _create_report(
        flaw=None,
        incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
        report_attrs=None,
        milestone_attrs=None,
    ) -> SRPReport:
        if flaw:
            flaw.major_incident_state = incident_state
            flaw.save()
            report = create_srp_report(flaw, incident_state)
            _set_report_attrs(report, report_attrs)
            _set_milestone_attrs(report.milestones.all(), milestone_attrs)
            return report
        else:
            flaw = FlawFactory(
                embargoed=False,
                major_incident_state=incident_state,
                major_incident_start_dt=timezone.now(),
            )
            report = create_srp_report(flaw, incident_state)
            _set_report_attrs(report, report_attrs)
            _set_milestone_attrs(report.milestones.all(), milestone_attrs)
            return report

    return _create_report
