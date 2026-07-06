import pytest


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
    from regulatory_reporting.signals import check_upstream_notifiable

    post_save.connect(check_upstream_notifiable, sender=Flaw)
    yield
    post_save.disconnect(check_upstream_notifiable, sender=Flaw)
