import pytest

from apps.sla.models import SLAPolicy, SLOPolicy
from apps.trackers.constants import TRACKERS_API_V1, TRACKERS_API_VERSION
from apps.trackers.models import JiraProjectFields
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from osidb.models import Affect, Flaw, Impact, PsModule, PsUpdateStream, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


@pytest.fixture(autouse=True)
def use_debug(settings) -> str:
    """Enforce DEBUG=True in all tests because pytest hardcodes it to False

    See: https://github.com/pytest-dev/pytest-django/pull/463

    Once the `--django-debug-mode` option is added to pytest, we can get rid of this fixture and
    use the CLI setting via pytest.ini:
    https://docs.pytest.org/en/latest/customize.html#adding-default-options
    """
    settings.DEBUG = True


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db) -> None:
    pass


@pytest.fixture(autouse=True)
def auto_enable_sync(enable_jira_task_sync, enable_bz_async_sync) -> None:
    pass


@pytest.fixture
def stage_jira_project() -> str:
    return "OSIM"


@pytest.fixture
def test_app_scheme_host() -> str:
    return "http://osidb-service:8000/trackers"


@pytest.fixture
def api_version() -> str:
    return TRACKERS_API_VERSION


@pytest.fixture
def api_version_v1() -> str:
    return TRACKERS_API_V1


@pytest.fixture
def test_app_api_uri(test_app_scheme_host, api_version) -> str:
    return f"{test_app_scheme_host}/api/{api_version}"


@pytest.fixture
def test_app_api_v1_uri(test_app_scheme_host, api_version_v1) -> str:
    return f"{test_app_scheme_host}/api/{api_version_v1}"


@pytest.fixture()
def clean_policies():
    """
    clean SLA/SLO policies before and after every test

        * before so it is not mixed with some leftovers
        * after so we do not leave any leftovers

    if we do it only before or only after the tests might behave differently
    when run in batch than when run alone so better to be safe then sorry
    """
    SLAPolicy.objects.all().delete()
    SLOPolicy.objects.all().delete()
    yield  # run test here
    SLAPolicy.objects.all().delete()
    SLOPolicy.objects.all().delete()


def jira_vulnissuetype_fields_setup_without_versions():
    # Affects Versions field not set up here so that tests can customize it
    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10121",
        field_name="Source",
        # Severely pruned for the test
        allowed_values=["Red Hat", "Upstream"],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10101",
        field_name="CVE ID",
        allowed_values=[],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10055",
        field_name="CVSS Score",
        allowed_values=[],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10151",
        field_name="CWE ID",
        allowed_values=[],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10056",
        field_name="Downstream Component Name",
        allowed_values=[],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10057",
        field_name="Upstream Affected Component",
        allowed_values=[],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10058",
        field_name="Embargo Status",
        allowed_values=["True", "False"],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10155",
        field_name="Special Handling",
        allowed_values=[
            "0-day",
            "Major Incident",
            "Minor Incident",
            "KEV (active exploit case)",
        ],
    ).save()

    JiraProjectFields(
        project_key="FOOPROJECT",
        field_id="customfield_10054",
        field_name="Severity",
        allowed_values=[
            "Critical",
            "Important",
            "Moderate",
            "Low",
            "unexpected mess here",
            "Informational",
            "None",
        ],
    ).save()


@pytest.fixture()
def setup_vulnerability_issue_type_fields() -> None:
    jira_vulnissuetype_fields_setup_without_versions()


@pytest.fixture
def flaw_dummy():
    return FlawFactory(
        embargoed=False,
        bz_id="123",
        cve_id="CVE-2999-1000",
        impact=Impact.MODERATE,
        major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        title="some description",
        source="REDHAT",
        cwe_id="CWE-1",
    )


@pytest.fixture
def affect_dummy(flaw_dummy: Flaw, ps_update_stream_dummy: PsUpdateStream):
    return AffectFactory(
        flaw=flaw_dummy,
        ps_update_stream="bar-1.2.3",
        ps_component="foo-component",
        affectedness=Affect.AffectAffectedness.AFFECTED,
        impact=Impact.MODERATE,
    )


@pytest.fixture
def ps_module_dummy_jira():
    return PsModuleFactory(name="foo-module", bts_name="jboss", bts_key="FOOPROJECT")


@pytest.fixture
def ps_update_stream_dummy(ps_module_dummy_jira: PsModule):
    return PsUpdateStreamFactory(
        ps_module=ps_module_dummy_jira, name="bar-1.2.3", version="1.2.3"
    )


@pytest.fixture
def tracker_dummy(flaw_dummy: Flaw, affect_dummy: Affect):
    return TrackerFactory(
        affects=[affect_dummy],
        type=Tracker.TrackerType.JIRA,
        ps_update_stream=affect_dummy.ps_update_stream,
        embargoed=flaw_dummy.is_embargoed,
    )


@pytest.fixture
def jira_project_fields_security(ps_module_dummy_jira: PsModule):
    JiraProjectFieldsFactory(
        project_key=ps_module_dummy_jira.bts_key,
        field_id="security",
        field_name="Security Level",
        allowed_values=[
            "Embargoed Security Issue",
            "Red Hat Employee",
            "Red Hat Engineering Authorized",
            "Red Hat Partner",
            "Restricted",
            "Team",
        ],
    )
