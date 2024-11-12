import json
import re

import pytest
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.db.models.signals import (
    m2m_changed,
    post_delete,
    post_save,
    pre_delete,
    pre_save,
)
from dotenv import dotenv_values
from rest_framework.test import APIClient

from osidb.constants import OSIDB_API_VERSION
from osidb.core import set_user_acls
from osidb.exceptions import InvalidTestEnvironmentException
from osidb.helpers import get_env

# matches base urls starting with http / https until the first slash after the protocol
base_url_pattern = re.compile(r"(https?://)[^/]+")


def strip_bz_update_token(body):
    body = json.loads(body)
    bugs = body.get("bugs", [])
    if isinstance(bugs, list):
        for bug in bugs:
            bug.pop("update_token", None)
    if bugs:
        body["bugs"] = bugs
    return json.dumps(body).encode("utf-8")


def strip_private_bz_comments(body):
    body = json.loads(body)
    bugs = body.get("bugs", [])

    if isinstance(bugs, dict):
        for _, bug in bugs.items():
            if "comments" in bug:
                bug["comments"] = [
                    c for c in bug["comments"] if not c.get("is_private", False)
                ]
    else:
        for bug in bugs:
            if "comments" in bug:
                bug["comments"] = [
                    c for c in bug["comments"] if not c.get("is_private", False)
                ]
    if bugs:
        body["bugs"] = bugs
    return json.dumps(body).encode("utf-8")


def clean_product_definitions_contacts(body):
    body = json.loads(body)
    contacts = body.get("contacts", [])
    if contacts:
        body["contacts"] = {
            "foo": {"bz_username": "foo", "jboss_username": "foo"},
            "bar": {"bz_username": "bar", "jboss_username": "bar"},
            "baz": {"bz_username": "baz", "jboss_username": "baz"},
            "ham": {"bz_username": "ham", "jboss_username": "ham"},
            "bacon": {"bz_username": "bacon", "jboss_username": "bacon"},
            "eggs": {"bz_username": "eggs", "jboss_username": "eggs"},
            "cheese": {"bz_username": "cheese", "jboss_username": "cheese"},
            "quux": {"bz_username": "quux", "jboss_username": "quux"},
        }
    return json.dumps(body).encode("utf-8")


def filter_response(response):
    response["headers"].pop("Set-Cookie", None)
    response["headers"].pop("x-ausername", None)
    response["headers"].pop("Content-Security-Policy", None)
    response["headers"].pop("X-frame-options", None)

    try:
        response["body"]["string"] = strip_private_bz_comments(
            response["body"]["string"]
        )
        response["body"]["string"] = clean_product_definitions_contacts(
            response["body"]["string"]
        )
        response["body"]["string"] = strip_bz_update_token(response["body"]["string"])
    except Exception:
        ...
    return response


def remove_host_request(request):
    request.uri = re.sub(base_url_pattern, "https://example.com", request.uri)
    return request


def remove_host_response(response):
    body_string = re.sub(
        base_url_pattern,
        "https://example.com",
        response["body"]["string"].decode("utf-8"),
    )
    response["body"]["string"] = body_string.encode("utf-8")

    # redirected requests need Location header
    original_locations = response["headers"].get("Location", [])
    if original_locations:
        locations = []
        for location in original_locations:
            locations.append(re.sub(base_url_pattern, "https://example.com", location))
        response["headers"]["Location"] = locations

    return response


@pytest.fixture(scope="session")
def vcr_config():
    return {
        "filter_headers": [
            "Authorization",
            "Cookie",
        ],
        "before_record_request": [remove_host_request],
        "before_record_response": [remove_host_response, filter_response],
        "filter_query_parameters": [
            "Bugzilla_api_key",
        ],
        "decode_compressed_response": True,
    }


class TokenClient(APIClient):
    def login(self, username, password):
        r = self.post(
            "/auth/token",
            {"username": username, "password": password},
            format="json",
        )
        self.credentials(HTTP_AUTHORIZATION=f"Bearer {r.data['access']}")


@pytest.fixture
def client():
    return TokenClient()


@pytest.fixture
def ldap_test_username():
    return "testuser"


@pytest.fixture
def ldap_test_password():
    return "password"


@pytest.fixture
def test_scheme_host():
    return "http://osidb-service:8000/osidb"


@pytest.fixture
def api_version():
    return OSIDB_API_VERSION


@pytest.fixture
def test_api_uri(test_scheme_host, api_version):
    return f"{test_scheme_host}/api/{api_version}"


@pytest.fixture
def auth_client(ldap_test_username, ldap_test_password):
    def clientify(as_user=ldap_test_username):
        client = TokenClient()
        client.login(as_user, ldap_test_password)
        return client

    return clientify


@pytest.fixture
def tokens(ldap_test_username, ldap_test_password):
    client = APIClient()
    r = client.post(
        "/auth/token",
        {"username": ldap_test_username, "password": ldap_test_password},
        format="json",
    )
    return r.data


# https://www.cameronmaske.com/muting-django-signals-with-a-pytest-fixture/
@pytest.fixture(autouse=True)  # Automatically use in tests.
def mute_signals(request):
    # Skip applying, if marked with `enable_signals`
    if "enable_signals" in request.keywords:
        return

    signals = [pre_save, post_save, pre_delete, post_delete, m2m_changed]
    restore = {}
    for signal in signals:
        # Temporally remove the signal's receivers (a.k.a attached functions)
        restore[signal] = signal.receivers
        signal.receivers = []

    def restore_signals():
        # When the test tears down, restore the signals.
        for signal, receivers in restore.items():
            signal.receivers = receivers

    # Called after a test has finished.
    request.addfinalizer(restore_signals)


@pytest.fixture(autouse=True)
def bypass_rls(db, request):
    # Don't bypass if marked with `enable_rls`
    if "enable_rls" in request.keywords:
        return
    set_user_acls(settings.ALL_GROUPS)


@pytest.fixture
def enable_bz_sync(monkeypatch) -> None:
    """
    enable the sync of trackers and flaw to Bugzilla
    """
    import apps.bbsync.mixins as mixins
    import osidb.models.flaw.flaw as flaw_module
    import osidb.models.tracker as tracker

    monkeypatch.setattr(flaw_module, "SYNC_FLAWS_TO_BZ", True)
    monkeypatch.setattr(mixins, "SYNC_TO_BZ", True)
    monkeypatch.setattr(tracker, "SYNC_TRACKERS_TO_BZ", True)


@pytest.fixture
def enable_bz_async_sync(enable_bz_sync, monkeypatch) -> None:
    """
    enable asynchonous synchronization of flaws to Bugzilla
    enable the sync of trackers to Bugzilla
    """
    import apps.bbsync.constants as bbsync_constants
    import apps.bbsync.save as bz_save
    import osidb.models.flaw.flaw as flaw_module

    monkeypatch.setattr(bbsync_constants, "SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY", True)
    monkeypatch.setattr(bz_save, "SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY", True)
    monkeypatch.setattr(flaw_module, "SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY", True)


@pytest.fixture
def enable_jira_task_sync(monkeypatch) -> None:
    """
    enable the sync of tasks to Jira
    """
    import apps.taskman.mixins as mixins
    import apps.taskman.service as service
    import osidb.models.flaw.flaw as flaw_module
    import osidb.serializer as serializer

    monkeypatch.setattr(flaw_module, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(service, "JIRA_STORY_ISSUE_TYPE_ID", "17")
    monkeypatch.setattr(service, "JIRA_TASKMAN_PROJECT_ID", "12337520")


@pytest.fixture
def enable_jira_tracker_sync(monkeypatch) -> None:
    """
    enable the sync of trackers to Jira
    """
    import osidb.models.tracker as tracker

    monkeypatch.setattr(tracker, "SYNC_TO_JIRA", True)


@pytest.fixture
def is_recording_vcr(pytestconfig):
    """
    identify if tests are running in any VCR recording mode
    """
    return pytestconfig.getoption("--record-mode") in ["once", "rewrite"]


@pytest.fixture(autouse=True)
def set_invalid_tokens(is_recording_vcr, monkeypatch):
    """
    set required Jira token for collector when not recording VCRs
    """
    from collectors.cveorg import collectors as cveorg_collector
    from collectors.jiraffe import collectors as jira_collector
    from collectors.osv import collectors as osv_collector

    if not is_recording_vcr:
        monkeypatch.setattr(osv_collector, "JIRA_AUTH_TOKEN", "SECRET")
        monkeypatch.setattr(cveorg_collector, "JIRA_AUTH_TOKEN", "SECRET")
        monkeypatch.setattr(jira_collector, "JIRA_TOKEN", "SECRET")


@pytest.fixture(autouse=True)  # Automatically use in tests.
def set_recording_environments(is_recording_vcr, monkeypatch):
    """
    automatically use local environments variables when writing VCRs cassettes
    """
    if not is_recording_vcr:
        return

    from apps.taskman import service as taskman_service
    from apps.trackers import common
    from apps.trackers.jira import save as jira_save
    from collectors.bzimport import collectors as bzimport_collector
    from collectors.jiraffe import core as jira_core
    from collectors.jiraffe.core import JiraConnector

    # testrunner should not contains environments set in order to make tests independent
    # from envs but VCR needs them so we manually load values where it is needed
    config = dotenv_values(".env")

    jira_url = config.get("JIRA_URL", "https://issues.redhat.com")
    jira_task_url = config.get("JIRA_TASKMAN_URL", "https://issues.redhat.com")
    bz_url = config.get("BZIMPORT_BZ_URL", "https://bugzilla.redhat.com")

    if "stage" not in jira_url:
        raise InvalidTestEnvironmentException(
            f"{jira_url} is not suitable for integration tests. Make sure JIRA_URL env is properly set."
        )

    if "stage" not in jira_task_url:
        raise InvalidTestEnvironmentException(
            f"{jira_url} is not suitable for integration tests. Make sure JIRA_TASKMAN_URL env is properly set."
        )

    if "stage" not in bz_url:
        raise InvalidTestEnvironmentException(
            f"{bz_url} is not suitable for integration tests. Make sure BZIMPORT_BZ_URL env is properly set."
        )

    monkeypatch.setenv("HTTPS_PROXY", config.get("HTTPS_PROXY"))

    # Classes that sets urls and tokens at class level (e.g. connectors) and
    # files that imports environments from constants need specific patches
    # because fixtures runs after the class loading phase

    # replace urls
    monkeypatch.setattr(JiraConnector, "_jira_server", jira_url)
    monkeypatch.setattr(jira_core, "JIRA_SERVER", jira_url)
    monkeypatch.setattr(jira_save, "JIRA_SERVER", jira_url)
    monkeypatch.setattr(taskman_service, "JIRA_TASKMAN_URL", jira_task_url)

    monkeypatch.setattr(common, "BZ_URL", bz_url)
    monkeypatch.setattr(bzimport_collector, "BZ_URL", bz_url)
