import json

import pytest
from django.contrib.auth.models import Group, User
from django.db.models.signals import (
    m2m_changed,
    post_delete,
    post_save,
    pre_delete,
    pre_save,
)
from rest_framework.test import APIClient

from osidb.constants import OSIDB_API_VERSION


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
    try:
        response["body"]["string"] = strip_private_bz_comments(
            response["body"]["string"]
        )
        response["body"]["string"] = clean_product_definitions_contacts(
            response["body"]["string"]
        )
    except Exception:
        ...
    return response


@pytest.fixture(scope="session")
def vcr_config():
    return {
        "filter_headers": [
            "Authorization",
            "Cookie",
        ],
        "before_record_response": filter_response,
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
    client = TokenClient()
    client.login(ldap_test_username, ldap_test_password)
    return client


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
    # Skip applying, if marked with `enabled_signals`
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


@pytest.fixture
def embargo_access():
    """
    provide embargo access to the testuser
    """
    group = Group(name="data-topsecret-write")
    group.save()
    User.objects.get(username="testuser").groups.add(group)
