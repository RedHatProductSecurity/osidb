import pytest
from rest_framework import status

from apps.ace.constants import LABEL_AUTO_AFFECTS, LABEL_AUTO_REJECTED
from apps.ace.tasks import PreFilterAction, SpecialWorkflow


@pytest.mark.django_db
def test_pre_filter_api_requires_component(auth_client, test_api_uri):
    response = auth_client().get(f"{test_api_uri}/component-mapping/pre-filter")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "component" in response.json()


@pytest.mark.django_db
def test_pre_filter_api_blocklist(auth_client, test_api_uri):
    from collectors.component_mapping.models import BlocklistEntry

    BlocklistEntry.objects.create(name="gitlab", reason="Not shipped by Red Hat")

    response = auth_client().get(
        f"{test_api_uri}/component-mapping/pre-filter",
        {"component": "GitLab"},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["action"] == PreFilterAction.SKIP.value
    assert data["label"] == LABEL_AUTO_REJECTED
    assert "Blocked" in data["reason"]


@pytest.mark.django_db
def test_pre_filter_api_strict_package_auto_affects(auth_client, test_api_uri):
    from collectors.component_mapping.models import StrictPackage

    StrictPackage.objects.create(name="openssl", repos=["rhel-9"])

    response = auth_client().get(
        f"{test_api_uri}/component-mapping/pre-filter",
        {"component": "openssl"},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["action"] == PreFilterAction.SEARCH.value
    assert data["label"] == LABEL_AUTO_AFFECTS
    assert "openssl" in data["resolved_names"]


@pytest.mark.django_db
def test_pre_filter_api_go_stdlib(auth_client, test_api_uri):
    response = auth_client().get(
        f"{test_api_uri}/component-mapping/pre-filter",
        {
            "component": "net/http",
            "flaw_components": "golang,net/http",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["action"] == PreFilterAction.SPECIAL.value
    assert data["workflow"] == SpecialWorkflow.GO_STDLIB.value
    assert data["label"] == LABEL_AUTO_AFFECTS
