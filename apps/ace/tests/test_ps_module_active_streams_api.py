import pytest
from rest_framework import status

from osidb.tests.factories import PsUpdateStreamFactory


@pytest.mark.django_db
def test_ps_module_active_streams_api_requires_names(auth_client, test_api_uri):
    response = auth_client().get(f"{test_api_uri}/ps-modules/active-streams")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "names" in response.json()


@pytest.mark.django_db
def test_ps_module_active_streams_api_returns_active_streams(auth_client, test_api_uri):
    stream1 = PsUpdateStreamFactory(name="openshift-4.16.z")
    stream2 = PsUpdateStreamFactory(name="openshift-4.17.z")
    ps_module = stream1.ps_module
    ps_module.name = "openshift-4"
    ps_module.save()

    stream1.active_to_ps_module = ps_module
    stream1.save()
    stream2.ps_module = ps_module
    stream2.active_to_ps_module = ps_module
    stream2.save()

    response = auth_client().get(
        f"{test_api_uri}/ps-modules/active-streams",
        {"names": "openshift-4,unknown-module"},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert set(data["ps_modules"]["openshift-4"]) == {
        "openshift-4.16.z",
        "openshift-4.17.z",
    }
    assert data["ps_modules"]["unknown-module"] == []
