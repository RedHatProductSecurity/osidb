import pytest
from rest_framework import status

from osidb.models.abstract import Impact
from osidb.models.affect import Affect
from osidb.tests.factories import (
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
)


@pytest.mark.django_db
def test_auto_resolve_api_requires_ps_update_stream(auth_client, test_api_uri):
    response = auth_client().get(f"{test_api_uri}/affects/auto-resolve")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "ps_update_stream" in response.json()


@pytest.mark.django_db
def test_auto_resolve_api_unknown_flaw(auth_client, test_api_uri):
    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": "any-stream",
            "flaw": "00000000-0000-0000-0000-000000000001",
        },
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_auto_resolve_api_delegated(auth_client, test_api_uri):
    ps_product = PsProductFactory(business_unit="RHEL")
    ps_module = PsModuleFactory(ps_product=ps_product)
    stream = PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        default_to_ps_module=ps_module,
    )
    flaw = FlawFactory(impact=Impact.IMPORTANT)

    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": stream.name,
            "flaw": str(flaw.uuid),
            "impact": Impact.IMPORTANT,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["affectedness"] == Affect.AffectAffectedness.AFFECTED
    assert data["resolution"] == Affect.AffectResolution.DELEGATED


@pytest.mark.django_db
def test_auto_resolve_api_important_without_flaw(auth_client, test_api_uri):
    ps_product = PsProductFactory(business_unit="RHEL")
    ps_module = PsModuleFactory(ps_product=ps_product)
    stream = PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        default_to_ps_module=ps_module,
    )

    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": stream.name,
            "impact": Impact.IMPORTANT,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["affectedness"] == Affect.AffectAffectedness.AFFECTED
    assert data["resolution"] == Affect.AffectResolution.DELEGATED


@pytest.mark.django_db
def test_auto_resolve_api_unknown_stream(auth_client, test_api_uri):
    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": "does-not-exist",
            "impact": Impact.IMPORTANT,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["affectedness"] == Affect.AffectAffectedness.NEW
    assert data["resolution"] == Affect.AffectResolution.NOVALUE


@pytest.mark.django_db
def test_auto_resolve_api_requires_impact_without_flaw(auth_client, test_api_uri):
    ps_product = PsProductFactory(business_unit="RHEL")
    ps_module = PsModuleFactory(ps_product=ps_product)
    stream = PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        default_to_ps_module=ps_module,
    )

    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {"ps_update_stream": stream.name},
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "impact" in response.json()


@pytest.mark.django_db
def test_auto_resolve_api_moderate_without_flaw_requires_cvss(
    auth_client, test_api_uri
):
    ps_product = PsProductFactory(business_unit="RHEL")
    ps_module = PsModuleFactory(ps_product=ps_product)
    stream = PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        moderate_to_ps_module=ps_module,
        unacked_to_ps_module=None,
    )

    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": stream.name,
            "impact": Impact.MODERATE,
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "flaw_has_high_cvss_score" in response.json()


@pytest.mark.django_db
def test_auto_resolve_api_moderate_without_flaw_with_explicit_cvss(
    auth_client, test_api_uri
):
    ps_product = PsProductFactory(business_unit="RHEL")
    ps_module = PsModuleFactory(ps_product=ps_product)
    stream = PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        moderate_to_ps_module=ps_module,
        unacked_to_ps_module=None,
    )

    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": stream.name,
            "impact": Impact.MODERATE,
            "flaw_has_high_cvss_score": "true",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["affectedness"] == Affect.AffectAffectedness.AFFECTED
    assert data["resolution"] == Affect.AffectResolution.DELEGATED


@pytest.mark.django_db
def test_auto_resolve_api_rejects_invalid_impact(auth_client, test_api_uri):
    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": "any-stream",
            "impact": "INVALID",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "impact" in response.json()


@pytest.mark.django_db
def test_auto_resolve_api_rejects_invalid_cvss_literal(auth_client, test_api_uri):
    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": "any-stream",
            "impact": Impact.MODERATE,
            "flaw_has_high_cvss_score": "invalid",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "flaw_has_high_cvss_score" in response.json()


@pytest.mark.django_db
def test_auto_resolve_api_moderate_without_flaw_explicit_false_cvss_defer(
    auth_client, test_api_uri
):
    ps_product = PsProductFactory(business_unit="RHEL")
    ps_module = PsModuleFactory(ps_product=ps_product)
    stream = PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        moderate_to_ps_module=ps_module,
        unacked_to_ps_module=None,
    )

    response = auth_client().get(
        f"{test_api_uri}/affects/auto-resolve",
        {
            "ps_update_stream": stream.name,
            "impact": Impact.MODERATE,
            "flaw_has_high_cvss_score": "false",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["affectedness"] == Affect.AffectAffectedness.AFFECTED
    assert data["resolution"] == Affect.AffectResolution.DEFER
