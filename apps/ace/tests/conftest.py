from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _result(ps_update_stream: str, purl: str) -> SimpleNamespace:
    """Minimal stand-in for NewcliBuildResult / NewcliDepResult."""
    return SimpleNamespace(
        ps_update_stream=ps_update_stream,
        purls=[purl],
        build_nvr=None,
    )


def _make_mock_querier(results_by_component: dict) -> MagicMock:
    """Return a NewtopiaQuerier mock whose .search().filter().all() returns
    the list mapped to each component key in *results_by_component*."""

    def _search(terms, **kwargs):
        component = terms[0]
        qs = MagicMock()
        qs.filter.return_value.all.return_value = results_by_component.get(
            component, []
        )
        return qs

    querier = MagicMock()
    querier.return_value.search.side_effect = _search
    return querier


@pytest.fixture
def urllib3_results():
    return [
        _result(
            "hummingbird-1",
            "pkg:oci/python-cryptography?repository_url=registry.redhat.io/python-cryptography",
        ),
        _result(
            "hummingbird-1",
            "pkg:oci/python-jsonschema?repository_url=registry.redhat.io/python-jsonschema",
        ),
        _result(
            "hummingbird-1",
            "pkg:oci/python-jsonschema-specifications?repository_url=registry.redhat.io/python-jsonschema-specifications",
        ),
        _result(
            "hummingbird-1",
            "pkg:oci/python-sentry-sdk?repository_url=registry.redhat.io/python-sentry-sdk",
        ),
        _result(
            "hummingbird-1",
            "pkg:oci/python3.11?repository_url=registry.redhat.io/python3.11",
        ),
    ]


@pytest.fixture
def openssl_results():
    return [
        _result(
            "hummingbird-1",
            "pkg:oci/python-cryptography?repository_url=registry.redhat.io/python-cryptography",
        ),
    ]


@pytest.fixture
def ostree_results():
    return [
        _result("hummingbird-1", "pkg:rpm/redhat/ostree@2026.1-2.hum1?arch=src"),
        _result("hummingbird-1", "pkg:rpm/redhat/bootc@1.14.0-0.1.1.hum1?arch=src"),
    ]


@pytest.fixture
def openssl_multi_results():
    return [
        _result("hummingbird-1", "pkg:rpm/redhat/openssl@3.5.6-0.1.hum1?arch=src"),
        _result("rhel-9.8.z", "pkg:rpm/redhat/openssl@3.5.1-7.el9_7?arch=src"),
        _result("rhel-9.8.z", "pkg:rpm/redhat/openssl@3.5.5-1.el9?arch=src"),
        _result("rhel-8.8.0.z", "pkg:rpm/redhat/openssl@1.1.1k-15.el8_6?arch=src"),
        _result("hummingbird-1", "pkg:rpm/redhat/bootc@1.14.0-0.1.1.hum1?arch=src"),
        _result("hummingbird-1", "pkg:rpm/redhat/chunkah@0.4.0-1.hum1?arch=src"),
    ]


@pytest.fixture
def mock_querier():
    """Factory fixture: call with a results-by-component dict to get a
    NewtopiaQuerier mock whose .search().filter().all() returns the right list."""
    return _make_mock_querier


@pytest.fixture
def ace_enabled(monkeypatch):
    """Patch HAS_LIB_NEWTOPIA=True so the task does not short-circuit."""
    monkeypatch.setattr("apps.ace.tasks.HAS_LIB_NEWTOPIA", True)
