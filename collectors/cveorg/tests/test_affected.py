"""CVE JSON 5 affected-range normalization."""

from types import SimpleNamespace

import pytest
import requests

from collectors.cveorg.affected import (
    affected_to_upstream_purls,
    fetch_cve_record,
    upsert_affected_from_record,
)
from osidb.models.flaw.upstream import UpstreamData
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


def _version(version="1.0", **fields):
    return {"version": version, "status": "affected", **fields}


def _product(name, *versions, **extra):
    return {"product": name, "versions": list(versions), **extra}


def _record(*products, adp=None):
    record = {"containers": {"cna": {"affected": list(products)}}}
    if adp is not None:
        record["containers"]["adp"] = [{"affected": list(adp)}]
    return record


def _events(record):
    entries = affected_to_upstream_purls(record)
    assert len(entries) == 1
    return entries[0]["ranges"][0]["events"]


@pytest.mark.parametrize(
    "version, events",
    [
        (
            _version(version="0", lessThan="3.0.9"),
            [{"introduced": "0"}, {"fixed": "3.0.9"}],
        ),
        (
            _version(version="1.0.0", lessThanOrEqual="1.2.0"),
            [{"introduced": "1.0.0"}, {"last_affected": "1.2.0"}],
        ),
        (
            _version(),
            [{"introduced": "1.0"}, {"last_affected": "1.0"}],
        ),
        (
            _version(version="1.0", lessThan="*"),
            [{"introduced": "1.0"}],
        ),
        (
            _version(version="1.0", lessThan="2.*"),
            [{"introduced": "1.0"}, {"fixed": "3"}],
        ),
        (
            _version(version="1.2.0", lessThan="1.2.*"),
            [{"introduced": "1.2.0"}, {"fixed": "1.3"}],
        ),
    ],
)
def test_version_objects_become_osv_events(version, events):
    assert _events(_record(_product("demo", version))) == events


@pytest.mark.parametrize(
    "version",
    [
        _version(version="< 9.2.0845"),
        _version(version="26.2", lessThan="< 26.2.5"),
    ],
)
def test_range_expressions_are_not_version_bounds(version):
    assert affected_to_upstream_purls(_record(_product("demo", version))) == []


def test_range_expression_drops_the_whole_product():
    record = _record(
        _product(
            "openssl",
            _version(version="0", lessThan="3.0.9"),
            _version(version="< 3.1.5"),
        ),
        _product("curl", _version(version="7.0", lessThan="8.0")),
    )
    assert [entry["name"] for entry in affected_to_upstream_purls(record)] == ["curl"]

    implied = _product(
        "openssl",
        {"version": "0", "lessThan": "3.0.9"},
        {"version": "< 3.1.5"},
        defaultStatus="affected",
    )
    assert affected_to_upstream_purls(_record(implied)) == []


def test_unaffected_phrase_keeps_the_converted_range():
    record = _record(
        _product(
            "openssl",
            _version(version="0", lessThan="3.0.9"),
            _version(version="< 1.0.0", status="unaffected"),
        )
    )
    assert _events(record) == [{"introduced": "0"}, {"fixed": "3.0.9"}]


@pytest.mark.parametrize(
    "product",
    [
        _product(
            "demo",
            _version(version="n/a", lessThan="*"),
            defaultStatus="affected",
        ),
        _product(
            "openssl",
            _version(version="3.0.9", status="unaffected"),
            defaultStatus="affected",
        ),
    ],
)
def test_unusable_affected_data_produces_no_range(product):
    assert affected_to_upstream_purls(_record(product)) == []


def test_cna_ranges_hide_adp_products():
    record = _record(
        _product("openssl", _version()),
        adp=[_product("other", _version(version="9.0"))],
    )
    entries = affected_to_upstream_purls(record)
    assert [entry["name"] for entry in entries] == ["openssl"]


def test_adp_is_used_when_cna_has_no_usable_range():
    record = _record(
        _product("openssl", _version(version="abc", versionType="git")),
        adp=[_product("curl", _version(version="8.0.0", lessThan="8.1.0"))],
    )
    entries = affected_to_upstream_purls(record)
    assert entries[0]["name"] == "curl"
    assert entries[0]["ranges"][0]["events"][-1] == {"fixed": "8.1.0"}


def test_platforms_are_kept_on_the_entry():
    restricted = _product(
        "demo",
        _version(version="3", lessThan="4"),
        platforms=[" Linux ", ""],
    )
    unrestricted = _product("curl", _version(version="1", lessThan="2"))
    entries = affected_to_upstream_purls(_record(restricted, unrestricted))
    assert [(entry["name"], entry["platforms"]) for entry in entries] == [
        ("demo", ["Linux"]),
        ("curl", []),
    ]

    malformed = _product("demo", _version(version="1", lessThan="2"), platforms="Linux")
    stored = affected_to_upstream_purls(_record(malformed))
    assert stored[0]["platforms"] == [""]


def test_package_name_and_product_are_both_kept():
    record = _record(
        {
            "packageName": "libssl",
            "product": "openssl",
            "versions": [_version(version="0", lessThan="3.0.9")],
        },
        _product("curl", _version(version="7.0", lessThan="8.0")),
    )
    entries = affected_to_upstream_purls(record)
    assert [(entry["name"], entry["product"]) for entry in entries] == [
        ("libssl", "openssl"),
        ("curl", ""),
    ]


def test_upsert_stores_ranges():
    flaw = FlawFactory(embargoed=False)
    upsert_affected_from_record(
        flaw.cve_id,
        _record(_product("openssl", _version(version="0", lessThan="3.0.9"))),
    )
    upstream = flaw.upstream_data.get(source=UpstreamData.Source.CVEORG)
    assert upstream.upstream_purls[0]["ranges"][0]["events"] == [
        {"introduced": "0"},
        {"fixed": "3.0.9"},
    ]


def test_fetch_returns_none_on_request_error(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr("collectors.cveorg.affected.requests.get", boom)
    assert fetch_cve_record("CVE-2024-0001") is None


def test_fetch_returns_record(monkeypatch):
    payload = {"containers": {"cna": {}}}
    response = SimpleNamespace(status_code=200, json=lambda: payload)
    monkeypatch.setattr(
        "collectors.cveorg.affected.requests.get", lambda *args, **kwargs: response
    )
    assert fetch_cve_record("CVE-2024-0001") == payload
