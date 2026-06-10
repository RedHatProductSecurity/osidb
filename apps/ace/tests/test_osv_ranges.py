"""Tests for apps.ace.osv_ranges."""

import pytest

from apps.ace.osv_ranges import (
    OsvPackageInfo,
    match_component_to_upstream,
    osv_entry_to_package_info,
)

pytestmark = pytest.mark.unit


# ── osv_entry_to_package_info ─────────────────────────────────────────────────


def test_entry_to_package_info_basic():
    entry = {
        "purl": "pkg:nuget/Magick.NET-Q16-AnyCPU",
        "name": "Magick.NET-Q16-AnyCPU",
        "ecosystem": "NuGet",
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "14.10.3"}],
            }
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.name == "Magick.NET-Q16-AnyCPU"
    assert info.ecosystem == "nuget"
    assert info.introduced == "0"
    assert info.fixed == "14.10.3"
    assert info.last_affected == ""


def test_entry_to_package_info_last_affected():
    entry = {
        "purl": "pkg:pypi/vllm",
        "name": "vllm",
        "ecosystem": "PyPI",
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0.1.0"}, {"last_affected": "0.10.65"}],
            }
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.introduced == "0.1.0"
    assert info.fixed == ""
    assert info.last_affected == "0.10.65"


def test_entry_to_package_info_git_range_skipped():
    # GIT ranges must be ignored — no meaningful version bounds
    entry = {
        "purl": "pkg:golang/example.com/foo",
        "name": "foo",
        "ecosystem": "Go",
        "ranges": [
            {
                "type": "GIT",
                "events": [{"introduced": "abc123"}, {"fixed": "def456"}],
            }
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.introduced == ""
    assert info.fixed == ""


def test_entry_to_package_info_empty_ranges():
    entry = {
        "purl": "pkg:rpm/redhat/openssl",
        "name": "openssl",
        "ecosystem": "Linux",
        "ranges": [],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.affected_range() is None


# ── OsvPackageInfo.affected_range ─────────────────────────────────────────────


def test_affected_range_introduced_zero_fixed():
    info = OsvPackageInfo(
        name="x",
        ecosystem="nuget",
        purl="",
        introduced="0",
        fixed="14.10.3",
        last_affected="",
    )
    assert info.affected_range() == "< 14.10.3"


def test_affected_range_introduced_nonzero_fixed():
    info = OsvPackageInfo(
        name="x",
        ecosystem="maven",
        purl="",
        introduced="2.0-b9",
        fixed="2.15.0",
        last_affected="",
    )
    assert info.affected_range() == ">= 2.0-b9, < 2.15.0"


def test_affected_range_last_affected():
    info = OsvPackageInfo(
        name="x",
        ecosystem="pypi",
        purl="",
        introduced="0.1.0",
        fixed="",
        last_affected="0.10.65",
    )
    assert info.affected_range() == ">= 0.1.0, <= 0.10.65"


def test_affected_range_no_events():
    info = OsvPackageInfo(
        name="x", ecosystem="rpm", purl="", introduced="", fixed="", last_affected=""
    )
    assert info.affected_range() is None


# ── match_component_to_upstream ───────────────────────────────────────────────


def _make_upstream_purls():
    return [
        {
            "purl": "pkg:nuget/Magick.NET-Q16-AnyCPU",
            "name": "Magick.NET-Q16-AnyCPU",
            "ecosystem": "NuGet",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "14.10.3"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:rpm/redhat/openssl",
            "name": "openssl",
            "ecosystem": "Linux",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.9"}],
                }
            ],
            "versions": [],
        },
    ]


def test_match_by_name_exact():
    result = match_component_to_upstream("openssl", _make_upstream_purls())
    assert result is not None
    assert result.name == "openssl"
    assert result.fixed == "3.0.9"


def test_match_by_name_case_insensitive():
    result = match_component_to_upstream("OpenSSL", _make_upstream_purls())
    assert result is not None
    assert result.name == "openssl"


def test_match_by_purl_name():
    # The entry has name="Magick.NET-Q16-AnyCPU" — match via purl name
    result = match_component_to_upstream(
        "Magick.NET-Q16-AnyCPU", _make_upstream_purls()
    )
    assert result is not None
    assert result.fixed == "14.10.3"


def test_no_match_returns_none():
    result = match_component_to_upstream("nonexistent-package", _make_upstream_purls())
    assert result is None


def test_empty_upstream_purls_returns_none():
    result = match_component_to_upstream("openssl", [])
    assert result is None


def test_empty_component_returns_none():
    result = match_component_to_upstream("", _make_upstream_purls())
    assert result is None
