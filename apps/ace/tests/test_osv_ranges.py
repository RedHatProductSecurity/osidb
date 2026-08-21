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
    upstream_purls = _make_upstream_purls()
    upstream_purls[0]["name"] = "different-display-name"
    result = match_component_to_upstream("Magick.NET-Q16-AnyCPU", upstream_purls)
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


# ── match_component_to_upstream ecosystem filtering ─────────────────────────


def _make_multi_ecosystem_purls():
    return [
        {
            "purl": "pkg:npm/redis",
            "name": "redis",
            "ecosystem": "npm",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "5.0.0"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:pypi/redis",
            "name": "redis",
            "ecosystem": "PyPI",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "4.0.0"}],
                }
            ],
            "versions": [],
        },
    ]


def test_match_filters_by_ecosystem():
    purls = _make_multi_ecosystem_purls()
    npm_result = match_component_to_upstream("redis", purls, ecosystem="npm")
    assert npm_result is not None
    assert npm_result.fixed == "5.0.0"

    pypi_result = match_component_to_upstream("redis", purls, ecosystem="pypi")
    assert pypi_result is not None
    assert pypi_result.fixed == "4.0.0"


def test_match_no_ecosystem_returns_first():
    purls = _make_multi_ecosystem_purls()
    result = match_component_to_upstream("redis", purls)
    assert result is not None
    assert result.fixed == "5.0.0"


def test_match_unknown_ecosystem_returns_none():
    purls = _make_multi_ecosystem_purls()
    result = match_component_to_upstream("redis", purls, ecosystem="maven")
    assert result is None


# ── match_component_to_upstream purl-less entries ────────────────────────────


def test_match_purl_less_entry_by_name():
    """Purl-less entry with name+ecosystem matches by name without ecosystem filter."""
    purls = [
        {
            "purl": "",
            "name": "Kernel",
            "ecosystem": "Linux",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "6.0.0"}],
                }
            ],
            "versions": [],
        }
    ]
    result = match_component_to_upstream("kernel", purls)
    assert result is not None
    assert result.name == "Kernel"
    assert result.ecosystem == "generic"
    assert result.fixed == "6.0.0"


def test_match_purl_less_entry_with_ecosystem_filter():
    """Purl-less entry with ecosystem matches when OSV ecosystem maps to filter."""
    purls = [
        {
            "purl": "",
            "name": "Kernel",
            "ecosystem": "Linux",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "6.0.0"}],
                }
            ],
            "versions": [],
        }
    ]
    # OSV ecosystem "Linux" maps to "generic" in OSV_ECOSYSTEM_MAP
    result = match_component_to_upstream("kernel", purls, ecosystem="generic")
    assert result is not None
    assert result.ecosystem == "generic"


def test_match_purl_less_entry_wrong_ecosystem():
    """Purl-less entry is skipped when mapped ecosystem doesn't match filter."""
    purls = [
        {
            "purl": "",
            "name": "Kernel",
            "ecosystem": "Linux",
            "ranges": [],
            "versions": [],
        }
    ]
    result = match_component_to_upstream("kernel", purls, ecosystem="npm")
    assert result is None


def test_entry_to_package_info_purl_less():
    """Purl-less entry correctly extracts name, ecosystem, and ranges."""
    entry = {
        "purl": "",
        "name": "Kernel",
        "ecosystem": "Linux",
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.0.0"}]}
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.name == "Kernel"
    assert info.ecosystem == "generic"
    assert info.purl == ""
    assert info.introduced == "0"
    assert info.fixed == "6.0.0"


# ── Disjoint range support (OSIDB-5343) ──────────────────────────────────────


def test_entry_disjoint_ranges_within_single_entry():
    """
    A single upstream_purls entry with multiple introduced/fixed pairs
    in its events list must produce OR groups.

    jackson-core example: events=[introduced:2.15.0, fixed:2.18.6,
    introduced:2.19.0, fixed:2.21.1] → ">= 2.15.0, < 2.18.6 || >= 2.19.0, < 2.21.1"
    """
    entry = {
        "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core",
        "name": "jackson-core",
        "ecosystem": "Maven",
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "2.15.0"},
                    {"fixed": "2.18.6"},
                    {"introduced": "2.19.0"},
                    {"fixed": "2.21.1"},
                ],
            }
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.affected_range() == ">= 2.15.0, < 2.18.6 || >= 2.19.0, < 2.21.1"


def test_entry_single_range_no_or_groups():
    """A single introduced/fixed pair should not produce OR groups."""
    entry = {
        "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core",
        "name": "jackson-core",
        "ecosystem": "Maven",
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.18.6"}],
            }
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert len(info.range_groups) == 1
    assert info.affected_range() == "< 2.18.6"


def test_match_merges_disjoint_entries():
    """
    When multiple upstream_purls entries match the same component name,
    their ranges must be merged with OR groups.

    This is the jackson-core CVE-2026-18401 scenario: three separate
    affected[] blocks produce three upstream_purls entries.
    """
    upstream_purls = [
        {
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core",
            "name": "jackson-core",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.15.0"}, {"fixed": "2.18.6"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core",
            "name": "jackson-core",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.19.0"}, {"fixed": "2.21.1"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:maven/tools.jackson.core/jackson-core",
            "name": "jackson-core",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.0"}],
                }
            ],
            "versions": [],
        },
    ]
    result = match_component_to_upstream("jackson-core", upstream_purls)
    assert result is not None
    range_str = result.affected_range()
    assert ">= 2.15.0, < 2.18.6" in range_str
    assert ">= 2.19.0, < 2.21.1" in range_str
    assert ">= 3.0.0, < 3.1.0" in range_str
    assert "||" in range_str


def test_match_disjoint_version_outside_all_ranges():
    """
    A version outside all disjoint ranges must be NOT_AFFECTED.

    jackson-core 2.21.4 is above the fix for the second range (2.21.1)
    and below the third range's start (3.0.0) → not affected.
    """
    from apps.ace.version import (
        OsvStatus,
        determine_status,
        parse_version_range_or,
    )

    upstream_purls = [
        {
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core",
            "name": "jackson-core",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.15.0"}, {"fixed": "2.18.6"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core",
            "name": "jackson-core",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.19.0"}, {"fixed": "2.21.1"}],
                }
            ],
            "versions": [],
        },
    ]
    info = match_component_to_upstream("jackson-core", upstream_purls)
    range_str = info.affected_range()
    constraints = parse_version_range_or(range_str, "maven")

    # 2.21.4 is above 2.21.1 fix → not affected
    assert determine_status("2.21.4", constraints) == OsvStatus.NOT_AFFECTED
    # 2.18.6 is at the fix boundary → not affected
    assert determine_status("2.18.6", constraints) == OsvStatus.NOT_AFFECTED
    # 2.17.0 is inside first range → affected
    assert determine_status("2.17.0", constraints) == OsvStatus.AFFECTED
    # 2.20.0 is inside second range → affected
    assert determine_status("2.20.0", constraints) == OsvStatus.AFFECTED
    # 2.14.0 is below first range's start → not affected
    assert determine_status("2.14.0", constraints) == OsvStatus.NOT_AFFECTED


def test_entry_introduced_only_no_fix():
    """
    An entry with only 'introduced' and no 'fixed' or 'last_affected' represents
    an open-ended range (no fix released yet).  It must produce '>= introduced'
    and not be silently dropped.
    """
    entry = {
        "purl": "pkg:pypi/some-lib",
        "name": "some-lib",
        "ecosystem": "PyPI",
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "2.15.0"}],
            }
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.affected_range() == ">= 2.15.0"


def test_match_merges_introduced_only_entry():
    """
    When merging multiple matching entries, an entry with only 'introduced'
    (no fix released) must be included in the merged range groups.
    """
    from apps.ace.version import (
        OsvStatus,
        determine_status,
        parse_version_range_or,
    )

    upstream_purls = [
        {
            "purl": "pkg:maven/com.example/mylib",
            "name": "mylib",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:maven/com.example/mylib",
            "name": "mylib",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.0.0"}],
                }
            ],
            "versions": [],
        },
    ]
    info = match_component_to_upstream("mylib", upstream_purls)
    assert info is not None
    range_str = info.affected_range()
    assert ">= 1.0.0, < 1.2.0" in range_str
    assert ">= 2.0.0" in range_str
    assert "||" in range_str

    constraints = parse_version_range_or(range_str, "maven")
    assert determine_status("1.1.0", constraints) == OsvStatus.AFFECTED
    assert determine_status("2.5.0", constraints) == OsvStatus.AFFECTED
    assert determine_status("1.3.0", constraints) == OsvStatus.NOT_AFFECTED


def test_unbounded_range_group_not_filtered():
    """
    An entry with introduced=0 and no fixed/last_affected represents
    'all versions affected'.  to_expr() must return '>= 0' (not None)
    so that affected_range() does not silently drop it.
    """
    entry = {
        "purl": "pkg:pypi/vuln-lib",
        "name": "vuln-lib",
        "ecosystem": "PyPI",
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}],
            }
        ],
        "versions": [],
    }
    info = osv_entry_to_package_info(entry)
    assert info.affected_range() == ">= 0"


def test_merge_unbounded_with_bounded_range():
    """
    When merging an unbounded entry (introduced=0, no fix) with a bounded
    entry, versions below the bounded interval must still be AFFECTED
    because the unbounded range covers all versions.
    """
    from apps.ace.version import (
        OsvStatus,
        determine_status,
        parse_version_range_or,
    )

    upstream_purls = [
        {
            "purl": "pkg:pypi/vuln-lib",
            "name": "vuln-lib",
            "ecosystem": "PyPI",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:pypi/vuln-lib",
            "name": "vuln-lib",
            "ecosystem": "PyPI",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0"}],
                }
            ],
            "versions": [],
        },
    ]
    info = match_component_to_upstream("vuln-lib", upstream_purls)
    assert info is not None
    range_str = info.affected_range()
    assert ">= 0" in range_str
    assert ">= 2.0.0, < 2.5.0" in range_str

    constraints = parse_version_range_or(range_str, "pypi")
    # 0.5.0 is below the bounded range but inside the unbounded one → AFFECTED
    assert determine_status("0.5.0", constraints) == OsvStatus.AFFECTED
    # 2.3.0 is inside the bounded range → AFFECTED
    assert determine_status("2.3.0", constraints) == OsvStatus.AFFECTED


def test_match_mixed_ecosystems_not_merged():
    """
    When ecosystem is not specified, same-name entries from different ecosystems
    must not be merged together — only entries matching the first match's
    ecosystem are included, so version comparison uses the correct algorithm.
    """
    upstream_purls = [
        {
            "purl": "pkg:maven/com.example/demo",
            "name": "demo",
            "ecosystem": "Maven",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "3.0"}, {"fixed": "4.0"}],
                }
            ],
            "versions": [],
        },
        {
            "purl": "pkg:npm/demo",
            "name": "demo",
            "ecosystem": "npm",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1.0"}],
                }
            ],
            "versions": [],
        },
    ]
    info = match_component_to_upstream("demo", upstream_purls)
    assert info is not None
    # Only the first ecosystem (Maven) entries should be included
    assert info.ecosystem == "maven"
    assert "||" not in (info.affected_range() or "")
