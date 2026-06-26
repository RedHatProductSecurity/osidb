"""Tests for apps.ace.tasks.

lib_newtopia is an optional dependency that may not be installed in the test
environment. All tests use the ``ace_enabled`` fixture to patch
``HAS_LIB_NEWTOPIA=True`` and monkeypatch ``NewtopiaQuerier`` directly so that
the real network-calling library is never invoked.
"""

from collections import defaultdict
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from packageurl import PackageURL

from apps.ace.tasks import sync_flaw_affects_from_newcli
from osidb.models.affect import Affect
from osidb.tests.factories import (
    FlawFactory,
    PsUpdateStreamFactory,
    UpstreamDataFactory,
)

pytestmark = pytest.mark.unit


def test_sync_creates_one_affect_per_result(
    monkeypatch, ace_enabled, urllib3_results, mock_querier
):
    flaw = FlawFactory(components=["urllib3"])
    expected_purls = {
        PackageURL.from_string(r.purls[0]).to_string() for r in urllib3_results
    }

    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"urllib3": urllib3_results})
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    n = len(urllib3_results)
    assert stats == {
        "created": n,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
    }
    assert flaw.affects.count() == n
    assert {
        str(a.purl) for a in flaw.affects.filter(ps_update_stream="hummingbird-1")
    } == expected_purls


def test_sync_runs_query_per_flaw_component(
    monkeypatch, ace_enabled, urllib3_results, openssl_results
):
    """
    Each flaw component gets its own NewtopiaQuerier.search() call; results are
    merged. The openssl results share one PURL with urllib3 results, so that
    entry is skipped as already existing.
    """
    flaw = FlawFactory(components=["urllib3", "openssl"])
    querier_calls = []

    def _search(terms, **kwargs):
        component = terms[0]
        querier_calls.append(component)
        mapping = {"urllib3": urllib3_results, "openssl": openssl_results}
        qs = MagicMock()
        qs.filter.return_value.all.return_value = mapping.get(component, [])
        return qs

    mock_nq = MagicMock()
    mock_nq.return_value.search.side_effect = _search
    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_nq)

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert querier_calls == ["urllib3", "openssl"]
    n_urllib3 = len(urllib3_results)
    assert stats == {
        "created": n_urllib3,
        "skipped": 0,
        "skipped_existing": 1,
        "marked_notaffected": 0,
    }
    assert flaw.affects.count() == n_urllib3


def test_sync_skips_existing_on_second_run(
    monkeypatch, ace_enabled, urllib3_results, mock_querier
):
    flaw = FlawFactory(components=["urllib3"])
    n = len(urllib3_results)

    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"urllib3": urllib3_results})
    )

    first = sync_flaw_affects_from_newcli(str(flaw.uuid))
    second = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert first == {
        "created": n,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
    }
    assert second == {
        "created": 0,
        "skipped": 0,
        "skipped_existing": n,
        "marked_notaffected": 0,
    }


def test_sync_no_components_raises(monkeypatch, ace_enabled):
    flaw = FlawFactory(components=[])

    with pytest.raises(ValueError, match="no non-empty components"):
        sync_flaw_affects_from_newcli(str(flaw.uuid))


def test_sync_includes_builds_as_affects(
    monkeypatch, ace_enabled, ostree_results, mock_querier
):
    """Both build and dep entries from ostree result in affects."""
    flaw = FlawFactory(components=["ostree"])

    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"ostree": ostree_results})
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats == {
        "created": 2,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
    }
    assert flaw.affects.count() == 2

    expected = {PackageURL.from_string(r.purls[0]).to_string() for r in ostree_results}
    assert {
        str(a.purl) for a in flaw.affects.filter(ps_update_stream="hummingbird-1")
    } == expected


def test_sync_multi_stream_with_duplicate(
    monkeypatch, ace_enabled, openssl_multi_results, mock_querier
):
    """
    Multiple entries across different streams, including a same-stream duplicate
    (rhel-9.8.z / openssl appears twice — same ps_update_stream and ps_component
    so the second is skipped_existing).

    Layout (6 entries):
    - hummingbird-1 / openssl       → created
    - rhel-9.8.z   / openssl 3.5.1 → created  (first encounter)
    - rhel-9.8.z   / openssl 3.5.5 → skipped_existing (same stream+component)
    - rhel-8.8.0.z / openssl 1.1.1k→ created
    - hummingbird-1 / bootc         → created
    - hummingbird-1 / chunkah       → created
    """
    flaw = FlawFactory(components=["openssl"])

    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier",
        mock_querier({"openssl": openssl_multi_results}),
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats == {
        "created": 5,
        "skipped": 0,
        "skipped_existing": 1,
        "marked_notaffected": 0,
    }
    assert flaw.affects.count() == 5

    stored_by_stream = defaultdict(set)
    for a in flaw.affects.all():
        stored_by_stream[a.ps_update_stream].add(
            PackageURL.from_string(str(a.purl)).name
        )

    assert stored_by_stream["hummingbird-1"] == {"openssl", "bootc", "chunkah"}
    assert stored_by_stream["rhel-9.8.z"] == {"openssl"}
    assert stored_by_stream["rhel-8.8.0.z"] == {"openssl"}

    # Second run: all 6 entries find existing affects; duplicate also matches → 6 skipped
    stats2 = sync_flaw_affects_from_newcli(str(flaw.uuid))
    assert stats2 == {
        "created": 0,
        "skipped": 0,
        "skipped_existing": 6,
        "marked_notaffected": 0,
    }
    assert flaw.affects.count() == 5


def test_sync_no_op_when_lib_newtopia_missing(monkeypatch):
    flaw = FlawFactory(components=["openssl"])

    monkeypatch.setattr("apps.ace.tasks.HAS_LIB_NEWTOPIA", False)
    result = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert result == {"skipped_reason": "lib_newtopia not installed"}
    assert flaw.affects.count() == 0


def test_sync_sets_created_by_and_updated_by(
    monkeypatch, ace_enabled, urllib3_results, mock_querier
):
    """ACE-created affects must have created_by and updated_by set to AffectCreationEngine."""
    flaw = FlawFactory(components=["urllib3"])
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"urllib3": urllib3_results})
    )

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    for affect in flaw.affects.all():
        assert affect.created_by == "AffectCreationEngine"
        assert affect.updated_by == "AffectCreationEngine"


def test_sync_sets_assist_meta(monkeypatch, ace_enabled, urllib3_results, mock_querier):
    """ACE-created affects must have assist_meta populated with expected keys."""
    flaw = FlawFactory(components=["urllib3"])
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"urllib3": urllib3_results})
    )

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    for affect in flaw.affects.all():
        meta = affect.assist_meta
        assert isinstance(meta, dict)
        assert "tool_name" in meta
        assert "tool_input" in meta
        assert "tool_output" in meta
        assert "tool_trigger" in meta
        assert "urllib3" in meta["tool_input"]
        assert "urllib3" in meta["tool_trigger"]


def test_sync_respects_ps_modules_setting(monkeypatch, ace_enabled, urllib3_results):
    monkeypatch.setenv(
        "OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES",
        '["hummingbird-1","rhel-9"]',
    )
    flaw = FlawFactory(components=["urllib3"])

    seen_filter_products = []

    def _search(terms, **kwargs):
        qs = MagicMock()

        def _filter(**fkwargs):
            seen_filter_products.append(fkwargs.get("products"))
            inner = MagicMock()
            inner.all.return_value = urllib3_results
            return inner

        qs.filter.side_effect = _filter
        return qs

    mock_nq = MagicMock()
    mock_nq.return_value.search.side_effect = _search
    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_nq)

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert seen_filter_products == [["hummingbird-1", "rhel-9"]]


# ── Version-range / OSV upstream_purls integration tests ─────────────────────


def test_sync_marks_notaffected_when_version_outside_range(
    monkeypatch, ace_enabled, mock_querier, result, upstream_purls_openssl_rpm
):
    """
    lib_newtopia returns openssl@3.5.1 but the OSV range says fixed at 3.0.9.
    The created affect must be NOTAFFECTED.
    """
    flaw = FlawFactory(components=["openssl"])
    UpstreamDataFactory(flaw=flaw, upstream_purls=upstream_purls_openssl_rpm)

    results = [
        result("rhel-9.8.z", "pkg:rpm/redhat/openssl@3.5.1-7.el9_7?arch=src"),
    ]
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"openssl": results})
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats["created"] == 1
    assert stats["marked_notaffected"] == 1
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.NOTAFFECTED


def test_sync_creates_affected_when_version_in_range(
    monkeypatch, ace_enabled, mock_querier, result, upstream_purls_openssl_rpm
):
    """
    lib_newtopia returns openssl@3.0.7 which is inside the OSV range (< 3.0.9).
    The created affect must be AFFECTED (auto_resolve applies).
    """
    PsUpdateStreamFactory(name="rhel-9.8.z")
    flaw = FlawFactory(components=["openssl"])
    UpstreamDataFactory(flaw=flaw, upstream_purls=upstream_purls_openssl_rpm)

    results = [
        result("rhel-9.8.z", "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src"),
    ]
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"openssl": results})
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats["created"] == 1
    assert stats["marked_notaffected"] == 0
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED


def test_sync_creates_affected_when_no_upstream_match(
    monkeypatch, ace_enabled, mock_querier, result
):
    """
    No upstream_purls entry matches the component name.
    Falls back to AFFECTED (current behaviour preserved).
    """
    PsUpdateStreamFactory(name="rhel-9.8.z")
    flaw = FlawFactory(components=["curl"])
    UpstreamDataFactory(
        flaw=flaw,
        upstream_purls=[
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
            }
        ],
    )

    results = [
        result("rhel-9.8.z", "pkg:rpm/redhat/curl@7.76.1-19.el9?arch=src"),
    ]
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"curl": results})
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats["created"] == 1
    assert stats["marked_notaffected"] == 0
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED


def test_sync_creates_affected_when_no_range(
    monkeypatch, ace_enabled, mock_querier, result
):
    """
    upstream_purls entry matches the component but has empty ranges.
    Falls back to AFFECTED (no range to compare against).
    """
    flaw = FlawFactory(components=["openssl"])
    UpstreamDataFactory(
        flaw=flaw,
        upstream_purls=[
            {
                "purl": "pkg:rpm/redhat/openssl",
                "name": "openssl",
                "ecosystem": "Linux",
                "ranges": [],
                "versions": [],
            }
        ],
    )

    results = [
        result("rhel-9.8.z", "pkg:rpm/redhat/openssl@3.5.1-7.el9_7?arch=src"),
    ]
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"openssl": results})
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats["created"] == 1
    assert stats["marked_notaffected"] == 0


def test_sync_assist_meta_includes_osv_fields(
    monkeypatch, ace_enabled, mock_querier, result, upstream_purls_openssl_rpm
):
    """
    Every created affect (AFFECTED or NOTAFFECTED) must have osv_* keys in assist_meta.
    """
    flaw = FlawFactory(components=["openssl"])
    UpstreamDataFactory(flaw=flaw, upstream_purls=upstream_purls_openssl_rpm)

    results = [
        result("rhel-9.8.z", "pkg:rpm/redhat/openssl@3.5.1-7.el9_7?arch=src"),
    ]
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"openssl": results})
    )

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    affect = flaw.affects.get()
    meta = affect.assist_meta
    assert meta["osv_range_used"] == "< 3.0.9"
    assert meta["osv_version_checked"] == "3.5.1-7.el9_7"
    assert meta["osv_status"] == "not_affected"


def test_sync_returns_marked_notaffected_count(
    monkeypatch, ace_enabled, mock_querier, result, upstream_purls_openssl_rpm
):
    """sync_flaw_affects_from_newcli return dict includes marked_notaffected."""
    flaw = FlawFactory(components=["openssl"])
    UpstreamDataFactory(flaw=flaw, upstream_purls=upstream_purls_openssl_rpm)

    results = [
        result("rhel-9.8.z", "pkg:rpm/redhat/openssl@3.5.1-7.el9_7?arch=src"),
        result("rhel-8.8.0.z", "pkg:rpm/redhat/openssl@3.5.1-7.el8?arch=src"),
    ]
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"openssl": results})
    )

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats == {
        "created": 2,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 2,
    }


# ── Ecosystem scoping tests ────────────────────────────────────────────────────


def test_sync_passes_ecosystem_to_newtopia(monkeypatch, ace_enabled):
    """When UpstreamData exists for a flaw, the ecosystem derived from its PURLs
    is forwarded to NewtopiaQuerier.search()."""
    flaw = FlawFactory(components=["redis"])
    UpstreamDataFactory(
        flaw=flaw,
        upstream_purls=[
            {
                "purl": "pkg:npm/redis",
                "name": "redis",
                "ecosystem": "npm",
                "ranges": [],
                "versions": [],
            }
        ],
    )

    search_kwargs = []

    def _search(terms, **kwargs):
        search_kwargs.append(kwargs)
        qs = MagicMock()
        qs.filter.return_value.all.return_value = []
        return qs

    mock_nq = MagicMock()
    mock_nq.return_value.search.side_effect = _search
    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_nq)

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert len(search_kwargs) == 1
    assert search_kwargs[0]["ecosystem"] == "npm"


def test_sync_no_ecosystem_when_no_upstream_data(monkeypatch, ace_enabled):
    """Without UpstreamData the ecosystem falls back to an empty string."""
    flaw = FlawFactory(components=["curl"])

    search_kwargs = []

    def _search(terms, **kwargs):
        search_kwargs.append(kwargs)
        qs = MagicMock()
        qs.filter.return_value.all.return_value = []
        return qs

    mock_nq = MagicMock()
    mock_nq.return_value.search.side_effect = _search
    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_nq)

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert len(search_kwargs) == 1
    assert search_kwargs[0]["ecosystem"] == ""


def test_sync_queries_each_ecosystem_for_component(monkeypatch, ace_enabled):
    """When a component maps to multiple ecosystems, lib-newtopia is queried
    once per ecosystem and all results are accumulated."""
    flaw = FlawFactory(components=["redis"])
    UpstreamDataFactory(
        flaw=flaw,
        upstream_purls=[
            {
                "purl": "pkg:npm/redis",
                "name": "redis",
                "ecosystem": "npm",
                "ranges": [],
                "versions": [],
            },
            {
                "purl": "pkg:pypi/redis",
                "name": "redis",
                "ecosystem": "PyPI",
                "ranges": [],
                "versions": [],
            },
        ],
    )

    search_kwargs = []

    def _search(terms, **kwargs):
        search_kwargs.append(kwargs)
        eco = kwargs.get("ecosystem", "")
        qs = MagicMock()
        qs.filter.return_value.all.return_value = [
            SimpleNamespace(
                ps_update_stream="hummingbird-1",
                purls=[
                    f"pkg:oci/redis-{eco}?repository_url=registry.redhat.io/redis-{eco}"
                ],
                build_nvr=None,
            )
        ]
        return qs

    mock_nq = MagicMock()
    mock_nq.return_value.search.side_effect = _search
    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_nq)

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert len(search_kwargs) == 2
    assert search_kwargs[0]["ecosystem"] == "npm"
    assert search_kwargs[1]["ecosystem"] == "pypi"
    assert stats["created"] == 2
