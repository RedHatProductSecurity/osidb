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

from apps.ace.constants import (
    LABEL_AUTO_AFFECTS,
    LABEL_AUTO_REJECTED,
    LABEL_MANUAL_TRIAGE,
    LABEL_POTENTIAL_REJECTION,
)
from apps.ace.tasks import (
    PreFilterAction,
    SpecialWorkflow,
    _is_go_stdlib_component,
    _pre_filter_component,
    _resolve_component,
    sync_flaw_affects_from_newcli,
)
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
        "pre_filtered": 0,
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
        "pre_filtered": 0,
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
        "pre_filtered": 0,
    }
    assert second == {
        "created": 0,
        "skipped": 0,
        "skipped_existing": n,
        "marked_notaffected": 0,
        "pre_filtered": 0,
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
        "pre_filtered": 0,
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
        "pre_filtered": 0,
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
        "pre_filtered": 0,
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
        "pre_filtered": 0,
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


# ── Pre-filter tests ──────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_pre_filter_blocklist_skips():
    from collectors.component_mapping.models import BlocklistEntry

    BlocklistEntry.objects.create(name="gitlab", reason="Not shipped by Red Hat")
    flaw = FlawFactory(components=["GitLab"], embargoed=False)

    result = _pre_filter_component(flaw, "GitLab", "")

    assert result.action is PreFilterAction.SKIP
    assert result.label == LABEL_AUTO_REJECTED
    assert "Blocked" in result.reason


@pytest.mark.django_db
def test_pre_filter_allows_non_blocked():
    from collectors.component_mapping.models import StrictPackage

    StrictPackage.objects.create(name="openssl", repos=["rhel-9"])
    flaw = FlawFactory(components=["openssl"], embargoed=False)

    result = _pre_filter_component(flaw, "openssl", "")

    assert result.action is PreFilterAction.SEARCH
    assert result.label == LABEL_AUTO_AFFECTS
    assert "openssl" in result.resolved_names


@pytest.mark.django_db
def test_resolve_component_from_db():
    from collectors.component_mapping.models import ComponentMapEntry

    ComponentMapEntry.objects.create(name="Django", upstream_packages="python-django")

    assert _resolve_component("Django") == (["python-django"], True)
    assert _resolve_component("django") == (["python-django"], True)


@pytest.mark.django_db
def test_resolve_component_list_mapping():
    from collectors.component_mapping.models import ComponentMapEntry

    ComponentMapEntry.objects.create(
        name="Kafka", upstream_packages=["kafka", "kafka-clients"]
    )

    assert _resolve_component("Kafka") == (["kafka", "kafka-clients"], True)


@pytest.mark.django_db
def test_resolve_component_fallback_normalizes():
    assert _resolve_component("JetBrains YouTrack") == (["JetBrains-YouTrack"], False)


@pytest.mark.django_db
def test_sync_skips_blocked_component(monkeypatch, ace_enabled, mock_querier):
    from collectors.component_mapping.models import BlocklistEntry

    BlocklistEntry.objects.create(name="gitlab", reason="Not shipped")
    flaw = FlawFactory(components=["GitLab"], embargoed=False)

    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_querier({"gitlab": []}))

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats["created"] == 0
    assert flaw.labels_v2.filter(name=LABEL_AUTO_REJECTED).exists()


@pytest.mark.django_db
def test_sync_blocked_component_skips_entire_flaw(
    monkeypatch, ace_enabled, mock_querier
):
    """If any component is blocklisted, the entire flaw is skipped."""
    from collectors.component_mapping.models import BlocklistEntry

    BlocklistEntry.objects.create(name="gitlab", reason="Not shipped")
    flaw = FlawFactory(components=["GitLab", "openssl"], embargoed=False)

    search_calls = []

    def _search(terms, **kwargs):
        search_calls.append(terms[0])
        qs = MagicMock()
        qs.filter.return_value.all.return_value = []
        return qs

    mock_nq = MagicMock()
    mock_nq.return_value.search.side_effect = _search
    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_nq)

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats["created"] == 0
    assert stats["pre_filtered"] == 1
    assert search_calls == []
    assert flaw.labels_v2.filter(name=LABEL_AUTO_REJECTED).exists()
    assert not flaw.labels_v2.filter(name=LABEL_AUTO_AFFECTS).exists()


@pytest.mark.django_db
def test_sync_resolves_component_before_search(
    monkeypatch, ace_enabled, urllib3_results
):
    from collectors.component_mapping.models import (
        ComponentMapEntry,
        StrictPackage,
        VerifiedMapping,
    )

    ComponentMapEntry.objects.create(name="Django", upstream_packages="python-django")
    VerifiedMapping.objects.create(name="Django", upstream_package="python-django")
    StrictPackage.objects.create(name="python-django", repos=[])
    flaw = FlawFactory(components=["Django"], embargoed=False)

    search_terms = []

    def _search(terms, **kwargs):
        search_terms.append(terms[0])
        qs = MagicMock()
        qs.filter.return_value.all.return_value = []
        return qs

    mock_nq = MagicMock()
    mock_nq.return_value.search.side_effect = _search
    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_nq)

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert search_terms == ["python-django"]


# ── Go stdlib / Chromium detection ────────────────────────────────────────────


def test_is_go_stdlib_component_true():
    comps = ["golang", "net/http"]
    assert _is_go_stdlib_component("golang", comps) is True
    assert _is_go_stdlib_component("net/http", comps) is True


def test_is_go_stdlib_component_false():
    comps = ["golang", "net/http"]
    assert _is_go_stdlib_component("openssl", comps) is False
    assert _is_go_stdlib_component("net/http", ["net/http"]) is False
    assert (
        _is_go_stdlib_component("github.com/foo/bar", ["golang", "github.com/foo/bar"])
        is False
    )


@pytest.mark.django_db
def test_pre_filter_go_stdlib_subcomponent_special():
    flaw = FlawFactory(components=["golang", "net/http"], embargoed=False)

    result = _pre_filter_component(flaw, "net/http", "")

    assert result.action is PreFilterAction.SPECIAL
    assert result.label == LABEL_AUTO_AFFECTS
    assert result.workflow is SpecialWorkflow.GO_STDLIB


@pytest.mark.django_db
def test_pre_filter_go_stdlib_golang_skipped():
    """The 'golang' component itself is skipped — Phase 1 of the handler covers it."""
    flaw = FlawFactory(components=["golang", "net/http"], embargoed=False)

    result = _pre_filter_component(flaw, "golang", "")

    assert result.action is PreFilterAction.MANUAL


@pytest.mark.django_db
def test_pre_filter_chromium_special():
    flaw = FlawFactory(components=["chromium"], embargoed=False)

    result = _pre_filter_component(flaw, "chromium", "")

    assert result.action is PreFilterAction.SPECIAL
    assert result.label == LABEL_AUTO_AFFECTS
    assert result.workflow is SpecialWorkflow.CHROMIUM


# ── Cross-ecosystem guard ────────────────────────────────────────────────────


@pytest.mark.django_db
def test_pre_filter_cross_ecosystem_no_ecosystem():
    from collectors.component_mapping.models import CrossEcosystemName

    CrossEcosystemName.objects.create(name="redis", ecosystems=["npm", "pypi"])
    flaw = FlawFactory(components=["redis"], embargoed=False)

    result = _pre_filter_component(flaw, "redis", "")

    assert result.action is PreFilterAction.MANUAL
    assert result.label == LABEL_MANUAL_TRIAGE
    assert "ecosystems" in result.reason


@pytest.mark.django_db
def test_pre_filter_cross_ecosystem_with_ecosystem_proceeds():
    from collectors.component_mapping.models import CrossEcosystemName

    CrossEcosystemName.objects.create(name="redis", ecosystems=["npm", "pypi"])
    flaw = FlawFactory(components=["redis"], embargoed=False)

    result = _pre_filter_component(flaw, "redis", "npm")

    assert result.action is PreFilterAction.SEARCH


# ── Verified mapping guard ───────────────────────────────────────────────────


@pytest.mark.django_db
def test_pre_filter_unverified_mapping_manual_triage():
    from collectors.component_mapping.models import ComponentMapEntry

    ComponentMapEntry.objects.create(
        name="SomeGoLib", upstream_packages="github.com/foo/bar"
    )
    flaw = FlawFactory(components=["SomeGoLib"], embargoed=False)

    result = _pre_filter_component(flaw, "SomeGoLib", "")

    assert result.action is PreFilterAction.MANUAL
    assert result.label == LABEL_MANUAL_TRIAGE
    assert "not verified" in result.reason


@pytest.mark.django_db
def test_pre_filter_verified_mapping_proceeds():
    from collectors.component_mapping.models import ComponentMapEntry, VerifiedMapping

    ComponentMapEntry.objects.create(
        name="Vault", upstream_packages="github.com/hashicorp/vault"
    )
    VerifiedMapping.objects.create(
        name="Vault", upstream_package="github.com/hashicorp/vault"
    )
    flaw = FlawFactory(components=["Vault"], embargoed=False)

    result = _pre_filter_component(flaw, "Vault", "")

    assert result.action is PreFilterAction.SEARCH


# ── Semi-strict review ───────────────────────────────────────────────────────


@pytest.mark.django_db
def test_pre_filter_semi_strict_no_pick_manual_triage():
    from collectors.component_mapping.models import SemiStrictReviewEntry

    SemiStrictReviewEntry.objects.create(
        name="accelerator", data={"candidates": ["pkg-a", "pkg-b"], "pick": ""}
    )
    flaw = FlawFactory(components=["accelerator"], embargoed=False)

    result = _pre_filter_component(flaw, "accelerator", "")

    assert result.action is PreFilterAction.MANUAL
    assert result.label == LABEL_MANUAL_TRIAGE
    assert "ambiguous" in result.reason


@pytest.mark.django_db
def test_pre_filter_semi_strict_with_pick_uses_picked():
    from collectors.component_mapping.models import SemiStrictReviewEntry, StrictPackage

    SemiStrictReviewEntry.objects.create(
        name="accelerator", data={"candidates": ["pkg-a", "pkg-b"], "pick": "pkg-a"}
    )
    StrictPackage.objects.create(name="pkg-a", repos=[])
    flaw = FlawFactory(components=["accelerator"], embargoed=False)

    result = _pre_filter_component(flaw, "accelerator", "")

    assert result.action is PreFilterAction.SEARCH
    assert result.label == LABEL_AUTO_AFFECTS
    assert result.resolved_names == ["pkg-a"]


# ── Confidence / strict packages ─────────────────────────────────────────────


@pytest.mark.django_db
def test_pre_filter_strict_package_auto_affects():
    from collectors.component_mapping.models import StrictPackage

    StrictPackage.objects.create(name="openssl", repos=["rhel-9"])
    flaw = FlawFactory(components=["openssl"], embargoed=False)

    result = _pre_filter_component(flaw, "openssl", "")

    assert result.action is PreFilterAction.SEARCH
    assert result.label == LABEL_AUTO_AFFECTS


@pytest.mark.django_db
def test_pre_filter_non_strict_potential_rejection():
    flaw = FlawFactory(components=["unknown-pkg"], embargoed=False)

    result = _pre_filter_component(flaw, "unknown-pkg", "")

    assert result.action is PreFilterAction.SEARCH
    assert result.label == LABEL_POTENTIAL_REJECTION
    assert "Low confidence" in result.reason


def test_sync_does_not_set_impact_on_created_affects(
    monkeypatch, ace_enabled, urllib3_results, mock_querier
):
    """ACE must not set impact on automatically created affects.

    Impact is intended to be an override of the Flaw's impact set explicitly by
    humans. Automation should leave it blank so that aggregated_impact falls back
    to the parent flaw's impact instead.
    """
    flaw = FlawFactory(components=["urllib3"])
    monkeypatch.setattr(
        "apps.ace.tasks.NewtopiaQuerier", mock_querier({"urllib3": urllib3_results})
    )

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    for affect in flaw.affects.all():
        assert affect.impact == ""


# ── Chromium workflow ─────────────────────────────────────────────────────────


def test_handle_chromium_creates_affects(chromium_streams):
    from apps.ace.tasks import _handle_chromium

    flaw = FlawFactory(components=["chromium"], embargoed=False)

    stats = _handle_chromium(flaw)

    assert stats["created"] == 2
    assert flaw.affects.filter(
        ps_update_stream="fedora-all", ps_component="chromium"
    ).exists()
    assert flaw.affects.filter(
        ps_update_stream="epel-all", ps_component="chromium"
    ).exists()


@pytest.mark.django_db
def test_handle_chromium_no_advisory_skips_metadata(chromium_streams):
    """Without a Chrome blog reference, affects are created but metadata is unchanged."""
    from apps.ace.tasks import _handle_chromium

    flaw = FlawFactory(components=["chromium"], embargoed=False)
    original_statement = flaw.statement
    original_title = flaw.title

    stats = _handle_chromium(flaw)

    assert stats["created"] == 2
    flaw.refresh_from_db()
    assert flaw.statement == original_statement
    assert flaw.title == original_title
    assert flaw.cvss_scores.count() == 0


@pytest.mark.django_db
def test_handle_chromium_with_advisory(monkeypatch, chromium_streams):
    """With a parseable advisory, statement/title/CVSS are set."""
    from apps.ace.constants import CHROMIUM_STATEMENT
    from apps.ace.tasks import _handle_chromium

    flaw = FlawFactory(components=["chromium"], impact="LOW", embargoed=False)

    monkeypatch.setattr(
        "apps.ace.tasks._parse_chrome_advisory",
        lambda url, cve: {
            "title": "chromium-browser: Use after free in USB",
            "cve_description": "A use after free flaw was found in USB.",
            "impact": "IMPORTANT",
        },
    )
    # Add a reference so the advisory path triggers
    from osidb.models.flaw.reference import FlawReference

    FlawReference(
        flaw=flaw,
        url="https://chromereleases.googleblog.com/2025/04/test.html",
        type=FlawReference.FlawReferenceType.EXTERNAL,
        acl_read=flaw.acl_read,
        acl_write=flaw.acl_write,
    ).save(raise_validation_error=False)

    stats = _handle_chromium(flaw)

    flaw.refresh_from_db()
    assert stats["created"] == 2
    assert flaw.statement == CHROMIUM_STATEMENT
    assert flaw.title == "chromium-browser: Use after free in USB"
    assert flaw.cve_description == "A use after free flaw was found in USB."
    assert flaw.cvss_scores.filter(issuer="RH", version="V3").exists()


@pytest.mark.django_db
def test_handle_chromium_idempotent(chromium_streams):
    from apps.ace.tasks import _handle_chromium

    flaw = FlawFactory(components=["chromium"], embargoed=False)

    first = _handle_chromium(flaw)
    second = _handle_chromium(flaw)

    assert first["created"] == 2
    assert second["created"] == 0
    assert flaw.affects.count() == 2


@pytest.mark.django_db
def test_handle_chromium_skips_cvss_if_exists(monkeypatch, chromium_streams):
    from apps.ace.tasks import _handle_chromium
    from osidb.models.flaw.cvss import FlawCVSS
    from osidb.models.flaw.reference import FlawReference

    flaw = FlawFactory(components=["chromium"], impact="IMPORTANT", embargoed=False)

    FlawCVSS.objects.create_cvss(
        flaw=flaw,
        issuer=FlawCVSS.CVSSIssuer.REDHAT,
        version=FlawCVSS.CVSSVersion.VERSION3,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        acl_read=flaw.acl_read,
        acl_write=flaw.acl_write,
    ).save()

    monkeypatch.setattr(
        "apps.ace.tasks._parse_chrome_advisory",
        lambda url, cve: {
            "title": "test",
            "cve_description": "test",
            "impact": "IMPORTANT",
        },
    )
    FlawReference(
        flaw=flaw,
        url="https://chromereleases.googleblog.com/2025/04/test.html",
        type=FlawReference.FlawReferenceType.EXTERNAL,
        acl_read=flaw.acl_read,
        acl_write=flaw.acl_write,
    ).save(raise_validation_error=False)

    _handle_chromium(flaw)

    assert (
        flaw.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
        ).count()
        == 1
    )


# ── Go stdlib workflow ────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_handle_go_stdlib_preserves_existing_affects(
    monkeypatch, ace_enabled, mock_querier
):
    """Existing affects are preserved — no replace/delete behavior."""
    from apps.ace.tasks import _handle_go_stdlib

    flaw = FlawFactory(components=["golang", "net/http"], embargoed=False)

    existing = Affect(
        flaw=flaw,
        ps_update_stream="hummingbird-1",
        ps_component="golang-existing",
        affectedness=Affect.AffectAffectedness.NEW,
        acl_read=flaw.acl_read,
        acl_write=flaw.acl_write,
        created_by="AffectCreationEngine",
        updated_by="AffectCreationEngine",
    )
    existing.save(raise_validation_error=False)

    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_querier({}))

    _handle_go_stdlib(flaw, "net/http", ["hummingbird-1"], [])

    assert flaw.affects.filter(ps_component="golang-existing").exists()


@pytest.mark.django_db
def test_handle_go_stdlib_preserves_analyst_affects(
    monkeypatch, ace_enabled, mock_querier
):
    """Replace mode does not delete analyst-created or non-NEW affects."""
    from apps.ace.tasks import _handle_go_stdlib

    flaw = FlawFactory(components=["golang", "net/http"], embargoed=False)

    # Create an analyst-created affect (not by ACE)
    analyst_affect = Affect(
        flaw=flaw,
        ps_update_stream="rhel-9.6.z",
        ps_component="golang",
        affectedness=Affect.AffectAffectedness.AFFECTED,
        acl_read=flaw.acl_read,
        acl_write=flaw.acl_write,
        created_by="analyst@redhat.com",
        updated_by="analyst@redhat.com",
    )
    analyst_affect.save(raise_validation_error=False)

    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_querier({}))

    _handle_go_stdlib(flaw, "net/http", ["hummingbird-1"], [])

    # Analyst-created affect should be preserved
    assert flaw.affects.filter(
        ps_component="golang", created_by="analyst@redhat.com"
    ).exists()


@pytest.mark.django_db
def test_handle_go_stdlib_phase4_creates_builder_affects(
    monkeypatch, ace_enabled, mock_querier
):
    """Phase 4 creates golang-builder-container affects from PsModule active streams."""
    from apps.ace.constants import GO_STDLIB_BUILDER_PURL
    from apps.ace.tasks import _handle_go_stdlib

    flaw = FlawFactory(components=["golang", "net/http"], embargoed=False)

    monkeypatch.setattr("apps.ace.tasks.NewtopiaQuerier", mock_querier({}))

    # Create a PsModule with active streams for Phase 4
    stream1 = PsUpdateStreamFactory(name="openshift-4.16.z")
    stream2 = PsUpdateStreamFactory(name="openshift-4.17.z")
    ps_module = stream1.ps_module
    ps_module.name = "openshift-4"
    ps_module.save()

    # Link streams as active
    stream1.active_to_ps_module = ps_module
    stream1.save()
    stream2.ps_module = ps_module
    stream2.active_to_ps_module = ps_module
    stream2.save()

    _handle_go_stdlib(flaw, "net/http", ["hummingbird-1"], [])

    builder_affects = flaw.affects.filter(
        ps_component="openshift-golang-builder-container"
    )
    assert builder_affects.count() == 2
    for a in builder_affects:
        assert str(a.purl) == GO_STDLIB_BUILDER_PURL
        assert a.affectedness == Affect.AffectAffectedness.AFFECTED
        assert a.resolution == Affect.AffectResolution.DELEGATED
