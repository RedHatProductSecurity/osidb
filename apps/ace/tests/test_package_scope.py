"""OSIDB-5450: Package scope is a metadata-driven resolution rule."""

import pytest

from apps.ace.constants import LABEL_MANUAL_TRIAGE
from apps.ace.tasks import _sync_affects_from_results
from collectors.component_mapping.core import sync_component_mapping
from osidb.models import Impact
from osidb.models.affect import Affect
from osidb.models.flaw.label import WorkflowLabel
from osidb.tests.factories import FlawFactory, PsModuleFactory, PsUpdateStreamFactory

pytestmark = [pytest.mark.unit, pytest.mark.django_db]


@pytest.fixture(params=["rhel-6-els", "example-1-restricted"])
def scoped_stream(request):
    """Exercise the same policy for RHEL 6 ELS and an unrelated stream."""
    module = PsModuleFactory()
    stream = PsUpdateStreamFactory(name=request.param, ps_module=module)
    module.default_ps_update_streams.add(stream)
    return stream


@pytest.fixture
def scope_data(scoped_stream):
    """Import an exhaustive list already expanded by the upstream data source."""
    sync_component_mapping(
        {
            "package_scope": {
                scoped_stream.name: [
                    "openssl",
                    "krb5-libs",
                    "krb5",
                    "krb5-workstation",
                    "vim-enhanced",
                    "vim",
                    "vim-common",
                    "yum",
                    "MAKEDEV",
                ],
            }
        }
    )


@pytest.mark.parametrize(
    "impact", [Impact.LOW, Impact.MODERATE, Impact.IMPORTANT, Impact.CRITICAL]
)
def test_excluded_perl_dbi_is_ooss(scoped_stream, scope_data, result, impact):
    """Exclude the downstream package at every impact, regardless of CVE naming."""
    flaw = FlawFactory(components=["DBI"], impact=impact)
    stats = _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609-4.el6?arch=src")],
        flaw_component="DBI",
    )
    affect = flaw.affects.get()
    assert stats["created"] == 1
    assert affect.ps_component == "perl-DBI"
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.OOSS
    assert "inclusion list" in affect.affectedness_explanation


@pytest.mark.parametrize(
    "component",
    ["openssl", "krb5", "krb5-workstation", "vim", "vim-common", "yum", "MAKEDEV"],
)
def test_included_families_keep_normal_resolution(
    scoped_stream, scope_data, result, component
):
    """Included source and binary names retain normal delegated resolution."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw, [result(scoped_stream.name, f"pkg:rpm/redhat/{component}@1.0?arch=src")]
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.DELEGATED


@pytest.mark.parametrize("apply_labels", [True, False])
def test_unconfigured_stream_keeps_normal_resolution(
    scoped_stream, result, apply_labels
):
    """Absent scope metadata leaves the existing resolution rules in control."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609?arch=src")],
        apply_labels=apply_labels,
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.DELEGATED
    assert not WorkflowLabel.objects.filter(
        flaw=flaw, name=LABEL_MANUAL_TRIAGE
    ).exists()


def test_exclusion_precedes_missing_tracker_streams(scoped_stream, scope_data, result):
    """Package exclusion takes precedence over the missing-tracker fallback."""
    scoped_stream.ps_module.default_ps_update_streams.clear()
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw, [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609?arch=src")]
    )
    assert flaw.affects.get().resolution == Affect.AffectResolution.OOSS


def test_osv_missing_version_remains_unknown(
    scoped_stream, scope_data, result, upstream_purls_openssl_rpm
):
    """Package scope cannot resolve an affect whose version is unknown."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/openssl?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.NEW
    assert affect.resolution == Affect.AffectResolution.NOVALUE


@pytest.mark.parametrize("component", ["openssl", "perl-DBI"])
@pytest.mark.parametrize("apply_labels", [True, False])
def test_osv_unknown_remains_manual(
    scoped_stream,
    scope_data,
    result,
    upstream_purls_openssl_rpm,
    component,
    apply_labels,
):
    """Indeterminate version checks stay NEW regardless of package scope."""
    upstream = upstream_purls_openssl_rpm[0]
    upstream["name"] = component
    upstream["purl"] = f"pkg:rpm/redhat/{component}"
    upstream["ranges"][0]["events"][1]["fixed"] = "invalid version"
    flaw = FlawFactory(components=[component], impact=Impact.IMPORTANT)

    stats = _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, f"pkg:rpm/redhat/{component}@1.0?arch=src")],
        flaw_component=component,
        upstream_purls=upstream_purls_openssl_rpm,
        apply_labels=apply_labels,
    )

    affect = flaw.affects.get()
    assert stats["created"] == 1
    assert stats["marked_notaffected"] == 0
    assert affect.assist_meta["osv_status"] == "unknown"
    assert affect.assist_meta["osv_version_checked"] == "1.0"
    assert affect.affectedness == Affect.AffectAffectedness.NEW
    assert affect.resolution == Affect.AffectResolution.NOVALUE
    assert (
        WorkflowLabel.objects.filter(flaw=flaw, name=LABEL_MANUAL_TRIAGE).exists()
        == apply_labels
    )


def test_scope_does_not_apply_to_other_streams(scope_data, result):
    """A configured scope only restricts its own update stream."""
    module = PsModuleFactory(name="rhel-9")
    stream = PsUpdateStreamFactory(name="rhel-9.8.z", ps_module=module)
    module.default_ps_update_streams.add(stream)
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw, [result(stream.name, "pkg:rpm/redhat/perl-DBI@1.0?arch=src")]
    )
    assert flaw.affects.get().resolution == Affect.AffectResolution.DELEGATED


def test_osv_notaffected_precedes_exclusion(
    scoped_stream, result, upstream_purls_openssl_rpm
):
    """A known fixed version stays NOTAFFECTED even when scope excludes it."""
    sync_component_mapping({"package_scope": {scoped_stream.name: []}})
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/openssl@3.0.10?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.NOTAFFECTED
    assert affect.resolution == Affect.AffectResolution.NOVALUE


def test_existing_affect_not_rewritten(scoped_stream, scope_data, result):
    """Rerunning ACE preserves an existing analyst resolution."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    results = [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609?arch=src")]
    _sync_affects_from_results(flaw, results)
    affect = flaw.affects.get()
    # Simulate an existing analyst decision without invoking save-side effects.
    Affect.objects.filter(pk=affect.pk).update(
        resolution=Affect.AffectResolution.DELEGATED
    )
    stats = _sync_affects_from_results(flaw, results)
    affect.refresh_from_db()
    assert stats["skipped_existing"] == 1
    assert affect.resolution == Affect.AffectResolution.DELEGATED


def test_explicit_empty_scope_excludes_all(scoped_stream, result):
    """An explicitly empty list differs from an unconfigured stream."""
    sync_component_mapping({"package_scope": {scoped_stream.name: []}})
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw, [result(scoped_stream.name, "pkg:rpm/redhat/openssl@1.0?arch=src")]
    )
    assert flaw.affects.get().resolution == Affect.AffectResolution.OOSS


@pytest.mark.parametrize("missing", ["stream", "module"])
@pytest.mark.parametrize("apply_labels", [True, False])
def test_unresolved_affects_get_manual_triage(result, missing, apply_labels):
    """Any unresolved stream can require triage, respecting the label opt-out."""
    stream_name = "example-1-unresolved"
    if missing == "module":
        PsUpdateStreamFactory(name=stream_name, ps_module=None)
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(stream_name, "pkg:rpm/redhat/openssl@1.0?arch=src")],
        apply_labels=apply_labels,
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.NEW
    assert affect.resolution == Affect.AffectResolution.NOVALUE
    assert (
        WorkflowLabel.objects.filter(flaw=flaw, name=LABEL_MANUAL_TRIAGE).exists()
        == apply_labels
    )


@pytest.mark.parametrize("configured", [True, False])
def test_missing_component_scope_is_unknown(scoped_stream, configured):
    """Scope resolution handles an unsaved affect without a component."""
    if configured:
        sync_component_mapping({"package_scope": {scoped_stream.name: ["openssl"]}})
    affect = Affect(
        flaw=FlawFactory(impact=Impact.IMPORTANT),
        ps_update_stream=scoped_stream.name,
        ps_component=None,
    )
    affect.auto_resolve()
    if configured:
        assert affect.affectedness == Affect.AffectAffectedness.NEW
        assert affect.resolution == Affect.AffectResolution.NOVALUE
    else:
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.DELEGATED
