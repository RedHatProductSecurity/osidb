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


@pytest.fixture
def upstream_purls_perl_dbi(upstream_purls_openssl_rpm):
    """Match the CVE's DBI name to an affected downstream perl-DBI RPM."""
    upstream_purls_openssl_rpm[0].update(
        name="DBI", purl="pkg:rpm/redhat/perl-DBI", ecosystem="rpm"
    )
    return upstream_purls_openssl_rpm


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
def test_excluded_perl_dbi_is_ooss(
    scoped_stream, scope_data, result, upstream_purls_perl_dbi, impact
):
    """Exclude the downstream package at every impact, regardless of CVE naming."""
    flaw = FlawFactory(components=["DBI"], impact=impact)
    stats = _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609-4.el6?arch=src")],
        flaw_component="DBI",
        upstream_purls=upstream_purls_perl_dbi,
    )
    affect = flaw.affects.get()
    assert stats["created"] == 1
    assert affect.ps_component == "perl-DBI"
    assert affect.assist_meta["osv_status"] == "affected"
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.OOSS
    assert "inclusion list" in affect.affectedness_explanation


@pytest.mark.parametrize(
    "component",
    ["openssl", "krb5", "krb5-workstation", "vim", "vim-common", "yum", "MAKEDEV"],
)
def test_included_families_keep_normal_resolution(
    scoped_stream, scope_data, result, upstream_purls_openssl_rpm, component
):
    """Included source and binary names retain normal delegated resolution."""
    upstream_purls_openssl_rpm[0].update(
        name=component, purl=f"pkg:rpm/redhat/{component}"
    )
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, f"pkg:rpm/redhat/{component}@1.0?arch=src")],
        flaw_component=component,
        upstream_purls=upstream_purls_openssl_rpm,
    )
    affect = flaw.affects.get()
    assert affect.assist_meta["osv_status"] == "affected"
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.DELEGATED


@pytest.mark.parametrize("apply_labels", [True, False])
def test_unconfigured_stream_keeps_normal_resolution(
    scoped_stream, result, upstream_purls_perl_dbi, apply_labels
):
    """Absent scope metadata leaves the existing resolution rules in control."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609?arch=src")],
        flaw_component="DBI",
        upstream_purls=upstream_purls_perl_dbi,
        apply_labels=apply_labels,
    )
    affect = flaw.affects.get()
    assert affect.assist_meta["osv_status"] == "affected"
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.DELEGATED
    assert not WorkflowLabel.objects.filter(
        flaw=flaw, name=LABEL_MANUAL_TRIAGE
    ).exists()


def test_exclusion_precedes_missing_tracker_streams(
    scoped_stream, scope_data, result, upstream_purls_perl_dbi
):
    """Package exclusion takes precedence over the missing-tracker fallback."""
    scoped_stream.ps_module.default_ps_update_streams.clear()
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609?arch=src")],
        flaw_component="DBI",
        upstream_purls=upstream_purls_perl_dbi,
    )
    assert flaw.affects.get().resolution == Affect.AffectResolution.OOSS


@pytest.mark.parametrize("components", [[], ["krb5"]])
@pytest.mark.parametrize("apply_labels", [True, False])
def test_exclusion_precedes_missing_module(
    scoped_stream, result, upstream_purls_openssl_rpm, components, apply_labels
):
    """An explicit exclusion resolves without module-dependent fallback rules."""
    scoped_stream.ps_module = None
    scoped_stream.save()
    sync_component_mapping({"package_scope": {scoped_stream.name: components}})
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    stats = _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/openssl@1.0?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
        apply_labels=apply_labels,
    )
    affect = flaw.affects.get()
    assert stats["created"] == 1
    assert affect.assist_meta["osv_status"] == "affected"
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.OOSS
    assert "inclusion list" in affect.affectedness_explanation
    assert not WorkflowLabel.objects.filter(
        flaw=flaw, name=LABEL_MANUAL_TRIAGE
    ).exists()


@pytest.mark.parametrize("components", [["openssl"], []])
def test_osv_missing_version_remains_unknown(
    scoped_stream, result, upstream_purls_openssl_rpm, components
):
    """Package scope cannot resolve an affect whose version is unknown."""
    sync_component_mapping({"package_scope": {scoped_stream.name: components}})
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/openssl?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
    )
    affect = flaw.affects.get()
    assert affect.assist_meta["osv_status"] == "no_version"
    assert affect.affectedness == Affect.AffectAffectedness.NEW
    assert affect.resolution == Affect.AffectResolution.NOVALUE
    assert WorkflowLabel.objects.filter(flaw=flaw, name=LABEL_MANUAL_TRIAGE).exists()


def test_scope_does_not_apply_to_other_streams(
    scope_data, result, upstream_purls_perl_dbi
):
    """A configured scope only restricts its own update stream."""
    module = PsModuleFactory(name="rhel-9")
    stream = PsUpdateStreamFactory(name="rhel-9.8.z", ps_module=module)
    module.default_ps_update_streams.add(stream)
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(stream.name, "pkg:rpm/redhat/perl-DBI@1.0?arch=src")],
        flaw_component="DBI",
        upstream_purls=upstream_purls_perl_dbi,
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


def test_existing_affect_not_rewritten(
    scoped_stream, scope_data, result, upstream_purls_perl_dbi
):
    """Rerunning ACE preserves an existing analyst resolution."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    results = [result(scoped_stream.name, "pkg:rpm/redhat/perl-DBI@1.609?arch=src")]
    _sync_affects_from_results(
        flaw, results, flaw_component="DBI", upstream_purls=upstream_purls_perl_dbi
    )
    affect = flaw.affects.get()
    assert affect.assist_meta["osv_status"] == "affected"
    assert affect.resolution == Affect.AffectResolution.OOSS
    # Simulate an existing analyst decision without invoking save-side effects.
    Affect.objects.filter(pk=affect.pk).update(
        resolution=Affect.AffectResolution.DELEGATED
    )
    stats = _sync_affects_from_results(
        flaw, results, flaw_component="DBI", upstream_purls=upstream_purls_perl_dbi
    )
    affect.refresh_from_db()
    assert stats["skipped_existing"] == 1
    assert affect.resolution == Affect.AffectResolution.DELEGATED


def test_explicit_empty_scope_excludes_all(
    scoped_stream, result, upstream_purls_openssl_rpm
):
    """An explicitly empty list differs from an unconfigured stream."""
    sync_component_mapping({"package_scope": {scoped_stream.name: []}})
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(scoped_stream.name, "pkg:rpm/redhat/openssl@1.0?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
    )
    assert flaw.affects.get().resolution == Affect.AffectResolution.OOSS


@pytest.mark.parametrize("missing", ["stream", "module"])
@pytest.mark.parametrize("apply_labels", [True, False])
@pytest.mark.parametrize("configured", [True, False])
def test_unresolved_affects_get_manual_triage(
    result, upstream_purls_openssl_rpm, missing, apply_labels, configured
):
    """Any unresolved stream can require triage, respecting the label opt-out."""
    stream_name = "example-1-unresolved"
    if missing == "module":
        PsUpdateStreamFactory(name=stream_name, ps_module=None)
    if configured:
        # Scope data cannot establish an unknown stream. Included components
        # still need module metadata to apply the normal resolution rules.
        components = [] if missing == "stream" else ["openssl"]
        sync_component_mapping({"package_scope": {stream_name: components}})
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result(stream_name, "pkg:rpm/redhat/openssl@1.0?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
        apply_labels=apply_labels,
    )
    affect = flaw.affects.get()
    assert affect.assist_meta["osv_status"] == "affected"
    assert affect.affectedness == Affect.AffectAffectedness.NEW
    assert affect.resolution == Affect.AffectResolution.NOVALUE
    assert (
        WorkflowLabel.objects.filter(flaw=flaw, name=LABEL_MANUAL_TRIAGE).exists()
        == apply_labels
    )
