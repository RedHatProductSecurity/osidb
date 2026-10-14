"""OSIDB-5450: ELS membership is a resolution rule, not a search filter."""

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
def els_stream():
    """Create the RHEL 6 ELS stream with a default tracker destination."""
    module = PsModuleFactory(name="rhel-6")
    stream = PsUpdateStreamFactory(name="rhel-6-els", ps_module=module)
    module.default_ps_update_streams.add(stream)
    return stream


@pytest.fixture
def els_data():
    """Load published names with representative binary-to-source relationships."""
    sync_component_mapping(
        {
            "rhel6_els_packages": {
                "packages": ["openssl", "krb5-libs", "vim-enhanced", "yum"],
                "source_package_aliases": {
                    "krb5-libs": "krb5",
                    "krb5-workstation": "krb5",
                    "vim-enhanced": "vim",
                    "vim-common": "vim",
                },
            }
        }
    )


@pytest.mark.parametrize(
    "impact", [Impact.LOW, Impact.MODERATE, Impact.IMPORTANT, Impact.CRITICAL]
)
def test_excluded_perl_dbi_is_ooss(els_stream, els_data, result, impact):
    """Exclude the downstream package at every impact, regardless of CVE naming."""
    flaw = FlawFactory(components=["DBI"], impact=impact)
    stats = _sync_affects_from_results(
        flaw,
        [result("rhel-6-els", "pkg:rpm/redhat/perl-DBI@1.609-4.el6?arch=src")],
        flaw_component="DBI",
    )
    affect = flaw.affects.get()
    assert stats["created"] == 1
    assert affect.ps_component == "perl-DBI"
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.OOSS
    assert "inclusion list" in affect.affectedness_explanation


@pytest.mark.parametrize(
    "component", ["openssl", "krb5", "krb5-workstation", "vim", "vim-common", "yum"]
)
def test_included_families_keep_normal_resolution(
    els_stream, els_data, result, component
):
    """Included source and binary names retain normal delegated resolution."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw, [result("rhel-6-els", f"pkg:rpm/redhat/{component}@1.0?arch=src")]
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
    assert affect.resolution == Affect.AffectResolution.DELEGATED


@pytest.mark.parametrize("apply_labels", [True, False])
def test_missing_list_is_unknown_and_manual(els_stream, result, apply_labels):
    """Unknown coverage stays NEW and respects the caller's label preference."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result("rhel-6-els", "pkg:rpm/redhat/perl-DBI@1.609?arch=src")],
        apply_labels=apply_labels,
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.NEW
    assert affect.resolution == Affect.AffectResolution.NOVALUE
    assert (
        WorkflowLabel.objects.filter(flaw=flaw, name=LABEL_MANUAL_TRIAGE).exists()
        == apply_labels
    )


def test_exclusion_precedes_missing_tracker_streams(els_stream, els_data, result):
    """Package exclusion takes precedence over the missing-tracker fallback."""
    els_stream.ps_module.default_ps_update_streams.clear()
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw, [result("rhel-6-els", "pkg:rpm/redhat/perl-DBI@1.609?arch=src")]
    )
    assert flaw.affects.get().resolution == Affect.AffectResolution.OOSS


def test_osv_missing_version_remains_unknown(
    els_stream, els_data, result, upstream_purls_openssl_rpm
):
    """ELS membership cannot resolve an affect whose version is unknown."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result("rhel-6-els", "pkg:rpm/redhat/openssl?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.NEW
    assert affect.resolution == Affect.AffectResolution.NOVALUE


@pytest.mark.parametrize("component", ["openssl", "perl-DBI"])
@pytest.mark.parametrize("apply_labels", [True, False])
def test_osv_unknown_remains_manual(
    els_stream, els_data, result, upstream_purls_openssl_rpm, component, apply_labels
):
    """Indeterminate version checks stay NEW regardless of ELS membership."""
    upstream = upstream_purls_openssl_rpm[0]
    upstream["name"] = component
    upstream["purl"] = f"pkg:rpm/redhat/{component}"
    upstream["ranges"][0]["events"][1]["fixed"] = "invalid version"
    flaw = FlawFactory(components=[component], impact=Impact.IMPORTANT)

    stats = _sync_affects_from_results(
        flaw,
        [result("rhel-6-els", f"pkg:rpm/redhat/{component}@1.0?arch=src")],
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


def test_no_els_lookup_for_other_streams(monkeypatch, result):
    """Other product streams do not consult RHEL 6-specific coverage."""
    module = PsModuleFactory(name="rhel-9")
    stream = PsUpdateStreamFactory(name="rhel-9.8.z", ps_module=module)
    module.default_ps_update_streams.add(stream)

    def unexpected_lookup(*args):
        """Fail if the non-ELS path attempts a coverage lookup."""
        pytest.fail("ELS coverage queried for a non-ELS stream")

    monkeypatch.setattr(
        "collectors.component_mapping.els.rhel6_els_in_scope", unexpected_lookup
    )
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw, [result(stream.name, "pkg:rpm/redhat/perl-DBI@1.0?arch=src")]
    )
    assert flaw.affects.get().resolution == Affect.AffectResolution.DELEGATED


def test_osv_notaffected_precedes_missing_list(
    els_stream, result, upstream_purls_openssl_rpm
):
    """A known fixed version stays NOTAFFECTED even without ELS data."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    _sync_affects_from_results(
        flaw,
        [result("rhel-6-els", "pkg:rpm/redhat/openssl@3.0.10?arch=src")],
        flaw_component="openssl",
        upstream_purls=upstream_purls_openssl_rpm,
    )
    affect = flaw.affects.get()
    assert affect.affectedness == Affect.AffectAffectedness.NOTAFFECTED
    assert affect.resolution == Affect.AffectResolution.NOVALUE


def test_existing_affect_not_rewritten(els_stream, els_data, result):
    """Rerunning ACE preserves an existing analyst resolution."""
    flaw = FlawFactory(impact=Impact.IMPORTANT)
    results = [result("rhel-6-els", "pkg:rpm/redhat/perl-DBI@1.609?arch=src")]
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
