import pytest
from django.core.exceptions import ValidationError

from osidb.constants import SERVICES_PRODUCTS
from osidb.models import Affect, Impact, Tracker
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
    default_rpm_purl_for_ps_component,
)

pytestmark = pytest.mark.unit


class TestAffect:
    @pytest.mark.parametrize(
        "affectedness,resolution,is_resolved",
        [
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.NOVALUE, False),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                False,
            ),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.WONTFIX, True),
            (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.WONTFIX, True),
        ],
    )
    @pytest.mark.parametrize(
        # Second set of values to use for when updating the affectedness/resolution,
        # so that the possible combinations are tested
        "affectedness_2,resolution_2,is_resolved_2",
        [
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.NOVALUE, False),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                False,
            ),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.WONTFIX, True),
            (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.WONTFIX, True),
        ],
    )
    def test_resolved_dt_auto_update(
        self,
        affectedness,
        resolution,
        is_resolved,
        affectedness_2,
        resolution_2,
        is_resolved_2,
    ):
        """
        test resolve_dt is null when an affect is unresolved and is
        automatically updated when first entered in a resolved state
        """
        flaw = FlawFactory()

        # Check factory behavior
        affect = AffectFactory(
            flaw=flaw,
            affectedness=affectedness,
            resolution=resolution,
        )
        assert affect.is_resolved == is_resolved
        assert affect.resolved_dt or not is_resolved

        ps_update_stream = PsUpdateStreamFactory(name="test-stream")

        # Check creation behavior
        affect = Affect(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=affectedness,
            resolution=resolution,
            ps_component="component-10",
            ps_update_stream=ps_update_stream.name,
            purl=default_rpm_purl_for_ps_component("component-10"),
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        affect.save()
        assert affect.is_resolved == is_resolved
        assert affect.resolved_dt or not is_resolved

        # Check update behavior
        affect.affectedness = affectedness_2
        affect.resolution = resolution_2
        affect.save()
        assert affect.is_resolved == is_resolved_2
        assert affect.resolved_dt or not is_resolved_2

    @pytest.mark.parametrize(
        "purl,ps_component",
        [
            ("pkg:rpm/redhat/php@7.2?arch=src&rpmmod=php:7.2", "php:7.2/php"),
            ("pkg:rpm/redhat/squid@4?arch=src&rpmmod=squid:4", "squid:4/squid"),
            (
                "pkg:rpm/redhat/gstreamer1-plugins-good@flatpak?arch=src&rpmmod=libreoffice:flatpak",
                "libreoffice:flatpak/gstreamer1-plugins-good",
            ),
            ("pkg:rpm/redhat/redis@6?arch=src&rpmmod=redis:6", "redis:6/redis"),
            (
                "pkg:rpm/redhat/ghostscript@flatpak?arch=src&rpmmod=gimp:flatpak",
                "gimp:flatpak/ghostscript",
            ),
            ("pkg:rpm/redhat/idm@DL1?arch=src&rpmmod=idm:DL1", "idm:DL1/idm"),
            (
                "pkg:rpm/redhat/nginx@1.14.1-9.module+el8.0.0+4108+cba21616?arch=x86_64&rpmmod=mainstream",
                "mainstream/nginx",
            ),
            (
                "pkg:oci/example-component?repository_url=registry.example.io/namespace/example-component",
                "namespace/example-component",
            ),
        ],
    )
    def test_ps_component_from_purl(self, purl, ps_component):
        affect = AffectFactory(purl=purl, ps_component="")

        assert affect.ps_component == ps_component

    def test_labels_field_default(self):
        """Test that the labels field defaults to an empty list"""
        affect = AffectFactory()
        assert affect.labels == []

    @pytest.mark.enable_signals
    def test_labels_field_auto_populated(self):
        """Test that the labels field is automatically populated when saving an affect"""
        from osidb.models.flaw.label import FlawLabel

        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        # Create a test label that matches our affect's ps_module and ps_component
        FlawLabel.objects.create(
            name="test-auto-label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=[ps_module.name],
            ps_components=["test-component"],
        )

        # Create an affect - the signal should automatically populate labels
        affect = AffectFactory(
            ps_update_stream=ps_update_stream.name,
            ps_module=ps_module.name,
            ps_component="test-component",
        )
        affect.save()

        # Check that the label was automatically added to the labels field
        assert "test-auto-label" in affect.labels

    def test_delete_affect_with_open_tracker(self):
        """Test that an affect with a non closed tracker can't be deleted"""
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)

        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_module=ps_module.name,
            ps_component="test-component",
        )

        tracker = TrackerFactory(
            embargoed=False,
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            external_system_id="OSIDB-1234",
            ps_update_stream=ps_update_stream.name,
            status="Open",
        )

        # Trying to delete the affect without first closing the Tracker should raise an error
        with pytest.raises(ValidationError):
            affect.delete()

        tracker.status = "Closed"
        tracker.save()

        # Tracker is closed, should not raise an error
        affect.delete()

    def test_delete_affect_without_tracker(self):
        """Test that an affect without a tracker can be deleted"""
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)

        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_module=ps_module.name,
            ps_component="test-component",
        )
        affect.delete()

    def test_validate_purl_existence(self):
        """
        Test that non-community, non-services products require a PURL
        """
        ps_product = PsProductFactory(business_unit="RHEL")
        ps_module = PsModuleFactory(ps_product=ps_product)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()

        affect = Affect(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="example",
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        with pytest.raises(ValidationError) as exc_info:
            affect.save()

        assert "is missing a PURL." in str(exc_info.value)
        assert str(affect.uuid) in str(exc_info.value)

    def test_validate_purl_existence_skipped_for_community_product(self):
        """
        Test that PURLs are not required for community affects.
        """
        ps_product = PsProductFactory(business_unit="Community")
        ps_module = PsModuleFactory(ps_product=ps_product)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()

        affect = Affect(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="example",
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        affect.save()

    def test_validate_purl_existence_skipped_for_services_product(self):
        """
        Test that PURLs are not required for service affects.
        """
        ps_product = PsProductFactory(short_name=SERVICES_PRODUCTS[0])
        ps_module = PsModuleFactory(ps_product=ps_product)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()

        affect = Affect(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="example",
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        affect.save()

    def test_validate_cvss_not_affected_fails_with_cvss(self):
        """Test that NOTAFFECTED affects with CVSS scores fail validation"""
        affect = AffectFactory(affectedness=Affect.AffectAffectedness.NOTAFFECTED)
        AffectCVSSFactory(affect=affect)

        with pytest.raises(ValidationError) as exc_info:
            affect.save()
        assert "is set as NOTAFFECTED but has CVSS scores associated" in str(
            exc_info.value
        )

    @pytest.mark.parametrize(
        "purl",
        [
            ("pkg:rpm/redhat/firefox"),
            ("pkg:rpm/redhat/firefox@1.2"),
            ("pkg:rpm/redhat/firefox?arch=src"),
            ("pkg:rpm/redhat/firefox?repository_url=hack.me"),
        ],
    )
    @pytest.mark.parametrize(
        "ps_component,should_raise",
        [
            ("", False),
            ("firefox", False),
            ("thunderbird", True),
            ("firefoxes", True),
            ("hack.me", True),
        ],
    )
    def test_validate_purl_and_ps_component(self, purl, ps_component, should_raise):
        """Test that ps_component can't mismatch purl parsed component"""
        ps_product = PsProductFactory()
        ps_module = PsModuleFactory(ps_product=ps_product)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()

        affect = Affect(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_component,
            purl=purl,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        if should_raise:
            with pytest.raises(ValidationError) as exc_info:
                affect.save()
            assert "does not match user-provided ps_component" in str(exc_info.value)
            assert str(affect.uuid) in str(exc_info.value)
        else:
            affect.save()


@pytest.mark.enable_signals
class TestAutoResolve:
    # ── unknown stream / no module ───────────────────────────────────────────

    def test_unknown_stream_sets_new_novalue(self):
        flaw = FlawFactory(impact=Impact.IMPORTANT)
        affect = AffectFactory.build(
            flaw=flaw,
            ps_update_stream="does-not-exist",
            impact=Impact.IMPORTANT,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.NEW
        assert affect.resolution == Affect.AffectResolution.NOVALUE

    def test_stream_without_module_sets_new_novalue(self, ps_update_stream_no_module):
        flaw = FlawFactory(impact=Impact.IMPORTANT)
        affect = AffectFactory.build(
            flaw=flaw,
            ps_update_stream=ps_update_stream_no_module.name,
            impact=Impact.IMPORTANT,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.NEW
        assert affect.resolution == Affect.AffectResolution.NOVALUE

    # ── AFFECTED/OOSS ────────────────────────────────────────────────────────

    @pytest.mark.parametrize("impact", [Impact.LOW, Impact.MODERATE])
    def test_ooss_low_moderate_impact_stream_not_moderate(
        self, impact, ps_stream_not_moderate
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=impact),
            ps_update_stream=ps_stream_not_moderate.name,
            impact=impact,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.OOSS

    @pytest.mark.parametrize("impact", [Impact.IMPORTANT, Impact.CRITICAL])
    def test_no_ooss_for_high_impact(self, impact, ps_stream_with_default):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=impact),
            ps_update_stream=ps_stream_with_default.name,
            impact=impact,
        )
        affect.auto_resolve()
        assert affect.resolution != Affect.AffectResolution.OOSS

    def test_no_ooss_community_stream_is_default(
        self, community_ps_stream_default_only
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=Impact.LOW),
            ps_update_stream=community_ps_stream_default_only.name,
            impact=Impact.LOW,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution != Affect.AffectResolution.OOSS

    def test_ooss_community_stream_neither_default_nor_moderate(
        self, community_ps_stream_not_moderate
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=Impact.LOW),
            ps_update_stream=community_ps_stream_not_moderate.name,
            impact=Impact.LOW,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.OOSS

    # ── AFFECTED/WONTFIX ─────────────────────────────────────────────────────

    @pytest.mark.parametrize("impact", [Impact.IMPORTANT, Impact.CRITICAL])
    def test_wontfix_high_impact_no_default_streams(
        self, impact, ps_stream_moderate_no_default
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=impact),
            ps_update_stream=ps_stream_moderate_no_default.name,
            impact=impact,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.WONTFIX

    def test_wontfix_low_impact_no_moderate_or_unacked_streams(
        self, ps_stream_moderate_no_tracker_streams
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=Impact.LOW),
            ps_update_stream=ps_stream_moderate_no_tracker_streams.name,
            impact=Impact.LOW,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.WONTFIX

    def test_no_wontfix_important_impact_has_default_streams(
        self, ps_stream_with_default
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=Impact.IMPORTANT),
            ps_update_stream=ps_stream_with_default.name,
            impact=Impact.IMPORTANT,
        )
        affect.auto_resolve()
        assert affect.resolution != Affect.AffectResolution.WONTFIX

    # ── AFFECTED/DEFER ───────────────────────────────────────────────────────

    def test_defer_low_impact_non_community(self, ps_stream_with_moderate_tracker):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=Impact.LOW),
            ps_update_stream=ps_stream_with_moderate_tracker.name,
            impact=Impact.LOW,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.DEFER

    @pytest.mark.parametrize(
        "cvss_vector",
        [
            None,  # no CVSS scores
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",  # score 3.5
        ],
    )
    def test_defer_moderate_impact_low_or_no_cvss(
        self, cvss_vector, ps_stream_with_moderate_tracker, flaw_with_cvss
    ):
        flaw = flaw_with_cvss(Impact.MODERATE, cvss_vector)
        affect = AffectFactory.build(
            flaw=flaw,
            ps_update_stream=ps_stream_with_moderate_tracker.name,
            impact=Impact.MODERATE,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.DEFER

    def test_no_defer_moderate_impact_high_cvss(
        self, ps_stream_with_moderate_tracker, flaw_with_cvss
    ):
        flaw = flaw_with_cvss(
            Impact.MODERATE, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )
        affect = AffectFactory.build(
            flaw=flaw,
            ps_update_stream=ps_stream_with_moderate_tracker.name,
            impact=Impact.MODERATE,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution != Affect.AffectResolution.DEFER

    def test_no_defer_low_impact_community(self, community_ps_stream_with_tracker):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=Impact.LOW),
            ps_update_stream=community_ps_stream_with_tracker.name,
            impact=Impact.LOW,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution != Affect.AffectResolution.DEFER

    # ── AFFECTED/DELEGATED ───────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "impact", [Impact.IMPORTANT, Impact.CRITICAL, Impact.NOVALUE]
    )
    def test_delegated_high_or_novalue_impact_has_default_streams(
        self, impact, ps_stream_with_default
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=impact),
            ps_update_stream=ps_stream_with_default.name,
            impact=impact,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.DELEGATED

    def test_delegated_moderate_impact_high_cvss(
        self, ps_stream_with_moderate_tracker, flaw_with_cvss
    ):
        flaw = flaw_with_cvss(
            Impact.MODERATE, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )
        affect = AffectFactory.build(
            flaw=flaw,
            ps_update_stream=ps_stream_with_moderate_tracker.name,
            impact=Impact.MODERATE,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.DELEGATED

    def test_delegated_community_low_impact_with_default_streams(
        self, community_ps_stream_with_tracker
    ):
        affect = AffectFactory.build(
            flaw=FlawFactory(impact=Impact.LOW),
            ps_update_stream=community_ps_stream_with_tracker.name,
            impact=Impact.LOW,
        )
        affect.auto_resolve()
        assert affect.affectedness == Affect.AffectAffectedness.AFFECTED
        assert affect.resolution == Affect.AffectResolution.DELEGATED
