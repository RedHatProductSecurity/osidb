import pytest
from django.core.exceptions import ValidationError

from osidb.models import Affect, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
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
                "pkg:oci/example-component@1.0.0?repository_url=registry.example.io/namespace/example-component",
                "namespace/example-component",
            ),
        ],
    )
    def test_ps_component_from_purl(self, purl, ps_component):
        affect = AffectFactory(purl=purl, ps_component=None)

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

    @pytest.mark.parametrize(
        "business_unit,purl,should_raise,expected_error",
        [
            # Middleware products require PURL for new affects
            ("Core Middleware", None, True, "must specify a PURL"),
            ("Core Middleware", "", True, "must specify a PURL"),
            ("Core Middleware", "pkg:rpm/example@1.0", False, None),
            # Non-middleware products don't require PURL
            ("RHEL", None, False, None),
            ("RHEL", "", False, None),
            ("RHEL", "pkg:rpm/example@1.0", False, None),
        ],
    )
    def test_validate_purl_middleware_new_affects(
        self, business_unit, purl, should_raise, expected_error
    ):
        """Test PURL validation for new affects on middleware products"""
        from osidb.tests.factories import PsProductFactory

        ps_product = PsProductFactory(business_unit=business_unit)
        ps_module = PsModuleFactory(ps_product=ps_product)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()

        affect = Affect(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="test-component",
            purl=purl,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        if should_raise:
            with pytest.raises(ValidationError) as exc_info:
                affect.save()
            assert expected_error in str(exc_info.value)
        else:
            affect.save()

    @pytest.mark.parametrize(
        "business_unit,initial_purl,updated_purl,should_raise,expected_error",
        [
            # Middleware product: removing PURL should raise error
            (
                "Core Middleware",
                "pkg:rpm/example@1.0",
                None,
                True,
                "cannot have its PURL removed",
            ),
            (
                "Core Middleware",
                "pkg:rpm/example@1.0",
                "",
                True,
                "cannot have its PURL removed",
            ),
            # Middleware product: keeping PURL should be fine
            (
                "Core Middleware",
                "pkg:rpm/example@1.0",
                "pkg:rpm/example@2.0",
                False,
                None,
            ),
            # Middleware product: adding PURL to existing affect should be fine
            ("Core Middleware", "", "pkg:rpm/example@1.0", False, None),
            # Non-middleware product: removing PURL should be fine
            ("RHEL", "pkg:rpm/example@1.0", None, False, None),
            ("RHEL", "pkg:rpm/example@1.0", "", False, None),
        ],
    )
    def test_validate_purl_middleware_existing_affects(
        self, business_unit, initial_purl, updated_purl, should_raise, expected_error
    ):
        """Test PURL validation for existing affects on middleware products"""
        from osidb.tests.factories import PsProductFactory

        ps_product = PsProductFactory(business_unit=business_unit)
        ps_module = PsModuleFactory(ps_product=ps_product)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()

        affect = AffectFactory.build(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="test-component",
            purl=initial_purl,
        )
        # Simulate existing affect by saving without the validation
        affect.save(raise_validation_error=False)

        affect.purl = updated_purl or ""

        if should_raise:
            with pytest.raises(ValidationError) as exc_info:
                affect.save()
            assert expected_error in str(exc_info.value)
        else:
            affect.save()

    @pytest.mark.parametrize(
        "initial_purl,updated_purl,should_fail",
        [
            # PURL addition - should validate
            ("", "pkg:rpm/redhat/curl@7.76.1?arch=src", False),
            ("", "pkg:rpm/redhat/curl?arch=src", True),
            # PURL modification - should validate
            (
                "pkg:rpm/redhat/old-package@1.0.0?arch=src",
                "pkg:rpm/redhat/curl@7.76.1?arch=src",
                False,
            ),
            (
                "pkg:rpm/redhat/curl?arch=src",
                "pkg:rpm/redhat/curl@7.76.1?arch=src",
                False,
            ),
            (
                "pkg:rpm/redhat/old-package@1.0.0?arch=src",
                "pkg:rpm/redhat/curl?arch=src",
                True,
            ),
            (
                "pkg:rpm/redhat/old-package?arch=src",
                "pkg:rpm/redhat/curl?arch=src",
                True,
            ),
            # PURL not changed - should not validate
            (
                "pkg:rpm/redhat/curl@7.76.1?arch=src",
                "pkg:rpm/redhat/curl@7.76.1?arch=src",
                False,
            ),
            ("pkg:rpm/redhat/curl?arch=src", "pkg:rpm/redhat/curl?arch=src", False),
            # PURL deletion - should not validate
            ("pkg:rpm/redhat/curl?arch=src", "", False),
            ("pkg:rpm/redhat/curl@7.76.1?arch=src", "", False),
        ],
    )
    def test_validate_version_in_purl(self, initial_purl, updated_purl, should_fail):
        """
        Test that _validate_version_in_purl validation is only run when PURL is
        added or modified, and properly validates version presence.
        """
        flaw = FlawFactory()
        ps_update_stream = PsUpdateStreamFactory()
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="test-component",
            impact=Impact.MODERATE,
        )
        affect.purl = initial_purl
        # Initially don't validate to set up test case, emulating old affects with invalid PURLs
        affect.save(raise_validation_error=False)

        affect.purl = updated_purl
        if initial_purl == updated_purl:
            # Test changing other field without PURL change
            affect.impact = Impact.IMPORTANT

        if should_fail:
            with pytest.raises(ValidationError) as exc_info:
                affect.save()
            assert "does not specify a version" in str(exc_info.value)
        else:
            affect.save()

    @pytest.mark.parametrize(
        "ps_component1,purl1,ps_component2,purl2,should_fail,expected_constraint",
        [
            # Empty PURL, same component - fails
            (
                "test-component",
                "",
                "test-component",
                "",
                True,
                "affect_unique_flaw_stream_component_when_purl_empty",
            ),
            # Empty PURL, different component - succeeds
            (
                "test-component",
                "",
                "different-component",
                "",
                False,
                None,
            ),
            # Non-empty PURL duplicate - fails
            (
                "component-a",
                "pkg:rpm/redhat/curl@7.76.1?arch=src",
                "component-b",
                "pkg:rpm/redhat/curl@7.76.1?arch=src",
                True,
                "affect_unique_flaw_stream_purl",
            ),
            # Non-empty PURL, different PURLs - succeeds
            (
                "component-a",
                "pkg:rpm/redhat/curl@7.76.1?arch=src",
                "component-b",
                "pkg:rpm/redhat/different@1.0.0?arch=src",
                False,
                None,
            ),
            # Non-empty PURL and empty PURL - succeeds
            (
                "same-component",
                "",
                "same-component",
                "pkg:rpm/redhat/package@1.0.0?arch=src",
                False,
                None,
            ),
            # PURLs that only differ by qualifiers - succeeds
            (
                "component-a",
                "pkg:rpm/redhat/curl@7.76.1?arch=src&rpmmod=test",
                "component-b",
                "pkg:rpm/redhat/curl@7.76.1?arch=x86_64&different=qualifier",
                False,
                None,
            ),
            # PURLs that only differ by subpath - succeeds
            (
                "component-a",
                "pkg:rpm/redhat/curl@7.76.1?arch=src#bin/curl",
                "component-b",
                "pkg:rpm/redhat/curl@7.76.1?arch=src#lib/libcurl.so",
                False,
                None,
            ),
        ],
    )
    def test_uniqueness_constraints(
        self,
        ps_component1,
        purl1,
        ps_component2,
        purl2,
        should_fail,
        expected_constraint,
    ):
        """
        Test various uniqueness constraint scenarios for affects using conditional constraints.
        """
        flaw = FlawFactory()
        ps_update_stream = PsUpdateStreamFactory()

        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_component1,
            purl=purl1,
        )

        if should_fail:
            with pytest.raises(ValidationError) as exc_info:
                AffectFactory(
                    flaw=flaw,
                    ps_update_stream=ps_update_stream.name,
                    ps_component=ps_component2,
                    purl=purl2,
                )
            assert expected_constraint in str(exc_info.value)
        else:
            AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                ps_component=ps_component2,
                purl=purl2,
            )
