import pytest

from osidb.models import Affect, Impact
from osidb.tests.factories import AffectFactory, FlawFactory, PsModuleFactory

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

        ps_module = PsModuleFactory(name="test-module")

        # Check creation behavior
        affect = Affect(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=affectedness,
            resolution=resolution,
            ps_component="component-10",
            ps_module=ps_module.name,
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
        affect = AffectFactory(purl=purl, ps_component=None)

        assert affect.ps_component == ps_component

    def test_same_module_component_diff_purl(self):
        a1 = AffectFactory(
            ps_module="quarkus-3",
            ps_component=None,
            purl="pkg:maven/software.amazon.awssdk/glue@2.27.20.redhat-00001?type=jar",
        )
        a2 = AffectFactory(
            flaw=a1.flaw,
            ps_module="quarkus-3",
            ps_component=None,
            purl="pkg:maven/software.amazon.awssdk/glue@2.30.36.redhat-00001?type=jar",
        )

        assert a1.flaw == a2.flaw
        assert a1.ps_module == a2.ps_module
        assert a1.ps_component == a2.ps_component
        assert a1.purl != a2.purl
