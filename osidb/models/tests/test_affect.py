from osidb.models import Affect, Impact
from osidb.tests.factories import AffectFactory, FlawFactory, PsModuleFactory


class TestAffect:
    def test_resolved_dt_auto_update(self):
        """
        test resolve_dt is null when an affect is unresolved and is
        automatically updated when first entered in a resolved state
        """
        flaw = FlawFactory()

        # Check factory behavior
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        assert not affect.is_resolved
        assert not affect.resolved_dt

        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.WONTFIX,
        )
        assert affect.is_resolved
        assert affect.resolved_dt

        ps_module = PsModuleFactory(name="test-module")

        # Check creation behavior
        affect_unresolved = Affect(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
            ps_component="component-10",
            ps_module=ps_module.name,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        affect_unresolved.save()

        assert not affect_unresolved.is_resolved
        assert not affect_unresolved.resolved_dt

        affect_resolved = Affect(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="component-20",
            ps_module=ps_module.name,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        affect_resolved.save()

        assert affect_resolved.is_resolved
        assert affect_resolved.resolved_dt

        # Check update behavior from unresolved to resolved
        affect_unresolved.affectedness = Affect.AffectAffectedness.AFFECTED
        affect_unresolved.resolution = Affect.AffectResolution.DELEGATED
        affect_unresolved.save()

        assert affect_unresolved.is_resolved
        assert affect_unresolved.resolved_dt

        # Check update behavior from resolved to resolved
        current_resolved_dt = affect_resolved.resolved_dt
        affect_resolved.affectedness = Affect.AffectAffectedness.AFFECTED
        affect_resolved.resolution = Affect.AffectResolution.WONTFIX
        affect_resolved.save()

        assert affect_resolved.is_resolved
        assert affect_resolved.resolved_dt == current_resolved_dt

        # Check update behavior from resolved to unresolved
        affect_resolved.affectedness = Affect.AffectAffectedness.NEW
        affect_resolved.resolution = Affect.AffectResolution.NOVALUE
        affect_resolved.save()

        assert not affect_resolved.is_resolved
        assert not affect_resolved.resolved_dt
