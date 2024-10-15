import json

import pytest

from apps.bbsync.cc import AffectCCBuilder, CCBuilder, RHSCLAffectCCBuilder
from apps.bbsync.constants import RHSCL_BTS_KEY, USER_BLACKLIST
from apps.bbsync.tests.factories import BugzillaComponentFactory, BugzillaProductFactory
from osidb.models import Affect, Flaw, PsModule
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsContactFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
)

pytestmark = pytest.mark.unit


class TestCCBuilder:
    def prepare_flaw(
        self,
        affects=None,
        embargoed=False,
        old_affects=None,
        old_cc=None,
    ):
        """
        helper to initialize flaw with affects
        provided only abbreviated definitions
        """

        def prepare_affect(affect):
            """
            helper to initialize affect
            """
            if isinstance(affect, tuple):
                if not PsModule.objects.filter(name=affect[0]).exists():
                    PsModuleFactory(
                        name=affect[0],
                        default_cc=[f"{affect[0]}.{affect[1]}@redhat.com"],
                    )
                return {
                    "ps_module": affect[0],
                    "ps_component": affect[1],
                    "affectedness": affect[2]
                    if len(affect) > 2
                    else Affect.AffectAffectedness.AFFECTED,
                    "resolution": affect[3]
                    if len(affect) > 3
                    else Affect.AffectResolution.DELEGATED,
                }
            else:
                return affect

        affects = (
            [] if affects is None else [prepare_affect(affect) for affect in affects]
        )
        old_affects = (
            []
            if old_affects is None
            else [prepare_affect(affect) for affect in old_affects]
        )

        meta_attr = {}
        if old_cc is not None:
            meta_attr["cc"] = '["' + '", "'.join(old_cc) + '"]'
        if old_affects is not None:
            meta_attr["original_srtnotes"] = (
                '{"affects": ' + json.dumps(old_affects) + "}"
            )

        flaw = FlawFactory(
            embargoed=embargoed,
            meta_attr=meta_attr,
        )
        for affect in affects:
            AffectFactory(flaw=flaw, **affect)

        return flaw

    def test_prepare(self):
        self.prepare_flaw(
            affects=[
                ("rhel-6", "kernel"),
                ("rhel-7", "openssl"),
            ],
            old_affects=[
                ("rhel-6", "kernel"),
            ],
            old_cc=[
                "email@redhat.com",
                "someone@gmail.com",
            ],
        )
        flaw = Flaw.objects.first()
        assert flaw
        assert flaw.embargoed is False
        assert flaw.meta_attr["cc"] == '["email@redhat.com", "someone@gmail.com"]'
        assert (
            flaw.meta_attr["original_srtnotes"]
            == '{"affects": [{"ps_module": "rhel-6", "ps_component": "kernel", "affectedness": "AFFECTED", "resolution": "DELEGATED"}]}'
        )
        assert flaw.affects.count() == 2
        assert flaw.affects.filter(ps_module="rhel-6", ps_component="kernel").exists()
        assert flaw.affects.filter(ps_module="rhel-7", ps_component="openssl").exists()
        assert PsModule.objects.get(name="rhel-6").default_cc == [
            "rhel-6.kernel@redhat.com"
        ]
        assert PsModule.objects.get(name="rhel-7").default_cc == [
            "rhel-7.openssl@redhat.com"
        ]

    ###############
    # FLAW CREATE #
    ###############

    def test_empty(self):
        """
        test that no affects result in empty CCs
        """
        flaw = FlawFactory()

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert not add_cc
        assert not remove_cc

    def test_unknown(self):
        """
        test that affect with an unknown PS module results in empty CCs
        """
        flaw = FlawFactory()
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert not add_cc
        assert not remove_cc

    def test_community(self):
        """
        test that community affect results in empty CCs
        """
        flaw = FlawFactory()
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        ps_product = PsProductFactory(business_unit="Community")
        PsModuleFactory(
            name=affect.ps_module,
            default_cc=["me@redhat.com"],
            ps_product=ps_product,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert not add_cc
        assert not remove_cc

    @pytest.mark.parametrize(
        "cc,embargoed",
        [
            ([], True),
            (["me@redhat.com", "you@redhat.com"], False),
        ],
    )
    def test_notaffected(self, cc, embargoed):
        """
        test that notaffected affects result in empty CCs
        however this restriction only applies to embargoed flaws
        """
        flaw = FlawFactory(embargoed=embargoed)
        affect1 = AffectFactory(
            flaw=flaw, affectedness=Affect.AffectAffectedness.NOTAFFECTED
        )
        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.WONTFIX,
        )
        PsModuleFactory(
            name=affect1.ps_module,
            default_cc=["me@redhat.com"],
        )
        PsModuleFactory(
            name=affect2.ps_module,
            default_cc=["you@redhat.com"],
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == cc
        assert not remove_cc

    ###############
    # FLAW UPDATE #
    ###############

    def test_no_change(self):
        """
        test that no change means no change
        """
        old_cc = [
            "rhel-6.kernel@redhat.com",
            "rhel-7.openssl@redhat.com",
        ]
        flaw = self.prepare_flaw(
            affects=[
                ("rhel-6", "kernel"),
                ("rhel-7", "openssl"),
            ],
            old_affects=[
                ("rhel-6", "kernel"),
                ("rhel-7", "openssl"),
            ],
            old_cc=old_cc,
        )

        cc_builder = CCBuilder(flaw, old_cc)
        add_cc, remove_cc = cc_builder.content
        assert not add_cc
        assert not remove_cc

    def test_add_affect(self):
        """
        test that adding an affect results in adding the corresponding CCs
        """
        old_cc = ["rhel-6.kernel@redhat.com"]
        new_flaw = self.prepare_flaw(
            affects=[
                ("rhel-6", "kernel"),
                ("rhel-7", "openssl"),
            ],
        )

        cc_builder = CCBuilder(new_flaw, old_cc)
        add_cc, remove_cc = cc_builder.content
        assert add_cc == ["rhel-7.openssl@redhat.com"]
        assert not remove_cc

    def test_remove_affect(self):
        """
        test that removing an affect results in no change
        """
        old_cc = [
            "rhel-6.kernel@redhat.com",
            "rhel-7.openssl@redhat.com",
        ]
        new_flaw = self.prepare_flaw(
            affects=[
                ("rhel-6", "kernel"),
            ],
        )

        cc_builder = CCBuilder(new_flaw, old_cc)
        add_cc, remove_cc = cc_builder.content
        assert not add_cc
        assert not remove_cc


class TestAffectCCBuilder:
    @pytest.mark.parametrize(
        "cc,private_trackers_allowed",
        [
            (["me@redhat.com", "you@redhat.com"], True),
            ([], False),
        ],
    )
    def test_private_trackers_allowed(self, cc, private_trackers_allowed):
        """
        test that the CCs are empty if embargoed
        when private trackers are not allowed
        """
        flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            name=affect.ps_module,
            default_cc=["me@redhat.com", "you@redhat.com"],
            private_trackers_allowed=private_trackers_allowed,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == cc
        assert not remove_cc

    def test_embargoed_nonredhat(self):
        """
        test that non-RH CC is not added when the flaw is embargoed
        """
        flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            name=affect.ps_module,
            default_cc=["me@fedora.org", "you@redhat.com"],
            private_trackers_allowed=True,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == ["you@redhat.com"]
        assert not remove_cc

    def test_embargoed_blacklist(self):
        """
        test that blacklisted CC is not added when the flaw is embargoed
        """
        flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            name=affect.ps_module,
            default_cc=USER_BLACKLIST[:10] + ["you@redhat.com"],
            private_trackers_allowed=True,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == ["you@redhat.com"]
        assert not remove_cc

    @pytest.mark.parametrize(
        "bts_name",
        [
            ("bugzilla"),
            ("jboss"),
        ],
    )
    def test_append_domain(self, bts_name):
        """
        test that RH domain is added to CC without a domain for BZ-based affects
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        mod = PsModuleFactory(
            name=affect.ps_module,
            default_cc=["cat", "dog", "duck@fedora.org"],
            bts_name=bts_name,
        )

        cc_builder = AffectCCBuilder(affect, False)
        cc_list = set(cc_builder.cc)
        if mod.bts_name == "bugzilla":
            assert cc_list == {
                "cat@redhat.com",
                "dog@redhat.com",
                "duck@fedora.org",
            }
        else:
            assert cc_list == {
                "cat",
                "dog",
                "duck@fedora.org",
            }
        # assert not remove_cc

    def test_expand_alias(self):
        """
        test that CC aliases are correctly expanded
        """
        flaw = FlawFactory(embargoed=False)
        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            bts_name="bugzilla",
            name=affect1.ps_module,
            default_cc=["cat", "duck@fedora.org"],
        )
        PsContactFactory(
            username="cat",
            bz_username="catfish@email.org",
            jboss_username="tomcat@domain.de",
        )
        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            bts_name="jboss",
            name=affect2.ps_module,
            default_cc=["dog", "horse@redhat.com"],
        )
        PsContactFactory(
            username="dog",
            bz_username="puppy@domain.au",
            jboss_username="hotdog@email.org",
        )

        cc_builder1 = AffectCCBuilder(affect1, False)
        cc_list1 = set(cc_builder1.cc)
        assert cc_list1 == {
            "catfish@email.org",
            "duck@fedora.org",
        }

        cc_builder2 = AffectCCBuilder(affect2, False)
        cc_list2 = set(cc_builder2.cc)
        assert cc_list2 == {
            "horse@redhat.com",
            "hotdog@email.org",
        }

    def test_bts_name_override(self):
        """
        test that CC aliases are created based on override bts name
        """
        flaw = FlawFactory(embargoed=False)
        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            bts_name="bugzilla",
            name=affect1.ps_module,
            default_cc=["cat", "duck@fedora.org"],
        )
        PsContactFactory(
            username="cat",
            bz_username="catfish@email.org",
            jboss_username="tomcat@domain.de",
        )
        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            bts_name="jboss",
            name=affect2.ps_module,
            default_cc=["dog", "horse@redhat.com"],
        )
        PsContactFactory(
            username="dog",
            bz_username="puppy@domain.au",
            jboss_username="hotdog@email.org",
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert set(add_cc) == {
            "catfish@email.org",
            "duck@fedora.org",
            "horse@redhat.com",
            "puppy@domain.au",
        }
        assert not remove_cc

    @pytest.mark.parametrize(
        "default_cc,expected_cc",
        [
            ([], []),
            (["me@redhat.com"], ["me@redhat.com"]),
            (
                ["me@redhat.com", "you@redhat.com"],
                ["me@redhat.com", "you@redhat.com"],
            ),
        ],
    )
    def test_module_cc(self, default_cc, expected_cc):
        """
        test that PS module CCs are correctly added
        """
        flaw = FlawFactory()
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        PsModuleFactory(
            name=affect.ps_module,
            default_cc=default_cc,
            private_trackers_allowed=True,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == expected_cc
        assert not remove_cc

    def test_private_tracker_cc(self):
        """
        test that PS module private tracker CCs are correctly added
        """
        flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        private_tracker_cc = ["me@redhat.com", "you@redhat.com"]
        PsModuleFactory(
            name=affect.ps_module,
            private_trackers_allowed=True,
            private_tracker_cc=private_tracker_cc,
        )

        # no private tracker CC is expected for the flaw
        assert not AffectCCBuilder(affect, flaw.embargoed, destination="flaw").cc
        assert sorted(
            AffectCCBuilder(affect, flaw.embargoed, destination="tracker").cc
        ) == ["me@redhat.com", "you@redhat.com"]

    @pytest.mark.parametrize(
        "ps_component,component_overrides,component_cc",
        [
            ("cup", {}, {}),
            (
                "cup",
                {},
                {
                    "fork": ["you@fedora.org"],
                    "spoon": ["me@redhat.com"],
                },
            ),
            (
                "cup",
                {
                    "cup": "spoon",
                    "fork": "knife",
                },
                {},
            ),
            (
                "cup",
                {
                    "banana": "cup",
                    "cup": "spoon",
                },
                {
                    "cup": ["her@redhat.com", "you@fedora.org"],
                    "spoon": ["me@redhat.com"],
                },
            ),
            # override preceeds slash
            (
                "cup/plate",
                {
                    "cup": "spoon",
                    "cup/plate": "fork",
                    "plate": "spoon",
                },
                {
                    "cup": ["her@redhat.com"],
                    "fork": ["me@redhat.com"],
                    "plate": ["you@fedora.org"],
                    "spoon": ["her@redhat.com", "you@fedora.org"],
                },
            ),
            (
                "cup/plate",
                {
                    "cup": "spoon",
                    "plate": "spoon",
                },
                {
                    "cup": ["her@redhat.com"],
                    "plate": ["me@redhat.com"],
                    "spoon": ["you@fedora.org"],
                },
            ),
            (
                "cup/fork/plate",
                {
                    "cup": "spoon",
                    "plate": "spoon",
                },
                {
                    "cup": ["her@redhat.com"],
                    "plate": ["me@redhat.com"],
                    "spoon": ["you@fedora.org"],
                },
            ),
        ],
    )
    def test_ps2bz_component(self, ps_component, component_overrides, component_cc):
        """
        test that PS component is correctly mapped to
        the Bugzilla one while generating the CCs
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component=ps_component,
        )
        PsModuleFactory(
            name=affect.ps_module,
            bts_name="bugzilla",
            component_cc=component_cc,
            component_overrides=component_overrides,
            default_cc=[],
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == (
            ["me@redhat.com"] if component_overrides and component_cc else []
        )
        assert not remove_cc

    @pytest.mark.parametrize(
        "component_cc,expected_cc",
        [
            ({}, []),
            (
                {
                    "stick": ["me@redhat.com"],
                },
                [],
            ),
            (
                {
                    "brick": ["me@redhat.com", "you@fedora.org"],
                    "stick": ["her@redhat.com"],
                },
                ["me@redhat.com", "you@fedora.org"],
            ),
            # wildcard match
            (
                {
                    "br*": ["him@redhat.com"],
                },
                ["him@redhat.com"],
            ),
            (
                {
                    "b*ck": ["her@redhat.com", "him@fedora.org"],
                    "s*": ["him@redhat.com"],
                },
                ["her@redhat.com", "him@fedora.org"],
            ),
            (
                {
                    "br*": ["her@redhat.com", "him@redhat.com"],
                    "b*ck": ["her@redhat.com", "him@fedora.org"],
                },
                ["her@redhat.com", "him@fedora.org", "him@redhat.com"],
            ),
        ],
    )
    def test_component_cc(self, component_cc, expected_cc):
        """
        test that CCs based on Bugzilla component are correctly added
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="brick",
        )
        PsModuleFactory(
            name=affect.ps_module,
            bts_name="bugzilla",
            component_cc=component_cc,
            default_cc=[],
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == expected_cc
        assert not remove_cc

    @pytest.mark.parametrize(
        "default_cc,expected_cc",
        [
            ([], ["me@redhat.com"]),
            (["you@redhat.com"], ["me@redhat.com", "you@redhat.com"]),
        ],
    )
    def test_bugzilla_cc(self, default_cc, expected_cc):
        """
        test that CCs based on Bugzilla product and component are correctly added
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        bz_product = BugzillaProductFactory()
        BugzillaComponentFactory(
            name=affect.ps_component,
            default_cc=default_cc,
            default_owner="me@redhat.com",
            product=bz_product,
        )
        PsModuleFactory(
            name=affect.ps_module,
            bts_name="bugzilla",
            bts_key=bz_product.name,
            component_cc={},
            default_cc=[],
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == expected_cc
        assert not remove_cc


class TestRHSCLAffectCCBuilder:
    def test_component_cc(self):
        """
        test that CCs based on Bugzilla component are correctly added
        even in the case of RHSCL where the mechanism is different
        """
        flaw = FlawFactory(embargoed=False)
        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="brick-collection",
        )
        ps_module1 = PsModuleFactory(
            name=affect1.ps_module,
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "brick": ["me@redhat.com"],
                "collection": ["you@redhat.com"],
                "stick": ["her@redhat.com"],
            },
            default_cc=[],
        )
        PsUpdateStreamFactory(
            collections=[
                "brick",
                "stick",
            ],
            ps_module=ps_module1,
        )
        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="apple-juice",
        )
        ps_module2 = PsModuleFactory(
            name=affect2.ps_module,
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "apple": ["cat@redhat.com"],
                "apple-juice": ["dog@redhat.com"],
                "juice": ["hamster@redhat.com"],
            },
            default_cc=[],
        )
        PsUpdateStreamFactory(
            collections=[
                "apple-juice",
                "juice",
            ],
            ps_module=ps_module2,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == ["dog@redhat.com", "me@redhat.com", "you@redhat.com"]
        assert not remove_cc

    def test_no_collection_match(self):
        """
        test that RHSCL CCs are correctly processed
        even when no collection is matched
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="stick",
        )
        ps_module = PsModuleFactory(
            name=affect.ps_module,
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "brick": ["me@redhat.com"],
                "stick": ["her@redhat.com"],
            },
            default_cc=["you@redhat.com"],
        )
        PsUpdateStreamFactory(
            collections=[
                "brick",
            ],
            ps_module=ps_module,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert RHSCLAffectCCBuilder(affect, flaw.embargoed).collection is None
        assert add_cc == ["her@redhat.com", "you@redhat.com"]
        assert not remove_cc

    def test_extra_collection_match(self):
        """
        test that RHSCL CCs are correctly processed
        even when extra collection is matched
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="stick-brick",
        )
        ps_module = PsModuleFactory(
            name=affect.ps_module,
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "brick": ["me@redhat.com"],
                "stick": ["her@redhat.com"],
            },
            default_cc=["you@redhat.com"],
        )
        PsUpdateStreamFactory(
            collections=[
                "stick",
                "stick-brick",
            ],
            ps_module=ps_module,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert RHSCLAffectCCBuilder(affect, flaw.embargoed).collection is None
        assert add_cc == ["you@redhat.com"]
        assert not remove_cc
