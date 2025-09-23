import json

import pytest

from apps.bbsync.cc import AffectCCBuilder, CCBuilder, RHSCLAffectCCBuilder
from apps.bbsync.constants import RHSCL_BTS_KEY, USER_BLACKLIST
from apps.bbsync.tests.factories import BugzillaComponentFactory, BugzillaProductFactory
from osidb.cc import JiraAffectCCBuilder
from osidb.models import Affect, Flaw, PsModule, PsUpdateStream
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
                # affect = (ps_module, ps_update_stream, ps_component, affectedness, resolution)
                if not PsModule.objects.filter(name=affect[0]).exists():
                    PsModuleFactory(
                        name=affect[0],
                        default_cc=[f"{affect[0]}.{affect[2]}@redhat.com"],
                    )
                if not PsUpdateStream.objects.filter(
                    ps_module__name=affect[0],
                    name=affect[1],
                ).exists():
                    PsUpdateStreamFactory(
                        ps_module=PsModule.objects.get(name=affect[0]),
                        name=affect[1],
                    )
                return {
                    "ps_module": affect[0],
                    "ps_update_stream": affect[1],
                    "ps_component": affect[2],
                    "affectedness": affect[3]
                    if len(affect) > 3
                    else Affect.AffectAffectedness.AFFECTED,
                    "resolution": affect[4]
                    if len(affect) > 4
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
                ("rhel-6", "rhel-6.1", "kernel"),
                ("rhel-7", "rhel-7.1", "openssl"),
            ],
            old_affects=[
                ("rhel-6", "rhel-6.1", "kernel"),
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
            == '{"affects": [{"ps_module": "rhel-6", "ps_update_stream": "rhel-6.1", "ps_component": "kernel", "affectedness": "AFFECTED", "resolution": "DELEGATED"}]}'
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
        ps_product = PsProductFactory(business_unit="Community")
        ps_module = PsModuleFactory(
            default_cc=["me@redhat.com"],
            ps_product=ps_product,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
        ps_module_1 = PsModuleFactory(
            default_cc=["me@redhat.com"],
        )
        ps_module_2 = PsModuleFactory(
            default_cc=["you@redhat.com"],
        )
        ps_update_stream_1 = PsUpdateStreamFactory(ps_module=ps_module_1)
        ps_update_stream_2 = PsUpdateStreamFactory(ps_module=ps_module_2)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream_1.name,
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
        )
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream_2.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.WONTFIX,
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
                ("rhel-6", "rhel-6.1", "kernel"),
                ("rhel-7", "rhel-7.1", "openssl"),
            ],
            old_affects=[
                ("rhel-6", "rhel-6.1", "kernel"),
                ("rhel-7", "rhel-7.1", "openssl"),
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
                ("rhel-6", "rhel-6.1", "kernel"),
                ("rhel-7", "rhel-7.1", "openssl"),
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
                ("rhel-6", "rhel-6.1", "kernel"),
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
        ps_module = PsModuleFactory(
            default_cc=["me@redhat.com", "you@redhat.com"],
            private_trackers_allowed=private_trackers_allowed,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
        ps_module = PsModuleFactory(
            default_cc=["me@fedora.org", "you@redhat.com"],
            private_trackers_allowed=True,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
        ps_module = PsModuleFactory(
            default_cc=USER_BLACKLIST[:10] + ["you@redhat.com"],
            private_trackers_allowed=True,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
        ps_module = PsModuleFactory(
            default_cc=["cat", "dog", "duck@fedora.org"],
            bts_name=bts_name,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        cc_builder = AffectCCBuilder(affect, False)
        cc_list = set(cc_builder.cc)
        if ps_module.bts_name == "bugzilla":
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
        ps_module_1 = PsModuleFactory(
            bts_name="bugzilla",
            default_cc=["cat", "duck@fedora.org"],
        )
        ps_module_2 = PsModuleFactory(
            bts_name="jboss",
            default_cc=["dog", "horse@redhat.com"],
        )
        ps_update_stream_1 = PsUpdateStreamFactory(ps_module=ps_module_1)
        ps_update_stream_2 = PsUpdateStreamFactory(ps_module=ps_module_2)
        PsContactFactory(
            username="cat",
            bz_username="catfish@email.org",
            jboss_username="tomcat@domain.de",
        )
        PsContactFactory(
            username="dog",
            bz_username="puppy@domain.au",
            jboss_username="hotdog@email.org",
        )
        affect1 = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream_1.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream_2.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
        ps_module_1 = PsModuleFactory(
            bts_name="bugzilla",
            default_cc=["cat", "duck@fedora.org"],
        )
        ps_module_2 = PsModuleFactory(
            bts_name="jboss",
            default_cc=["dog", "horse@redhat.com"],
        )
        ps_update_stream_1 = PsUpdateStreamFactory(ps_module=ps_module_1)
        ps_update_stream_2 = PsUpdateStreamFactory(ps_module=ps_module_2)
        PsContactFactory(
            username="cat",
            bz_username="catfish@email.org",
            jboss_username="tomcat@domain.de",
        )
        PsContactFactory(
            username="dog",
            bz_username="puppy@domain.au",
            jboss_username="hotdog@email.org",
        )
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream_1.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream_2.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
        ps_module = PsModuleFactory(
            default_cc=default_cc,
            private_trackers_allowed=True,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert add_cc == expected_cc
        assert not remove_cc

    def test_private_tracker_cc(self):
        """
        test that PS module private tracker CCs are correctly added
        """
        private_tracker_cc = ["me@redhat.com", "you@redhat.com"]
        flaw = FlawFactory(embargoed=True)
        ps_module = PsModuleFactory(
            private_trackers_allowed=True,
            private_tracker_cc=private_tracker_cc,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            component_cc=component_cc,
            component_overrides=component_overrides,
            default_cc=[],
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component=ps_component,
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
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            component_cc=component_cc,
            default_cc=[],
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="brick",
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
        bz_product = BugzillaProductFactory()
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key=bz_product.name,
            component_cc={},
            default_cc=[],
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        BugzillaComponentFactory(
            name=affect.ps_component,
            default_cc=default_cc,
            default_owner="me@redhat.com",
            product=bz_product,
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
        ps_module1 = PsModuleFactory(
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "brick": ["me@redhat.com"],
                "collection": ["you@redhat.com"],
                "stick": ["her@redhat.com"],
            },
            default_cc=[],
        )
        ps_update_stream1 = PsUpdateStreamFactory(
            collections=[
                "brick",
                "stick",
            ],
            ps_module=ps_module1,
        )
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream1.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="brick-collection",
        )

        ps_module2 = PsModuleFactory(
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "apple": ["cat@redhat.com"],
                "apple-juice": ["dog@redhat.com"],
                "juice": ["hamster@redhat.com"],
            },
            default_cc=[],
        )
        ps_update_stream2 = PsUpdateStreamFactory(
            collections=[
                "apple-juice",
                "juice",
            ],
            ps_module=ps_module2,
        )
        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream2.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="apple-juice",
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
        ps_module = PsModuleFactory(
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "brick": ["me@redhat.com"],
                "stick": ["her@redhat.com"],
            },
            default_cc=["you@redhat.com"],
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=[
                "brick",
            ],
            ps_module=ps_module,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="stick",
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
        ps_module = PsModuleFactory(
            bts_key=RHSCL_BTS_KEY,
            bts_name="bugzilla",
            component_cc={
                "brick": ["me@redhat.com"],
                "stick": ["her@redhat.com"],
            },
            default_cc=["you@redhat.com"],
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=[
                "stick",
                "stick-brick",
            ],
            ps_module=ps_module,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="stick-brick",
        )

        cc_builder = CCBuilder(flaw, [])
        add_cc, remove_cc = cc_builder.content
        assert RHSCLAffectCCBuilder(affect, flaw.embargoed).collection is None
        assert add_cc == ["you@redhat.com"]
        assert not remove_cc


class TestJiraAffectCCBuilder:
    """Test JiraAffectCCBuilder functionality"""

    @pytest.mark.parametrize(
        "ps_module,component_cc,ps_component,cc_contact",
        [
            ("rhel10", "firefox", "rhel10/firefox", "me@redhat.com"),
            (
                "rhel10",
                "rhel10/firefox-flatpak",
                "rhel10/firefox-flatpak",
                "me@redhat.com",
            ),
            ("idm", "idm:DL1/ipa", "idm:DL1/ipa", "me@redhat.com"),
        ],
    )
    def test_component_cc(self, ps_module, component_cc, ps_component, cc_contact):
        ps_module = PsModuleFactory(
            name=ps_module,
            bts_name="jboss",
            component_cc={
                component_cc: [cc_contact],
            },
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            ps_update_stream=ps_update_stream.name, ps_component=ps_component
        )
        cc = JiraAffectCCBuilder(affect, False)

        assert cc.generate_cc() == [cc_contact]
