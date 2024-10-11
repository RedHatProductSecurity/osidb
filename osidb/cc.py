"""
CC list builders for
- Bugzilla Flaw
- Bugzilla Flaw's Affect (and Bugzilla-based Tracker)
- Jira-based Tracker (described using a Flaw's Affect)
"""

import logging
import re
from functools import cached_property
from itertools import chain
from typing import List, Optional, Tuple

from apps.bbsync.constants import USER_BLACKLIST
from apps.bbsync.exceptions import ProductDataError
from apps.bbsync.models import BugzillaComponent
from osidb.models import PsContact, PsModule, PsUpdateStream
from osidb.models.affect import Affect
from osidb.models.flaw.flaw import Flaw

logger = logging.getLogger(__name__)


class WrongBtsWithJiraAffectCCBuilderError(Exception):
    """
    Error caused by trying to use JiraAffectCCBuilder to generate CC lists
    for a module not tracked in Jira.
    """


class BaseAffectCCBuilder:
    def __init__(
        self, affect: Affect, embargoed: bool, bts_name_override: Optional[str] = None
    ) -> None:
        """
        init stuff
        expects a valid affect
        """
        self.affect = affect
        self.ps_module = affect.ps_module
        self.ps_component = affect.ps_component
        self.ps_module_obj = PsModule.objects.get(name=affect.ps_module)
        # In some specific scenarios (see OSIDB-2985) we need to generate CC lists
        # in Bugzilla format even for Jira tracker PS modules (namely when generating Flaw CC list),
        # in such scenarios we need to override the CC list format
        self.bts_name = bts_name_override or self.ps_module_obj.bts_name
        self.embargoed = embargoed

        super().__init__()

    @property
    def is_bugzilla(self) -> bool:
        """
        check that this PS module is tracked in Bugzilla
        """
        return self.bts_name == "bugzilla"

    @cached_property
    def cc(self) -> List[str]:
        """
        CC list getter
        """
        return self.generate_cc()

    def generate_cc(self) -> List[str]:
        """
        CC list generator
        """
        # skip modules with private trackers not allowed if embargoed
        if self.embargoed and not self.ps_module_obj.private_trackers_allowed:
            return []

        cc_list = self.module_cc() + self.component_cc() + self.bugzilla_cc()

        cc_list = [self.expand_alias(cc) for cc in cc_list]
        if self.is_bugzilla:
            cc_list = [self.append_domain(cc) for cc in cc_list]

        if self.embargoed:
            # If embargoed we need to additionally ensure that
            # we do not add non-RH or bot or invalid accounts.
            # Non-email-formatted usernames are allowed For Jira.
            cc_list = [
                cc
                for cc in cc_list
                if not self.is_blacklisted(cc)
                and (self.is_redhat(cc) or ("@" not in cc and not self.is_bugzilla))
            ]

        return cc_list

    def append_domain(self, cc: str) -> str:
        """
        append @redhat.com domain
        in case no domain is present
        """
        return cc if self.is_email(cc) else f"{cc}@redhat.com"

    def expand_alias(self, cc: str) -> str:
        """
        expand an alias to the actual email
        in the case this is actually an alias
        """
        if self.is_email(cc):
            return cc

        contact = PsContact.objects.filter(username=cc).first()
        if not contact:
            return cc

        if self.bts_name == "bugzilla":
            return contact.bz_username

        elif self.bts_name == "jboss":
            return contact.jboss_username

        else:
            raise ProductDataError(f"Unknown BTS name {self.ps_module_obj.bts_name}")

    def is_blacklisted(self, cc: str) -> bool:
        """
        check and return whether the CC is on the blacklist
        contains mostly bot and invalid Bugzilla accounts
        """
        return cc in USER_BLACKLIST

    def is_email(self, cc: str) -> bool:
        """
        check and return whether the CC is an email

        this is only an estimation but as there are
        either emails or aliases it should be correct
        """
        return "@" in cc

    def is_redhat(self, cc: str) -> bool:
        """
        check and return whether the CC is RH one
        """
        return cc.endswith("@redhat.com")

    def module_cc(self) -> List[str]:
        """
        generate CCs based on module
        """
        cc_list = []

        # default CCs
        if self.ps_module_obj.default_cc:
            cc_list.extend(self.ps_module_obj.default_cc)

        if self.embargoed and self.ps_module_obj.private_tracker_cc:
            cc_list.extend(self.ps_module_obj.private_tracker_cc)

        return cc_list

    def component_cc(self) -> List[str]:
        """
        generate CCs based on component
        """
        # exact match
        if self.bz_component in self.ps_module_obj.component_cc:
            return self.ps_module_obj.component_cc[self.bz_component]

        cc_list = []
        # wildcard match
        for component_pattern, component_cc in self.ps_module_obj.component_cc.items():
            if "*" in component_pattern:
                re_pattern = re.escape(component_pattern).replace("\\*", ".+")
                if re.match(re_pattern, self.bz_component):
                    cc_list.extend(component_cc)

        return cc_list

    def bugzilla_cc(self) -> List[str]:
        """
        generate CCs based on Bugzilla product and component
        """
        if not self.is_bugzilla:
            return []

        bz_component_obj = BugzillaComponent.objects.filter(
            product__name=self.ps_module_obj.bts_key, name=self.bz_component
        ).first()

        if not bz_component_obj:
            return []

        cc_list = []
        if bz_component_obj.default_cc:
            cc_list.extend(bz_component_obj.default_cc)
        if bz_component_obj.default_owner:
            cc_list.append(bz_component_obj.default_owner)

        return cc_list


class JiraAffectCCBuilder(BaseAffectCCBuilder):
    """
    CC list builder for a single Affect when the resulting list is to be used
    with a Jira-based Tracker. Remember to gather CC list for each Affect for
    multi-affect Trackers.
    """

    def __init__(
        self, affect: Affect, embargoed: bool, bts_name_override: Optional[str] = None
    ) -> None:
        """
        init stuff, works only for Jira
        expects a valid affect
        """
        super().__init__(affect, embargoed, bts_name_override)

        if self.ps_module_obj.bts_name != "jboss":
            raise WrongBtsWithJiraAffectCCBuilderError

        # SFM2 uses a thing called "bz_component" even for *jira*-tracked modules.
        # Its contents are somewhat different from bugzilla-tracked modules, here in
        # OSIDB illustrated by the differences between JiraAffectCCBuilder and
        # BugzillaAffectCCBuilder (ps2bz_component-equivalent logic not used whole for Jira).
        #
        # In the future, we may opt to make this nicer, but currently our goal is to
        # preserve current SFM2 behavior that is deemed correct and this is too
        # complicated to refactor without risks too endangering our schedule. (as of 2024-04)

        # NOTE That SFM2 for Jira tracker creation uses ps_module.component_overrides only for
        #      generating Jira "components" field, but not for CC lists;
        #      CC list creation is based solely on ps_component, not on bz_component.
        #      Therefore ps2bz_component is not reused here.
        # Parse BZ component
        if self.ps_component and "/" in self.ps_component:
            self.bz_component = self.ps_component.split("/")[-1]
        else:
            self.bz_component = self.ps_component


class BugzillaAffectCCBuilder(BaseAffectCCBuilder):
    """
    bugzilla affect CC list builder

    Dual use:

    1. CC list builder for a single Affect when generating CC lists for a
       Flaw (saved in Bugzilla). This is done by BugzillaFlawCCBuilder.

    2. CC list builder for a single Affect when the resulting list is to be used
       with a BZ-based Tracker. Remember to gather CC list for each Affect for
       multi-affect Trackers.
    """

    def __init__(
        self, affect: Affect, embargoed: bool, bts_name_override: Optional[str] = None
    ) -> None:
        """
        init stuff
        expects a valid affect
        """
        super().__init__(affect, embargoed, bts_name_override)

        self.bz_component = self.ps2bz_component() if self.is_bugzilla else None

    def ps2bz_component(self) -> str:
        """
        translate PS component to Bugzilla one

        there are three posible options how to map to the Bugzilla component

            component overrides: mapping defined in PS module
            component split-off: container-tools:rhel8/podman -> podman
            identity:            podman -> podman

        """
        if (
            self.ps_module_obj.component_overrides
            and self.ps_component in self.ps_module_obj.component_overrides
        ):
            override = self.ps_module_obj.component_overrides[self.ps_component]
            if override is not None:
                return override["component"] if isinstance(override, dict) else override

        elif "/" in self.ps_component:
            return self.ps_component.split("/")[-1]

        return self.ps_component


class RHSCLBugzillaAffectCCBuilder(BugzillaAffectCCBuilder):
    """
    Red Hat Software Collections affect CC list builder
    introduces special differences from the parent class
    """

    collection = None

    def collections(self) -> List[str]:
        """
        generate collections for the PS module
        """
        return list(
            set(
                chain.from_iterable(
                    PsUpdateStream.objects.filter(
                        ps_module__name=self.ps_module
                    ).values_list("collections", flat=True)
                )
            )
        )

    def collection_component(self) -> Tuple[Optional[str], str]:
        """
        parse RHSCL PS component into collection and
        Bugzilla component and return them as a tuple

            ps_component | collection | result
            ----------------------------------
            podman         truck        None podman
            podman         podman       podman podman
            podman-thing   podman       podman thing

        """
        matched_collections = [
            collection
            for collection in self.collections()
            if self.ps_component.startswith(collection + "-")
            or self.ps_component == collection
        ]

        if not matched_collections or len(matched_collections) > 1:
            return None, self.ps_component

        collection = matched_collections[0]
        if collection and self.ps_component != collection:
            return collection, self.ps_component[len(collection) + 1 :]

        return collection, self.ps_component

    def ps2bz_component(self) -> str:
        """
        translate PS component to Bugzilla one
        RH software collections special case
        """
        self.collection, bz_component = self.collection_component()
        return bz_component

    def component_cc(self) -> List[str]:
        """
        generate CCs based on component
        RH software collections special case
        """
        cc_list = self.ps_module_obj.component_cc.get(self.bz_component, [])
        cc_list.extend(self.ps_module_obj.component_cc.get(self.collection, []))

        return cc_list


class BugzillaFlawCCBuilder:
    """
    Bugzilla flaw CC list array builder
    """

    def __init__(self, flaw: Flaw, old_cc: list) -> None:
        """
        init stuff
        """
        self.flaw = flaw
        self.old_cc = old_cc

    @property
    def content(self) -> Tuple[List[str], List[str]]:
        """
        content getter shorcut
        sort result to easy compare
        """
        add_cc, remove_cc = self.generate()
        return sorted(add_cc), sorted(remove_cc)

    def generate(self) -> Tuple[List[str], List[str]]:
        """
        generate content
        """
        all_cc = self.affect_list2cc(self.flaw.affects.all())
        add_cc = [cc for cc in all_cc if cc not in self.old_cc]
        # simplify the functionality by only adding people
        # who where never added before (accumulating)
        # and never removing anyone - they can do it
        return add_cc, []

    def affect_list2cc(self, affects: List[Affect]) -> List[str]:
        """
        process the list of affects and return the corresponding list of CCs
        """
        cc_list = set()

        for affect in affects:
            # exclude unknown PS modules
            if affect.is_unknown:
                logger.error(
                    f"Affect {affect.uuid} contains unknown PS module: {affect.ps_module}"
                )
                continue

            # exclude community products
            # which was requested to reduce the spam to the communities
            if affect.is_community:
                continue

            # for some reason in SFM2 we ignore affects set as not affected or not to be fixed
            # only for embargoed flaws so to keep the functional parity we continue with it
            if self.flaw.is_embargoed and affect.is_notaffected:
                continue

            cc_list.update(self.affect2cc(affect))

        return list(cc_list)

    def affect2cc(self, affect: Affect) -> List[str]:
        """
        process an affect and return the corresponding list of CCs
        """
        affect_cc_builder_class = (
            RHSCLBugzillaAffectCCBuilder if affect.is_rhscl else BugzillaAffectCCBuilder
        )
        affect_cc_builder = affect_cc_builder_class(
            affect, self.flaw.is_embargoed, bts_name_override="bugzilla"
        )
        return affect_cc_builder.cc
