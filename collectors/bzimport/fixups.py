"""
fixups
"""
import re
from typing import Any, List, Tuple

from django.utils.timezone import make_aware

from osidb.dmodels import FlawSource, Impact
from osidb.dmodels.affect import Affect
from osidb.models import Flaw


class AffectFixer:
    """affect fixup handler"""

    def __init__(
        self,
        affect_obj: Affect,
        affect_json: Any,
        ps_module: str,
        ps_component: str,
    ) -> None:
        """init resources"""
        self.affect_obj = affect_obj
        self.affect_json = affect_json
        self.ps_module = ps_module
        self.ps_component = ps_component
        self.errors = []

    def fix(self) -> Tuple[Affect, List[str]]:
        """
        run all fixups and return the result
        plus also return the list of errors
        """
        self.fix_affectedness()
        self.fix_resolution()
        self.fix_impact()
        self.fix_ps_module()

        return self.affect_obj, self.errors

    def fix_affectedness(self) -> None:
        """affectedness fixup"""
        affectedness = (
            # there maybe be explicite None so
            # the default value does not help
            self.affect_json.get("affectedness")
            or Affect.AffectAffectedness.NOVALUE
        ).upper()

        try:
            # convert the string to an enum value
            self.affect_obj.affectedness = Affect.AffectAffectedness(affectedness)
        except ValueError:
            # unless it is not a valid enum value
            self.affect_obj.affectedness = affectedness
            self.errors.append(
                f"{self.ps_module}:{self.ps_component} affect affectedness has invalid value {affectedness}"
            )
        else:
            if self.affect_obj.affectedness == Affect.AffectAffectedness.NOVALUE:
                self.errors.append(
                    f"{self.ps_module}:{self.ps_component} affect has no affectedness value"
                )

    def fix_resolution(self) -> None:
        """resolution fixup"""
        resolution = (
            # there maybe be explicite None so
            # the default value does not help
            self.affect_json.get("resolution")
            or Affect.AffectResolution.NOVALUE
        ).upper()

        try:
            # convert the string to an enum value
            self.affect_obj.resolution = Affect.AffectResolution(resolution)
        except ValueError:
            # unless it is not a valid enum value
            self.affect_obj.resolution = resolution
            if resolution:
                self.errors.append(
                    f"{self.ps_module}:{self.ps_component} affect resolution has invalid value {resolution}"
                )
        else:
            # only some affectedness values allow an empty resolution
            if (
                self.affect_obj.resolution == Affect.AffectResolution.NOVALUE
                and self.affect_obj.affectedness
                not in [
                    Affect.AffectAffectedness.NEW,
                    Affect.AffectAffectedness.NOTAFFECTED,
                ]
            ):
                self.errors.append(
                    f"{self.ps_module}:{self.ps_component} affect has no resolution value"
                )

    def fix_impact(self) -> None:
        """impact fixup"""
        impact = self.affect_json.get("impact")
        if impact and impact.upper() in Impact:
            self.affect_obj.impact = impact.upper()
        else:
            self.affect_obj.impact = Impact.NOVALUE

    def fix_ps_module(self) -> None:
        """PS module fixup"""
        self.affect_obj.ps_module = self.fixplace_ps_module(self.affect_obj.ps_module)

    @staticmethod
    def fixplace_ps_module(ps_module):
        """PS module fixup and replace"""
        # the following code is borrowed from SDEngine
        # In times past we used to put eg 'rhel-6.3' as the affects entry to mean 'rhel-6' if
        # 6.3 happened to be the current minor version. Same with rhev and mrg. Simply strip
        # the minor version so that we can match up with the correct PsModule easier, but
        # *don't* do it on eus streams for example.
        if (
            re.match(r"^rhel-\d\.\d\d?$", ps_module)
            or re.match(r"^rhev-m-3\.", ps_module)
            or re.match(r"^mrg-\d\.", ps_module)
        ):
            return ps_module.partition(".")[0]
        return ps_module


class FlawFixer:
    """flaw fixup handler"""

    def __init__(
        self,
        flaw_obj: Flaw,
        flaw_json: Any,
        srtnotes: Any,
    ) -> None:
        """init resources"""
        self.flaw_obj = flaw_obj
        self.flaw_json = flaw_json
        self.srtnotes = srtnotes
        self.errors = []

    def fix(self) -> Tuple[Flaw, List[str]]:
        """
        run all fixups and return the result
        plus also return the list of errors
        """
        self.fix_title()
        self.fix_description()
        self.fix_summary()

        if not self.srtnotes:
            self.errors.append("has no srtnotes")
            # stop here as we get all the other
            # attributes from SRT notes
            return self.flaw, self.errors

        self.fix_unembargo_dt()
        self.fix_impact()
        self.fix_mitigation()
        self.fix_statement()
        self.fix_reported_dt()
        self.fix_source()
        self.fix_cwe_id()

        return self.flaw_obj, self.errors

    def fix_title(self) -> None:
        """
        title fixup

        we strip the summary prefixes without checking them
        and then try to get and store the component
        """
        if "summary" not in self.flaw_json:
            self.errors.append("no summary")
            # here we do not have to default as the
            # non-empty value is enforced by the model
            return

        title = self.flaw_json["summary"]

        # try to strip EMBARGOED
        title = re.sub(r"^EMBARGOED\s*", "", title)
        # try to strip TRIAGE
        title = re.sub(r"^TRIAGE(-|\s*)", "", title)
        # try to strip CVE IDs possibly followed by three dots
        title = re.sub(r"^(CVE-[0-9]{4}-[0-9]+\s*)+\.*\s*", "", title)

        component_res = re.search(r"\s*([^\s]+:)", title)
        components = []
        while component_res:
            title = title[component_res.span()[1] :].strip()
            components.append(component_res.group()[:-1].strip())
            component_res = re.search(r"^\s*([^\s]+:)", title)

        if not components:
            self.errors.append("no component")

        # store flaw component
        self.flaw_obj.components = components

        # strip any whitespace
        title = title.strip()

        # if left with an empty string a meaningful title is missing
        if not title:
            self.errors.append("no title")

        # store flaw title
        self.flaw_obj.title = title

    def fix_description(self) -> None:
        """description fixup"""
        if "description" in self.flaw_json:
            self.flaw_obj.comment_zero = self.flaw_json["description"]
        else:
            self.errors.append("no description")
            # here we do not have to default as the
            # non-empty value is enforced by the model

    def fix_summary(self) -> None:
        """summary fixup"""
        if "cf_release_notes" in self.flaw_json:
            self.flaw_obj.cve_description = self.flaw_json["cf_release_notes"]
        else:
            self.errors.append("no cf_release_notes")
            self.flaw_obj.cve_description = ""

    def fix_unembargo_dt(self) -> None:
        """unembargo_dt fixup"""
        if self.srtnotes.get("public"):
            self.flaw_obj.unembargo_dt = make_aware(self.srtnotes["public"])
        else:
            self.errors.append("has no unembargo_dt (public date)")
            self.flaw_obj.unembargo_dt = None

    def fix_impact(self) -> None:
        """impact fixup"""
        impact = self.srtnotes.get("impact")
        if impact and impact.upper() in Impact:
            self.flaw_obj.impact = impact.upper()
        else:
            self.errors.append("impact has NOVALUE")
            self.flaw_obj.impact = Impact.NOVALUE

    def fix_mitigation(self) -> None:
        """mitigation fixup"""
        self.flaw_obj.mitigation = self.srtnotes.get("mitigation")

    def fix_statement(self) -> None:
        """statement fixup"""
        self.flaw_obj.statement = self.srtnotes.get("statement")

    def fix_reported_dt(self) -> None:
        """reported_dt fixup"""
        if self.srtnotes.get("reported"):
            self.flaw_obj.reported_dt = make_aware(self.srtnotes["reported"])
        else:
            self.errors.append("has no reported_dt (reported)")
            self.flaw_obj.reported_dt = None

    SOURCE_VALUE_MAP = {
        "vendorsec": FlawSource.VENDOR_SEC,
        "fulldisclosure": FlawSource.FULL_DISCLOSURE,
        "osssecurity": FlawSource.OSS_SECURITY,
        "sunalert": FlawSource.SUN,
        "sunsolve": FlawSource.SUN,
        "hw-vendor": FlawSource.HW_VENDOR,
        "hwvendor": FlawSource.HW_VENDOR,
        "fulldisc": FlawSource.FULL_DISCLOSURE,
    }

    def fix_source(self) -> None:
        """source fixup"""
        source = self.srtnotes.get("source")
        if source:
            if source in self.SOURCE_VALUE_MAP:
                self.errors.append(f"rewrite source: {source}")
                self.flaw_obj.source = self.SOURCE_VALUE_MAP[source]
            else:
                # otherwise remove all dashes and make uppercase
                self.flaw_obj.source = re.sub("-", "", source).upper()
        else:
            self.errors.append("source has no value")
            self.flaw_obj.source = FlawSource.NOVALUE

    def fix_cwe_id(self) -> None:
        """cwe_id fixup"""
        self.flaw_obj.cwe_id = self.srtnotes.get("cwe")
