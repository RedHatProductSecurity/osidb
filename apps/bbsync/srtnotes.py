import json
from typing import Union

import jsonschema

from osidb.models import Affect, AffectCVSS, FlawCVSS, FlawReference, Tracker

from .constants import DATE_FMT, DATETIME_FMT, SRTNOTES_SCHEMA_PATH
from .exceptions import SRTNotesValidationError


class SRTNotesBuilder:
    """
    Bugzilla flaw bug SRT notes field JSON content builder
    """

    def __init__(self, flaw, old_flaw=None):
        """
        init stuff
        parametr old_flaw is optional as there is no old flaw on creation
        and if not set we consider the query to be a create query
        """
        self.flaw = flaw
        self.old_flaw = old_flaw
        self._json = None
        self._original_keys = []

    @property
    def content(self):
        """
        string content getter shorcut
        """
        if self._json is None:
            self.generate()
            self.validate()

        return json.dumps(self._json)

    def add_conditionally(self, key, value, empty_value=None):
        """
        conditionally add the value to the SRT notes field
        unless it is empty and was not originally present

        this is to make less noise in Bugzilla history
        """
        # value was there already
        if key in self._original_keys:
            self._json[key] = value

        # some attributes have special values to denote emptyness
        # for example empty impact has string value of "none"
        elif empty_value is not None:
            if value != empty_value:
                self._json[key] = value

        # some values are empty when their boolean conversion is False
        # for example arrays or strings or timestamps
        elif value:
            self._json[key] = value

    def generate(self):
        """
        generate json content
        """
        self.restore_original()
        self.generate_acknowledgments()
        self.generate_affects()
        self.generate_date("unembargo_dt", "public")
        self.generate_date("reported_dt", "reported")
        self.generate_impact()
        self.generate_jira_trackers()
        self.generate_references()
        self.generate_flaw_cvss()
        self.generate_source()
        self.generate_string("cwe_id", "cwe")
        self.generate_string("mitigation", "mitigation")
        self.generate_string("statement", "statement")

    def generate_acknowledgments(self):
        """
        generate array of acknowledgments to SRT notes
        """
        self.add_conditionally(
            "acknowledgments",
            [
                {
                    "affiliation": ack.affiliation,
                    "from_upstream": ack.from_upstream,
                    "name": ack.name,
                }
                for ack in self.flaw.acknowledgments.all()
            ],
        )

    def generate_affects(self):
        """
        generate array of affects to SRT notes
        """

        def get_cvss(affect: Affect, version: FlawCVSS.CVSSVersion) -> Union[str, None]:
            return (
                None
                if not affect.cvss_scores.filter(
                    issuer=AffectCVSS.CVSSIssuer.REDHAT, version=version
                )
                else "{}/{}".format(
                    *affect.cvss_scores.filter(
                        issuer=AffectCVSS.CVSSIssuer.REDHAT, version=version
                    ).values_list("score", "vector")[0]
                )
            )

        self.add_conditionally(
            "affects",
            [
                {
                    "ps_module": affect.ps_module,
                    "ps_component": affect.ps_component,
                    "affectedness": affect.affectedness.lower() or None,
                    "resolution": affect.resolution.lower() or None,
                    # there is an interesting fact that the impact may be null or none
                    # while these two values hold the same information (empty impact)
                    # so let us prefer null which may cause some unexpected rewrites
                    # from none to null but this can be considered as data fixes
                    "impact": affect.impact.lower() or None,
                    # CVSSv2, CVSSv3 and CVSSv4 are from AffectCVSS
                    "cvss2": get_cvss(affect, AffectCVSS.CVSSVersion.VERSION2),
                    "cvss3": get_cvss(affect, AffectCVSS.CVSSVersion.VERSION3),
                    "cvss4": get_cvss(affect, AffectCVSS.CVSSVersion.VERSION4),
                }
                for affect in self.flaw.affects.all()
            ],
        )

    def generate_date(self, flaw_attribute, srtnotes_attribute):
        """
        generate given date attribute

        it can be either date or datetime so we should check the old
        value and preserve the format when the value does not change
        """
        date_value = getattr(self.flaw, flaw_attribute)
        if not date_value:
            self.add_conditionally(srtnotes_attribute, None)
            return

        date_str = date_value.strftime(DATE_FMT)
        if (
            srtnotes_attribute in self._original_keys
            and self.old_flaw
            and date_value == getattr(self.old_flaw, flaw_attribute)
            and self._json[srtnotes_attribute] == date_str
        ):
            # we prefer datetime format but if there was just date format
            # before and the value does not change we keep the old format
            pass

        else:
            self._json[srtnotes_attribute] = date_value.strftime(DATETIME_FMT)

    def generate_impact(self):
        """
        generate impact attribute
        """
        impact = "none" if not self.flaw.impact else self.flaw.impact.lower()
        self.add_conditionally("impact", impact, empty_value="none")

    def generate_jira_trackers(self):
        """
        generate array of Jira tracker identifier pairs
        consisting of BTS name being Jira instance identifier
        and Jira issue key in given Jira instance
        """
        self.add_conditionally(
            "jira_trackers",
            [
                # BTS name is always jboss which is the
                # historical naming of the only Jira instance we use
                {"bts_name": "jboss", "key": tracker.external_system_id}
                for affect in self.flaw.affects.all()
                for tracker in affect.trackers.filter(type=Tracker.TrackerType.JIRA)
            ],
        )

    def generate_references(self):
        """
        generate array of references to SRT notes

        OSIDB uses "ARTICLE", "EXTERNAL" and "SOURCE",
        but Bugzilla uses "vuln_response", "external" and "source".
        """
        references_mapping = {
            FlawReference.FlawReferenceType.ARTICLE: "vuln_response",
            FlawReference.FlawReferenceType.EXTERNAL: "external",
            FlawReference.FlawReferenceType.SOURCE: "source",
        }

        self.add_conditionally(
            "references",
            [
                {
                    "type": references_mapping[reference.type],
                    "url": reference.url,
                    "description": reference.description or None,
                }
                for reference in self.flaw.references.all()
            ],
        )

    def generate_flaw_cvss(self):
        """
        generate cvss2, cvss3, cvss3_comment, cvss4 and cvss4_comment attributes
        """

        def get_cvss(version: FlawCVSS.CVSSVersion) -> Union[tuple, None]:
            return (
                self.flaw.cvss_scores.filter(issuer=FlawCVSS.CVSSIssuer.REDHAT)
                .filter(version=version)
                .values_list("score", "vector", "comment")
                .first()
            )

        cvss2 = get_cvss(FlawCVSS.CVSSVersion.VERSION2)
        cvss3 = get_cvss(FlawCVSS.CVSSVersion.VERSION3)
        cvss4 = get_cvss(FlawCVSS.CVSSVersion.VERSION4)

        cvss2_string = f"{cvss2[0]}/{cvss2[1]}" if cvss2 else None
        cvss3_string, cvss3_comment = (
            (f"{cvss3[0]}/{cvss3[1]}", cvss3[2]) if cvss3 else (None, None)
        )
        cvss4_string, cvss4_comment = (
            (f"{cvss4[0]}/{cvss4[1]}", cvss4[2]) if cvss4 else (None, None)
        )

        for key, value in [
            ("cvss2", cvss2_string),
            ("cvss3", cvss3_string),
            ("cvss3_comment", cvss3_comment),
            ("cvss4", cvss4_string),
            ("cvss4_comment", cvss4_comment),
        ]:
            self.add_conditionally(key, value)

    def generate_source(self):
        """
        generate source attribute
        """
        # HW_VENDOR is represented as hw-vendor in data
        source = self.flaw.source.lower().replace("_", "-")
        source = source if source else None
        self.add_conditionally("source", source)

    def generate_string(self, flaw_attribute, srtnotes_attribute):
        """
        generate given string attribute
        generic generator for string attributes with no special handling
        """
        self.add_conditionally(
            srtnotes_attribute, getattr(self.flaw, flaw_attribute) or None
        )

    def restore_original(self):
        """
        restore the original SRT notes attributes
        this ensures that we preserve potential unknown attributes intact
        """
        srtnotes = self.flaw.meta_attr.get("original_srtnotes")
        self._json = json.loads(srtnotes) if srtnotes else {}
        self._original_keys = list(self._json.keys())

    def validate(self):
        """
        validation safeguard to ensure that we always create valid SRT notes JSON data
        throws SRTNotesValidationError exception in the case of invalid SRT notes JSON
        """
        with open(SRTNOTES_SCHEMA_PATH) as schema_fp:
            self.srtnotes_schema = json.load(schema_fp)

        try:
            jsonschema.validate(self._json, schema=self.srtnotes_schema)
        except jsonschema.ValidationError:
            raise SRTNotesValidationError("Invalid JSON produced for SRT notes")
