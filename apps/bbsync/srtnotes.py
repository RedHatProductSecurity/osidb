import json
from ast import literal_eval

import jsonschema

from osidb.models import FlawMeta, Tracker

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
        # TODO the references are not yet fully implemented in OSIDB
        # this requirement is trackerd in OSIDB-71 and when fulfilled
        # we need to implement generate_references accordingly
        self.generate_source()
        self.generate_string("cvss2", "cvss2")
        self.generate_string("cvss3", "cvss3")
        # TODO the CVSS comments are not yet supported in OSIDB and tracked as part of OSIDB-377
        # we need to implement their SRT notes generator afterwards and probably modify
        # the existing CVSS into SRT notes generation too
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
                    "affiliation": meta.meta_attr["affiliation"],
                    # hstore holds bolean values as strings containing True|False
                    # so we need to explicitly convert it to the bolean value
                    "from_upstream": literal_eval(meta.meta_attr["from_upstream"]),
                    "name": meta.meta_attr["name"],
                }
                for meta in self.flaw.meta.all()
                if meta.type == FlawMeta.FlawMetaType.ACKNOWLEDGMENT
            ],
        )

    def generate_affects(self):
        """
        generate array of affects to SRT notes
        """
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
                    "cvss2": affect.cvss2 or None,
                    "cvss3": affect.cvss3 or None,
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
