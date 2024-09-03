"""
Jira tracker query generation module
"""
import json
import logging
from datetime import datetime
from functools import cached_property

from django.utils.timezone import make_aware

from apps.sla.framework import sla_classify
from apps.trackers.common import TrackerQueryBuilder
from apps.trackers.exceptions import (
    ComponentUnavailableError,
    MissingEmbargoStatusError,
    MissingJiraProjectMetadata,
    MissingPriorityError,
    MissingSecurityLevelError,
    MissingSeverityError,
    MissingSourceError,
    MissingSpecialHandlingError,
    MissingTargetReleaseVersionError,
    MissingVulnerabilityIssueFieldError,
    TrackerCreationError,
)
from apps.trackers.models import JiraProjectFields
from collectors.jiraffe.constants import JIRA_BZ_ID_LABEL_RE
from osidb.cc import JiraAffectCCBuilder
from osidb.helpers import cve_id_comparator
from osidb.models import Affect, AffectCVSS, Flaw, FlawSource, Impact
from osidb.validators import CVE_RE_STR

from .constants import (
    JIRA_EMBARGO_SECURITY_LEVEL_NAME,
    JIRA_INTERNAL_SECURITY_LEVEL_NAME,
    PS_ADDITIONAL_FIELD_TO_JIRA,
)

logger = logging.getLogger(__name__)


class JiraPriority:
    """
    Allowed Jira priorities compliant with OJA-PRIS-001
    """

    BLOCKER = "Blocker"
    CRITICAL = "Critical"
    MAJOR = "Major"
    NORMAL = "Normal"
    MINOR = "Minor"
    UNDEFINED = "Undefined"


IMPACT_TO_JIRA_PRIORITY = {
    Impact.CRITICAL: [JiraPriority.CRITICAL],
    Impact.IMPORTANT: [JiraPriority.MAJOR],
    Impact.MODERATE: [
        JiraPriority.NORMAL,
        JiraPriority.MINOR,
    ],  # some projects still miss Normal priority
    Impact.LOW: [JiraPriority.MINOR],
    # mapping below is just safeguard
    # but we should never file such trackers
    Impact.NOVALUE: [JiraPriority.UNDEFINED],
}

FLAW_SOURCE_TO_JIRA_SOURCE = {
    # This lists all jira allowed values as of 2024-08 even for
    # FlawSource that are not in FlawSource.allowed for maximum
    # pairing coverage.
    # The "# None:" jira values have no FlawSource equivalent.
    #
    # None: 'Security Architecture Review (SAR)',
    # None: 'Threat Model (TM)',
    # None: 'Penetration Test (PenTest)',
    # None: 'Static Application Security Testing (SAST)',
    # None: 'Dynamic Application Security Testing (DAST)',
    #
    FlawSource.ADOBE: "Adobe",
    FlawSource.APPLE: "Apple",
    FlawSource.BUGTRAQ: "Bugtraq",
    FlawSource.CERT: "CERT",
    FlawSource.CUSTOMER: "Customer",
    FlawSource.CVE: "CVE",
    FlawSource.CVEORG: "CVEORG",
    FlawSource.DEBIAN: "Debian",
    FlawSource.DISTROS: "Distros",
    FlawSource.FULL_DISCLOSURE: "Full Disclosure",
    FlawSource.GENTOO: "Gentoo",
    FlawSource.GIT: "Git",
    FlawSource.GOOGLE: "Google",
    FlawSource.HW_VENDOR: "Hardware Vendor",
    FlawSource.INTERNET: "Internet",
    FlawSource.LKML: "LKML",
    FlawSource.MAGEIA: "Mageia",
    FlawSource.MOZILLA: "Mozilla",
    FlawSource.NVD: "NVD",
    FlawSource.OPENSSL: "OpenSSL",
    FlawSource.ORACLE: "Oracle",
    FlawSource.OSS_SECURITY: "OSS-Security",
    FlawSource.OSV: "OSV",
    FlawSource.REDHAT: "Red Hat",
    FlawSource.RESEARCHER: "Researcher",
    FlawSource.SECUNIA: "Secunia",
    FlawSource.SKO: "Sko",
    FlawSource.SUN: "Sun",
    FlawSource.SUSE: "Suse",
    FlawSource.TWITTER: "Twitter",
    FlawSource.UBUNTU: "Ubuntu",
    FlawSource.UPSTREAM: "Upstream",
    # TODO: Double-check that vendor_sec is correct. Tracked in OSIDB-3352.
    FlawSource.VENDOR_SEC: "vendor_sec",
    # TODO: Double-check that Xen is correct. Tracked in OSIDB-3352.
    FlawSource.XEN: "Xen",
}


class JiraSeverity:
    """
    Allowed Jira severity values compatible with
    https://access.redhat.com/security/updates/classification
    """

    CRITICAL = "Critical"
    IMPORTANT = "Important"
    MODERATE = "Moderate"
    LOW = "Low"
    NONE = "None"


class JiraSeverityAlternative:
    """
    Allowed Jira severity values NOT compatible with
    https://access.redhat.com/security/updates/classification
    but used in some Jira projects.
    """

    # "Schema 2"
    BLOCKER = "Blocker"
    CRITICAL = "Critical"
    MAJOR = "Major"
    NORMAL = "Normal"
    MINOR = "Minor"
    TRIVIAL = "Trivial"

    # "Schema 3"
    URGENT = "Urgent"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


IMPACT_TO_JIRA_SEVERITY = {
    Impact.CRITICAL: [
        JiraSeverity.CRITICAL,
        JiraSeverityAlternative.CRITICAL,
        JiraSeverityAlternative.URGENT,
    ],
    Impact.IMPORTANT: [
        JiraSeverity.IMPORTANT,
        JiraSeverityAlternative.MAJOR,
        JiraSeverityAlternative.HIGH,
    ],
    Impact.MODERATE: [
        JiraSeverity.MODERATE,
        JiraSeverityAlternative.NORMAL,
        JiraSeverityAlternative.MEDIUM,
    ],
    Impact.LOW: [
        JiraSeverity.LOW,
        JiraSeverityAlternative.MINOR,
        JiraSeverityAlternative.LOW,
    ],
}


# NOTE that these four values can change, as they are for sanity-checking
# allowed values for Jira field Special Handling.
MAJOR_INCIDENT = "Major Incident"
KEV = "KEV (active exploit case)"
COMPLIANCE_PRIORITY = "Compliance Priority"
CONTRACT_PRIORITY = "Contract Priority"


class OldTrackerJiraQueryBuilder(TrackerQueryBuilder):
    """
    Jira tracker bug query builder
    to generate general tracker save query
    """

    def __init__(self, instance):
        """
        init stuff
        """
        self.instance = instance
        self._query = None
        self._comment = None

    @cached_property
    def impact(self):
        """
        cached tracker maximum impact
        """
        return self.tracker.aggregated_impact

    @cached_property
    def reported_dt(self):
        """
        cached earliest reported date
        """
        self.tracker.affects.order_by("flaw__reported_dt")[0].flaw.reported_dt

    def generate(self):
        """
        generate query
        """
        self.generate_base()
        self.generate_component()
        self.generate_priority()
        self.generate_description()
        self.generate_labels()
        self.generate_sla()
        self.generate_summary()
        self.generate_versions()
        self.generate_additional_fields()
        self.generate_security()
        self.generate_cc()
        self.generate_target_release()

    def generate_base(self):
        self._query = {
            "fields": {
                "issuetype": {"name": "Bug"},
                "project": {"key": self.ps_module.bts_key},
            }
        }
        if self.tracker.external_system_id:
            self._query["key"] = self.tracker.external_system_id

    def generate_component(self):
        """
        Generate Jira "components" field (with 1 component)
        """

        component = self.ps_component

        try:
            allowed_component_values = JiraProjectFields.objects.get(
                project_key=self.ps_module.bts_key, field_id="components"
            ).allowed_values
        except JiraProjectFields.DoesNotExist:
            # In some cases this information is not available. In that case, Jira will return
            # its own error if the component is invalid. So in that case, skip OSIDB-side checks.
            # JiraProjectFields may not be available
            # - in tests
            # - when OSIDB is run freshly without running product_definitions_collector and metadata_collector first
            # - if metadata_collector fails for some reason
            allowed_component_values = None

        # Component override, mirrors SFM2
        what_component = "component"  # just to display correct exception msg when component is not found

        if (
            self.ps_module.component_overrides
            and self.ps_component in self.ps_module.component_overrides
        ):
            what_component = "overridden component"
            override = self.ps_module.component_overrides[self.ps_component]
            if override is not None:
                component = (
                    override["component"] if isinstance(override, dict) else override
                )
        elif self.ps_module.bts_key == "RHEL" and component != (
            parsed_bz_component := self.ps_component.split("/")[-1]
            if "/" in self.ps_component
            else self.ps_component
        ):
            # RHEL-specific modular ps_component splitting
            # FIXME: make this not be RHEL specific (this line brought over from SFM2, not sure about current status as of 2024-06)
            what_component = "modular rpm component"
            component = parsed_bz_component
        elif (
            self.ps_module.default_component
            and allowed_component_values
            and component not in allowed_component_values
        ):
            # Use default when ps_component does not match a Jira component
            what_component = "default component"
            component = self.ps_module.default_component
            logger.warning(
                f"""Component "{self.ps_component}" overriden to default "{component}" for ps_module "{self.ps_module.name}" and ps_update_stream "{self.ps_update_stream.name}"."""
            )

        if allowed_component_values and component not in allowed_component_values:
            raise ComponentUnavailableError(
                f"""Tracker {what_component} "{component}" is not valid for """
                f"Jira project {self.ps_module.bts_key}."
            )

        self._query["fields"]["components"] = [{"name": component}]

    def generate_priority(self):
        """
        Convert OSIDB impact to Jira Priority
        """
        try:
            allowed_values = JiraProjectFields.objects.get(
                project_key=self.ps_module.bts_key, field_id="priority"
            ).allowed_values
        except JiraProjectFields.DoesNotExist:
            raise MissingJiraProjectMetadata(
                f"Metadata for Jira project {self.ps_module.bts_key} are missing."
            )

        for priority in IMPACT_TO_JIRA_PRIORITY[self.impact]:
            if priority in allowed_values:
                self._query["fields"]["priority"] = {"name": priority}
                return

        raise MissingPriorityError(
            f"Jira project {self.ps_module.bts_key} does not have a corresponding priority for impact "
            f"{self.impact}; allowed Jira priority values are: {', '.join(allowed_values)}"
        )

    def generate_description(self):
        """
        generates query for the tracker description
        """
        self._query["fields"]["description"] = self.description

    def generate_labels(self):
        """
        generate query for Jira labels
        """

        all_existing_labels = json.loads(self.tracker.meta_attr.get("labels", "[]"))

        # These labels are from elsewhere than this method and preserved with their ordering intact.
        # Because the engineering may use them.
        labels_to_preserve = [
            lbl
            for lbl in all_existing_labels
            if not (
                # Labels matching this condition will be recreated as needed.
                lbl.startswith("pscomponent:")
                or lbl in ["SecurityTracking", "Security", "validation-requested"]
                or CVE_RE_STR.match(lbl)
                or JIRA_BZ_ID_LABEL_RE.match(lbl)
            )
        ]

        # sort the labels to keep them consistent
        self._query["fields"]["labels"] = sorted(
            [
                *labels_to_preserve,
                "SecurityTracking",
                "Security",
                f"pscomponent:{self.ps_component}",
                *list(  # add all linked non-empty CVE IDs
                    self.tracker.affects.exclude(flaw__cve_id__isnull=True).values_list(
                        "flaw__cve_id", flat=True
                    )
                ),
                *[  # add all linked flaw UUIDs
                    f"flawuuid:{uuid}"
                    for uuid in self.tracker.affects.filter(
                        flaw__isnull=False
                    ).values_list("flaw__uuid", flat=True)
                ],
                *[  # add all linked non-empty BZ IDs
                    "flaw:bz#" + meta_attr["bz_id"]
                    for meta_attr in self.tracker.affects.filter(
                        flaw__meta_attr__bz_id__isnull=False
                    ).values_list("flaw__meta_attr", flat=True)
                ],
            ]
        )

        # If all affects are NEW, add label validation-requested.
        if set(self.tracker.affects.all().values_list("affectedness", flat=True)) == {
            Affect.AffectAffectedness.NEW
        }:
            self._query["fields"]["labels"].append("validation-requested")

        # If at least one affect has is_contract_priority, add label contract-priority
        if self.tracker.is_contract_priority:
            self._query["fields"]["labels"].append("contract-priority")

        if self.tracker.is_compliance_priority:
            self._query["fields"]["labels"].append("compliance-priority")

    def generate_sla(self):
        """
        generate query for Jira SLA timestamps
        """
        # Tracker has a manually defined due date
        if "nonstandard-sla" in self._query["fields"]["labels"]:
            return

        if not self.tracker.external_system_id:
            # Workaround for when a new tracker is filed. At this point in the code it
            # has not been fully saved so created_dt is not a valid date, but the SLAs
            # use the tracker's created date. Since we only care about the date and not the
            # time for the SLA computation, we temporarily set a created_dt of now, which
            # will be replaced later by the TrackingMixin, and this way we do not have to change
            # the entire logic of the code for this to work.
            self.tracker.created_dt = make_aware(datetime.now())

        sla_context = sla_classify(self.tracker)
        # the tracker may or may not be under SLA
        if sla_context.sla is not None:
            self._query["fields"]["duedate"] = sla_context.end.isoformat()
            # check that Target start field is present
            # and eventually get its custom field ID
            target_start = JiraProjectFields.objects.filter(
                project_key=self.ps_module.bts_key, field_name="Target start"
            )
            if target_start.exists():
                self._query["fields"][
                    target_start.first().field_id
                ] = sla_context.start.isoformat()

    def generate_summary(self):
        """
        Generates the summary of a tracker
        """
        self._query["fields"]["summary"] = self.summary

    def generate_versions(self):
        """
        generates the versions
        """
        versions = JiraProjectFields.objects.filter(
            project_key=self.ps_module.bts_key, field_name="Affects Version/s"
        )
        # project may or may not support versions so it is optional
        if versions.exists() and self.ps_update_stream.version:
            self._query["fields"]["versions"] = [
                {"name": self.ps_update_stream.version}
            ]

    def generate_security(self):
        """
        generate the appropriate security level for restricting who can access the Jira
        """
        if field_obj := JiraProjectFields.objects.filter(
            project_key=self.ps_module.bts_key, field_id="security"
        ).first():
            allowed_values = field_obj.allowed_values
        else:
            # Allow misconfigured projects for public trackers
            allowed_values = []

        if self.tracker.is_embargoed:
            if JIRA_EMBARGO_SECURITY_LEVEL_NAME in allowed_values:
                self._query["fields"]["security"] = {
                    "name": JIRA_EMBARGO_SECURITY_LEVEL_NAME
                }
                return
            raise MissingSecurityLevelError(
                f"Jira project {self.ps_module.bts_key} does not have available Security Level "
                f"{JIRA_EMBARGO_SECURITY_LEVEL_NAME}; allowed Jira priority values are: {', '.join(allowed_values)}"
            )
        elif self.ps_module.private_trackers_allowed:
            if JIRA_INTERNAL_SECURITY_LEVEL_NAME in allowed_values:
                self._query["fields"]["security"] = {
                    "name": JIRA_INTERNAL_SECURITY_LEVEL_NAME
                }
                return
            raise MissingSecurityLevelError(
                f"Jira project {self.ps_module.bts_key} does not have available Security Level "
                f"{JIRA_INTERNAL_SECURITY_LEVEL_NAME}; allowed Jira priority values are: {', '.join(allowed_values)}"
            )
        else:
            # This tells Jira to remove the field value if there is one set.
            self._query["fields"]["security"] = None

    def generate_additional_fields(self):
        """
        Generate fields passed as additional fields in the PS update stream.
        """
        if self.ps_update_stream.additional_fields is None:
            return

        if (
            additional_fields := self.ps_update_stream.additional_fields.get(
                "jboss", None
            )
        ) is not None:
            for name, value in additional_fields.items():
                # Additional fields require specific handling logic
                if name == "fixVersions":
                    field_value = [{"name": value}]
                elif name == "release_blocker":
                    field_value = {"value": value}
                else:
                    # Unsupported field
                    continue

                self._query["fields"][PS_ADDITIONAL_FIELD_TO_JIRA[name]] = field_value

    def generate_cc(self):
        """
        generate query for CC list
        """

        # Each instance of OldTrackerJiraQueryBuilder is used only once, but if ever used twice,
        # always produce consistent query and comment.
        self._comment = None

        if self.tracker.external_system_id:
            # Add CCs only on creation.
            return

        cc_list = set()
        for affect in self.tracker.affects.all():
            affect_cc_builder = JiraAffectCCBuilder(
                affect, embargoed=self.tracker.is_embargoed
            )
            cc_list.update(affect_cc_builder.generate_cc())

        if cc_list:
            # Keep the order stable for ease of testing and debugging
            cc_list = sorted(cc_list)

            # Note that access control for the comment is not necessary because the whole
            # tracker has access control set in generate_security().
            notify_users = ", ".join([("[~%s]" % u) for u in cc_list])
            self._comment = "Added involved users: " + notify_users

            # contributors fields will replace the involved field
            # but let us conditionally support both for smooth transition
            if contr_field_obj := JiraProjectFields.objects.filter(
                project_key=self.ps_module.bts_key, field_name="Contributors"
            ).first():
                self._query["fields"][contr_field_obj.field_id] = [
                    {"name": un} for un in cc_list
                ]
            elif inv_field_obj := JiraProjectFields.objects.filter(
                project_key=self.ps_module.bts_key, field_name="Involved"
            ).first():
                self._query["fields"][inv_field_obj.field_id] = [
                    {"name": un} for un in cc_list
                ]
            else:
                # At the time of writing this, all Jira projects have these fields.
                raise TrackerCreationError(
                    f"Jira project {self.ps_module.bts_key} does not have available field Contributors or "
                    f"Involved. This is a regression on the part of the administration of that Jira project."
                )

    def generate_target_release(self):
        """
        Generate target release field from the PsUpdateStream's data.
        """
        value = self.ps_update_stream.target_release
        if not value:
            return

        # Try to use Jira field "Target Release"
        field_name = "Target Release"
        field_id = PS_ADDITIONAL_FIELD_TO_JIRA["target_release"]
        field_obj = JiraProjectFields.objects.filter(
            project_key=self.ps_module.bts_key, field_id=field_id
        ).first()
        if field_obj is None:
            # Use field "Target Version" as fallback option
            field_name = "Target Version"
            field_id = PS_ADDITIONAL_FIELD_TO_JIRA["target_version"]
            field_obj = JiraProjectFields.objects.filter(
                project_key=self.ps_module.bts_key, field_id=field_id
            ).first()
        if field_obj is None:
            # The fields are not available for this project
            return

        allowed_values = field_obj.allowed_values
        if allowed_values and value in allowed_values:
            query_value = (
                {"name": value} if field_name == "Target Release" else [{"name": value}]
            )
            self._query["fields"][field_id] = query_value
        else:
            raise MissingTargetReleaseVersionError(
                f"Jira project {self.ps_module.bts_key} does not have {field_name} with value "
                f"{value} available; allowed values values are: {', '.join(allowed_values)}"
            )

    @property
    def query_comment(self):
        """
        Retrieves the comment generated by .query(). Can be None if no comment was generated.
        """
        return self._comment


class TrackerJiraQueryBuilder(OldTrackerJiraQueryBuilder):
    """
    Jira tracker bug query builder
    to generate general tracker save query
    """

    def generate(self):
        """
        generate query
        """

        # NOTE: NOT calling super().generate() on purpose.

        # NOTE: no self.generate_priority() as compared to OldTrackerJiraQueryBuilder
        # NOTE: no self.generate_security() as compared to OldTrackerJiraQueryBuilder

        self.generate_base()
        self.generate_component()
        self.generate_description()
        self.generate_labels()
        self.generate_sla()
        self.generate_summary()
        self.generate_versions()
        self.generate_additional_fields()
        self.generate_cc()
        self.generate_target_release()

        self.generate_severity()
        self.generate_source()
        self.generate_cve_id()
        self.generate_cvss_score()
        self.generate_cwe_id()
        self.generate_downstream_component()
        self.generate_upstream_component()
        self.generate_embargo_status()
        self.generate_special_handling()

    def field_check_and_get_values_and_id(self, field_name):
        field = JiraProjectFields.objects.filter(
            project_key=self.ps_module.bts_key, field_name=field_name
        ).first()
        if field is None:
            raise MissingVulnerabilityIssueFieldError(
                f"Field {field_name} not available for Vulnerability issuetype in "
                f"Jira project {self.ps_module.bts_key}."
            )
        allowed_values = field.allowed_values
        field_id = field.field_id
        return allowed_values, field_id

    # TODO write tests - tracked in OSIDB-2980
    def generate_severity(self):
        field_name = "Severity"
        allowed_values, field_id = self.field_check_and_get_values_and_id(field_name)

        if self.impact is Impact.NOVALUE:
            raise TrackerCreationError(
                "Tracker has disallowed Impact value Impact.NOVALUE (empty string)."
            )

        for severity in IMPACT_TO_JIRA_SEVERITY[self.impact]:
            if severity in allowed_values:
                self._query["fields"][field_id] = {"value": severity}
                return

        raise MissingSeverityError(
            f"Jira project {self.ps_module.bts_key} does not have the {field_name} field value appropriate for "
            f"severity {severity}, which is one of {', '.join(IMPACT_TO_JIRA_SEVERITY[self.impact])}; "
            f"allowed values are: {', '.join(allowed_values)}"
        )

    # TODO write tests - tracked in OSIDB-2980
    def generate_source(self):
        field_name = "Source"
        allowed_values, field_id = self.field_check_and_get_values_and_id(field_name)

        # TODO: This logic has to be overhauled to select the most relevant CVSS score
        #       and also the most related CWE ID and Source.
        #       Tracked in OSIDB-3348.

        flaw_source = self.tracker.affects.first().flaw.source
        flaw_source_lower = flaw_source.lower()
        choice_found = FLAW_SOURCE_TO_JIRA_SOURCE.get(flaw_source)
        if choice_found not in allowed_values:
            # The pairing table might be out of date, since Jira configuration is dynamic.
            choice_found = None
        if not choice_found:
            # Allow for future-proof pairing of values when they differ only in case.
            for choice in allowed_values:
                if choice.lower() == flaw_source_lower:
                    choice_found = choice
                    break
        if not choice_found:
            raise MissingSourceError(
                f"Jira project {self.ps_module.bts_key} does not have the {field_name} field value "
                f"{flaw_source}; allowed values are: {', '.join(allowed_values)}"
            )
        self._query["fields"][field_id] = {"value": choice_found}

    # TODO write tests - tracked in OSIDB-2980
    def generate_cve_id(self):
        field_name = "CVE ID"
        _, field_id = self.field_check_and_get_values_and_id(field_name)

        cves = sorted(
            set([flaw.cve_id for flaw in self.flaws if flaw.cve_id]),
            key=cve_id_comparator,
        )
        if not cves:
            # This is for a placeholder flaw. Do not fill in the Jira field.
            return
        self._query["fields"][field_id] = ", ".join(cves)

    # TODO write tests - tracked in OSIDB-2980
    def generate_cvss_score(self):
        field_name = "CVSS Score"
        _, field_id = self.field_check_and_get_values_and_id(field_name)

        # TODO: This logic has to be overhauled to select the most relevant CVSS score
        #       and also the most related CWE ID and Source.
        #       Tracked in OSIDB-3348.

        # Preferring RH issuer (which is last when sorted, based on valid choices in CVSSIssuer),
        # Preferring the highest CVSS version for the preferred issuer.
        cvss_score = (
            self.tracker.affects.order_by("flaw__reported_dt")[0]
            .flaw.cvss_scores.order_by("-issuer", "-version")
            .first()
        )

        # If an affect has an associated CVSS score, prefer it over the Flaw.
        affectcvss_uuids = self.tracker.affects.values_list(
            "cvss_scores__uuid", flat=True
        )
        affect_cvss_score = (
            AffectCVSS.objects.filter(uuid__in=affectcvss_uuids)
            .order_by("-issuer", "-version")
            .first()
        )
        if affect_cvss_score:
            cvss_score = affect_cvss_score

        if not cvss_score:
            return

        result = f"{cvss_score.score} {cvss_score.vector}"

        self._query["fields"][field_id] = result

    # TODO write tests - tracked in OSIDB-2980
    def generate_cwe_id(self):
        field_name = "CWE ID"
        _, field_id = self.field_check_and_get_values_and_id(field_name)

        # TODO: This logic has to be overhauled to select the most relevant CVSS score
        #       and also the most related CWE ID and Source.
        #       Tracked in OSIDB-3348.

        cwe_id = self.tracker.affects.first().flaw.cwe_id
        if not cwe_id:
            return
        self._query["fields"][field_id] = cwe_id

    # TODO write tests - tracked in OSIDB-2980
    def generate_downstream_component(self):
        field_name = "Downstream Component Name"
        _, field_id = self.field_check_and_get_values_and_id(field_name)
        self._query["fields"][field_id] = self.tracker.affects.first().ps_component

    # TODO write tests - tracked in OSIDB-2980
    def generate_upstream_component(self):
        # TODO: Every time the components change in the flaw, the trackers must be updated as well.
        #       - tracked in OSIDB-3323

        field_name = "Upstream Affected Component"
        _, field_id = self.field_check_and_get_values_and_id(field_name)
        components = set()
        # `flaw.components` is a list, it doesn't behave like a RelatedManager.
        component_lists = self.tracker.affects.values_list(
            "flaw__components", flat=True
        )
        for one_list in component_lists:
            components.update(one_list)
        components = sorted(components)
        if not components:
            return
        upstream_component = "; ".join(components)

        self._query["fields"][field_id] = upstream_component

    # TODO write tests, pay extra attention to testing this; tracked in OSIDB-2980
    def generate_embargo_status(self):
        field_name = "Embargo Status"
        allowed_values, field_id = self.field_check_and_get_values_and_id(field_name)
        choice_str = repr(self.tracker.is_embargoed)
        if choice_str not in allowed_values:
            raise MissingEmbargoStatusError(
                f"Jira project {self.ps_module.bts_key} does not have the {field_name} field value "
                f"{choice_str}; allowed values are: {', '.join(allowed_values)}"
            )

        # Since this effectively controls access rights, do a separate check that
        # it is exactly as expected. Even an additional unexpected value might signify
        # an emergent bug in security-sensitive logic that requires investigation.
        expected_allowed_values = {"True", "False"}
        if set(allowed_values) != expected_allowed_values:
            raise MissingEmbargoStatusError(
                f"Jira project {self.ps_module.bts_key} has unexpected allowed states for the {field_name} field: "
                f"{', '.join(allowed_values)}; expected {field_name} values are: {', '.join(expected_allowed_values)} "
                f"(also investigate the types; expected are str, not bool)."
            )

        self._query["fields"][field_id] = {"value": choice_str}

    # TODO write tests - tracked in OSIDB-2980
    def generate_special_handling(self):
        field_name = "Special Handling"
        allowed_values, field_id = self.field_check_and_get_values_and_id(field_name)

        expected_allowed_values = [
            MAJOR_INCIDENT,
            KEV,
            COMPLIANCE_PRIORITY,
            CONTRACT_PRIORITY,
        ]
        missing_allowed_values = sorted(
            set(expected_allowed_values) - set(allowed_values)
        )
        if missing_allowed_values:
            raise MissingSpecialHandlingError(
                f"Jira project {self.ps_module.bts_key} does not have the required {field_name} field values "
                f"{', '.join(missing_allowed_values)}; allowed Jira Source values are: {', '.join(allowed_values)}"
            )

        # To make the tracker's Special Handling informative, look across all related flaws.

        choice_major_incident = False
        choice_kev = False
        choice_compliance_priority = False
        choice_contract_priority = False

        flaw_uuids = self.tracker.affects.values_list("flaw__uuid", flat=True)

        for flaw in Flaw.objects.filter(uuid__in=flaw_uuids):

            choice_major_incident |= (
                flaw.major_incident_state == Flaw.FlawMajorIncident.APPROVED
            )
            choice_kev |= (
                flaw.major_incident_state == Flaw.FlawMajorIncident.CISA_APPROVED
            )
            choice_compliance_priority |= self.tracker.is_compliance_priority
            choice_contract_priority |= self.tracker.is_contract_priority

        multichoice_jira_field_value = []
        if choice_major_incident:
            multichoice_jira_field_value.append({"value": MAJOR_INCIDENT})
        if choice_kev:
            multichoice_jira_field_value.append({"value": KEV})
        if choice_compliance_priority:
            multichoice_jira_field_value.append({"value": COMPLIANCE_PRIORITY})
        if choice_contract_priority:
            multichoice_jira_field_value.append({"value": CONTRACT_PRIORITY})

        self._query["fields"][field_id] = multichoice_jira_field_value

    def generate_base(self):
        # NOTE: NOT calling super().generate_base() on purpose.
        self._query = {
            "fields": {
                "issuetype": {"name": "Vulnerability"},
                "project": {"key": self.ps_module.bts_key},
            }
        }
        if self.tracker.external_system_id:
            self._query["key"] = self.tracker.external_system_id
