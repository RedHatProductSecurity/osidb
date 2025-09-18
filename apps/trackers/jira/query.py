"""
Jira tracker query generation module
"""

import json
import logging
import re
from datetime import datetime
from functools import cached_property
from typing import Optional

from django.utils.timezone import make_aware

from apps.sla.models import SLAPolicy
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
from osidb.models import Affect, AffectCVSS, Flaw, FlawCVSS, FlawSource, Impact
from osidb.models.abstract import CVSS
from osidb.validators import CVE_RE_STR

from .constants import (
    JIRA_EMBARGO_SECURITY_LEVEL_NAME,
    JIRA_INTERNAL_SECURITY_LEVEL_NAME,
    PS_ADDITIONAL_FIELD_TO_JIRA,
    TrackersAppSettings,
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
    allowed Jira Severity field values compatible with
    https://access.redhat.com/security/updates/classification
    """

    CRITICAL = "Critical"
    IMPORTANT = "Important"
    MODERATE = "Moderate"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    NONE = "None"


IMPACT_TO_JIRA_SEVERITY = {
    Impact.CRITICAL: JiraSeverity.CRITICAL,
    Impact.IMPORTANT: JiraSeverity.IMPORTANT,
    Impact.MODERATE: JiraSeverity.MODERATE,
    Impact.LOW: JiraSeverity.LOW,
    # INFORMATIONAL and NONE exist in Jira but are not used by OSIDB
}

# NOTE that these four values can change, as they are for sanity-checking
# allowed values for Jira field Special Handling.
MAJOR_INCIDENT = "Major Incident"
MINOR_INCIDENT = "Minor Incident"
KEV = "KEV (active exploit case)"
ZERO_DAY = "0-day"


class OldTrackerJiraQueryBuilder(TrackerQueryBuilder):
    """
    Jira tracker bug query builder
    to generate general tracker save query
    """

    def __init__(self, instance, settings: Optional[TrackersAppSettings] = None):
        """
        init stuff
        """
        self.instance = instance
        self._query = None
        self._comment = None
        self.settings = settings or TrackersAppSettings()

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
        # exclude from updates
        if not self.is_creating:
            return

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
        elif (parsed_bz_component := self.extract_package_from_module()) is not None:
            # RHEL-specific modular ps_component splitting
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

        # check that Target start field is present
        # and eventually get its custom field ID
        target_start = JiraProjectFields.objects.filter(
            project_key=self.ps_module.bts_key, field_name="Target start"
        )

        sla_context = SLAPolicy.classify(self.tracker)
        # the tracker may or may not be under SLA
        if sla_context.policy is not None:
            self._query["fields"]["duedate"] = sla_context.end.isoformat()
            if target_start.exists():
                self._query["fields"][target_start.first().field_id] = (
                    sla_context.start.isoformat()
                )
        else:
            # explicitly set the empty dates so they are cleared
            # out in case of falling out of SLA later on update
            self._query["fields"]["duedate"] = None
            if target_start.exists():
                self._query["fields"][target_start.first().field_id] = None

    def generate_summary(self):
        """
        Generates the summary of a tracker
        """
        self._query["fields"]["summary"] = self.summary

    def generate_versions(self):
        """
        generates the versions
        """
        # exclude from updates
        if not self.is_creating:
            return

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
                f"{JIRA_EMBARGO_SECURITY_LEVEL_NAME}; allowed Security Level values are: "
                f"{', '.join(allowed_values)}"
            )
        elif self.ps_module.private_trackers_allowed:
            if JIRA_INTERNAL_SECURITY_LEVEL_NAME in allowed_values:
                self._query["fields"]["security"] = {
                    "name": JIRA_INTERNAL_SECURITY_LEVEL_NAME
                }
                return
            raise MissingSecurityLevelError(
                f"Jira project {self.ps_module.bts_key} does not have available Security Level "
                f"{JIRA_INTERNAL_SECURITY_LEVEL_NAME}; allowed Security Level values are: "
                f"{', '.join(allowed_values)}"
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

        if not self.is_creating:
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

    def extract_package_from_module(self):
        """
        Check if the component matches the pattern module:stream/package
        and extracts the package part, otherwise returns None.
        """
        match = re.match(r"^[\w-]+:[^/]+\/([\w-]+)$", self.ps_component)
        if match:
            return match.group(1)
        return None


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
        self.generate_special_handling()

        # we set both embargo status and security level field values since
        # the Jira automation responsible for handling the security level based
        # on embargo status has a delay during which the embargo might leak
        self.generate_embargo_status()
        self.generate_security()

    @cached_property
    def most_important_affect(self):
        """
        Selects the most important affect to use for displaying
        CVE/CVSS/CWE/Source in Vulnerability issuetype Jira tracker
        fields, which is relevant for multi-flaw trackers where
        the tracker can have multiple sets of CVE/CVSS/CWE/source
        but the tracker should display only one such set.
        Quote from 2024-09-27 in OSIDB-3348:
          "For multiflaw trackers, select CVE with highest Impact value,
           if there are multiple such CVE, select the one where flaw has
           the oldest created_date/time value. Use CVE/cvss/cwe/source
           from that CVE."
        Note: The writer assumed a flaw has only one authoritative CVE
              object (the one issued by RH) and Flaw == CVE in this context.
        Note: Assuming validations and administrative procedures ensure
              that the impact model fields are in accordance with the
              cvss_scores fields.
        """
        affects_impacts = sorted(
            [
                (affect, affect.aggregated_impact)
                for affect in self.tracker.affects.all()
            ],
            key=lambda pair: pair[1],
        )
        greatest_impact_affects_impacts = [
            (affect, impact)
            for affect, impact in affects_impacts
            if impact == affects_impacts[-1][1]
        ]
        flaw_created_dt_affects = sorted(
            [
                (affect.flaw.created_dt, affect)
                for affect, impact in greatest_impact_affects_impacts
            ],
            key=lambda pair: pair[0],
        )
        most_important_affect = flaw_created_dt_affects[0][1]
        return most_important_affect

    @cached_property
    def most_important_cvss(self) -> Optional[CVSS]:
        """
        Returns a RH/NIST/CISA-issued CVSS.
        For explanation see docstring of most_important_affect.
        If the most important affect doesn't have a related CVSS score,
        then no other affect's/flaw's CVSS score is selected even for multi-flaw
        trackers, so that the set of CVE/CVSS/CWE/Source is consistent.
        """

        affect = self.most_important_affect
        if affect.cvss_scores.filter(issuer=AffectCVSS.CVSSIssuer.REDHAT).exists():
            # Affect override present.
            return (
                affect.cvss_scores.filter(issuer=AffectCVSS.CVSSIssuer.REDHAT)
                .order_by("-version")
                .first()
            )

        rh_cvss = (
            affect.flaw.cvss_scores.filter(issuer=FlawCVSS.CVSSIssuer.REDHAT)
            .order_by("-version")
            .first()
        )
        ext_cvss = (
            affect.flaw.cvss_scores.filter(
                issuer__in=[FlawCVSS.CVSSIssuer.NIST, FlawCVSS.CVSSIssuer.CISA],
                score__gte=7.0,
            )
            .order_by("-version")
            .first()
        )

        if rh_cvss and rh_cvss.score >= 7.0:
            return rh_cvss
        elif ext_cvss:
            return ext_cvss
        return rh_cvss

    @cached_property
    def most_important_cve(self):
        """
        For explanation see docstring of most_important_affect.
        If the most important affect doesn't have a CVE ID,
        then no other affect's/flaw's CVE ID is selected even for multi-flaw
        trackers, so that the set of CVE/CVSS/CWE/Source is consistent.
        """

        return self.most_important_affect.flaw.cve_id

    @cached_property
    def most_important_cwe(self):
        """
        For explanation see docstring of most_important_affect.
        If the most important affect doesn't have a CWE ID,
        then no other affect's/flaw's CWE ID is selected even for multi-flaw
        trackers, so that the set of CVE/CVSS/CWE/Source is consistent.
        """

        return self.most_important_affect.flaw.cwe_id

    @cached_property
    def most_important_source(self):
        """
        For explanation see docstring of most_important_affect.
        If the most important affect doesn't have a Source,
        then no other affect's/flaw's Source is selected even for multi-flaw
        trackers, so that the set of CVE/CVSS/CWE/Source is consistent.
        """

        return self.most_important_affect.flaw.source

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

    def generate_severity(self):
        field_name = "Severity"
        allowed_values, field_id = self.field_check_and_get_values_and_id(field_name)

        if self.impact is Impact.NOVALUE:
            raise TrackerCreationError(
                "Tracker has disallowed Impact value Impact.NOVALUE (empty string)."
            )

        severity = IMPACT_TO_JIRA_SEVERITY[self.impact]
        if severity not in allowed_values:
            raise MissingSeverityError(
                f"Jira project {self.ps_module.bts_key} does not have the {field_name} field value "
                f"{severity}; allowed values are: {', '.join(allowed_values)}"
            )
        self._query["fields"][field_id] = {"value": severity}

    def generate_source(self):
        field_name = "Source"
        allowed_values, field_id = self.field_check_and_get_values_and_id(field_name)

        flaw_source = self.most_important_source
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

    def generate_cve_id(self):
        field_name = "CVE ID"
        _, field_id = self.field_check_and_get_values_and_id(field_name)

        cve = self.most_important_cve
        if not cve:
            # This is for a placeholder flaw. Do not fill in the Jira field.
            return
        self._query["fields"][field_id] = cve

    def generate_cvss_score(self):
        field_name = "CVSS Score"
        _, field_id = self.field_check_and_get_values_and_id(field_name)

        cvss_score = self.most_important_cvss

        if not cvss_score:
            return

        result = f"{cvss_score.score} {cvss_score.vector}"

        self._query["fields"][field_id] = result

    def generate_cwe_id(self):
        field_name = "CWE ID"
        _, field_id = self.field_check_and_get_values_and_id(field_name)

        cwe_id = self.most_important_cwe
        if not cwe_id:
            return
        self._query["fields"][field_id] = cwe_id

    def generate_downstream_component(self):
        field_name = "Downstream Component Name"
        _, field_id = self.field_check_and_get_values_and_id(field_name)
        component = self.most_important_affect.ps_component
        if (
            self.settings.prefer_purls
            and self.ps_module.ps_product.is_middleware
            and (purl := self.most_important_affect.purl)
        ):
            component = purl
        self._query["fields"][field_id] = component

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

    def generate_special_handling(self):
        field_name = "Special Handling"
        allowed_values, field_id = self.field_check_and_get_values_and_id(field_name)

        expected_allowed_values = [
            MAJOR_INCIDENT,
            MINOR_INCIDENT,
            KEV,
            ZERO_DAY,
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
        choice_minor_incident = False
        choice_kev = False
        choice_zero_day = False

        flaw_uuids = self.tracker.affects.values_list("flaw__uuid", flat=True)

        for flaw in Flaw.objects.filter(uuid__in=flaw_uuids):
            choice_major_incident |= (
                flaw.major_incident_state == Flaw.FlawMajorIncident.APPROVED
            )
            choice_minor_incident |= (
                flaw.major_incident_state == Flaw.FlawMajorIncident.MINOR
            )
            choice_kev |= (
                flaw.major_incident_state == Flaw.FlawMajorIncident.CISA_APPROVED
            )
            choice_zero_day |= (
                flaw.major_incident_state == Flaw.FlawMajorIncident.ZERO_DAY
            )

        multichoice_jira_field_value = []
        if choice_major_incident:
            multichoice_jira_field_value.append({"value": MAJOR_INCIDENT})
        if choice_minor_incident:
            multichoice_jira_field_value.append({"value": MINOR_INCIDENT})
        if choice_kev:
            multichoice_jira_field_value.append({"value": KEV})
        if choice_zero_day:
            multichoice_jira_field_value.append({"value": ZERO_DAY})

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
