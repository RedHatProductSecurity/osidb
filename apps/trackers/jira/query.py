"""
Jira tracker query generation module
"""
import json
import logging
from functools import cached_property

from apps.sla.framework import SLAFramework
from apps.trackers.common import TrackerQueryBuilder
from apps.trackers.exceptions import (
    NoPriorityAvailableError,
    NoSecurityLevelAvailableError,
    NoTargetReleaseVersionAvailableError,
    TrackerCreationError,
)
from apps.trackers.models import JiraProjectFields
from collectors.jiraffe.constants import JIRA_BZ_ID_LABEL_RE
from osidb.cc import JiraAffectCCBuilder
from osidb.models import Affect, Impact
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


class TrackerJiraQueryBuilder(TrackerQueryBuilder):
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

    def generate_priority(self):
        """
        Convert OSIDB impact to Jira Priority
        """
        allowed_values = JiraProjectFields.objects.get(
            project_key=self.ps_module.bts_key, field_id="priority"
        ).allowed_values
        for priority in IMPACT_TO_JIRA_PRIORITY[self.impact]:
            if priority in allowed_values:
                self._query["fields"]["priority"] = {"name": priority}
                return

        raise NoPriorityAvailableError(
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
        sla_framework = SLAFramework()
        sla_context = sla_framework.classify(self.tracker)
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
        if versions.exists() and self.ps_update_stream.version is not None:
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
            raise NoSecurityLevelAvailableError(
                f"Jira project {self.ps_module.bts_key} does not have available Security Level "
                f"{JIRA_EMBARGO_SECURITY_LEVEL_NAME}; allowed Jira priority values are: {', '.join(allowed_values)}"
            )
        elif self.ps_module.private_trackers_allowed:
            if JIRA_INTERNAL_SECURITY_LEVEL_NAME in allowed_values:
                self._query["fields"]["security"] = {
                    "name": JIRA_INTERNAL_SECURITY_LEVEL_NAME
                }
                return
            raise NoSecurityLevelAvailableError(
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

        # Each instance of TrackerJiraQueryBuilder is used only once, but if ever used twice,
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
            raise NoTargetReleaseVersionAvailableError(
                f"Jira project {self.ps_module.bts_key} does not have {field_name} with value "
                f"{value} available; allowed values values are: {', '.join(allowed_values)}"
            )

    @property
    def query_comment(self):
        """
        Retrieves the comment generated by .query(). Can be None if no comment was generated.
        """
        return self._comment
