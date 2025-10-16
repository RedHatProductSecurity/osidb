"""
transform Jira issue into OSIDB tracker model
"""

import json
import logging
import uuid
from datetime import datetime
from functools import cached_property

from django.conf import settings
from django.db import transaction

from apps.workflows.workflow import WorkflowFramework
from osidb.core import generate_acls, set_user_acls
from osidb.models import Flaw, Tracker
from osidb.validators import CVE_RE_STR

from ..utils import (
    tracker_parse_update_stream_component,
    tracker_summary2module_component,
)
from .constants import JIRA_DT_FULL_FMT, TASK_CHANGELOG_FIELD_MAPPING

logger = logging.getLogger(__name__)


class JiraTaskConvertor:
    def __init__(
        self,
        task_data,
    ):
        self._raw = task_data
        self.histories = getattr(
            getattr(task_data, "changelog", None),
            "histories",
            [],
        )
        # important that this is last as it might require other fields on self
        self.task_data = self._normalize()
        # set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

    def get_field_attr(self, issue, field, attr=""):
        """
        field value getter helper

        it is possible that the value of a field is
        not always a Field object (can be None)
        """
        if hasattr(issue.fields, field):
            if attr and hasattr(getattr(issue.fields, field), attr):
                return getattr(getattr(issue.fields, field), attr)
            else:
                return getattr(issue.fields, field)

        return None

    def _normalize(self) -> dict:
        """
        raw data normalization
        """
        status = self.get_field_attr(self._raw, "status", "name")
        resolution = self.get_field_attr(self._raw, "resolution", "name")
        workflow, state = WorkflowFramework().jira_to_state(status, resolution)

        return {
            "external_system_id": self._raw.key,
            "labels": self._raw.fields.labels,
            "owner": self.get_field_attr(self._raw, "assignee", "name"),
            "jira_status": status,
            "jira_resolution": resolution,
            "workflow_state": state,
            "workflow_name": workflow,
            "team_id": self.get_field_attr(self._raw, "customfield_10001", "id"),
            "group_key": self.get_field_attr(self._raw, "customfield_10014"),
            "task_updated_dt": datetime.strptime(
                self.get_field_attr(self._raw, "updated"), JIRA_DT_FULL_FMT
            ),
        }

    @property
    def flaw(self):
        if not self.task_data["workflow_name"]:
            logger.error(
                f"Ignoring Jira task ({self.task_data['external_system_id']})"
                "due invalid combination of status and resolution"
                f"({self.task_data['jira_status']}),{self.task_data['jira_resolution']})."
            )
            return None

        flaw = None
        for label in self.task_data["labels"]:
            if CVE_RE_STR.match(label):
                try:
                    flaw = Flaw.objects.get(cve_id=label)
                    # prioritize CVE ID over UUID if possible
                    # so the linking is OSIDB instance independent
                    # by immediately leaving the for cycle here
                    break
                except Flaw.DoesNotExist:
                    logger.error(
                        f"The task {self.task_data['external_system_id']} "
                        f"has a label with unknown/non-existing CVE ID {label}."
                    )

            if label.startswith("flawuuid:"):
                flaw_uuid = label.split(":")[1]
                try:
                    flaw = Flaw.objects.get(uuid=flaw_uuid)
                except Flaw.DoesNotExist:
                    logger.error(f"Ignoring task with invalid flaw uuid ({flaw_uuid}).")

        if not flaw:
            logger.error(
                f"Ignoring task ({self.task_data['external_system_id']}) without label containing flaw uuid."
            )
            return None

        changed_fields = set()
        for record in self.histories[::-1]:
            record_dt = datetime.strptime(record.created, JIRA_DT_FULL_FMT)
            if not flaw.task_updated_dt or record_dt > flaw.task_updated_dt:
                for item in record.items:
                    record_changed_fields = TASK_CHANGELOG_FIELD_MAPPING.get(item.field)
                    if record_changed_fields:
                        changed_fields.update(record_changed_fields)
            else:
                # no more new changes in history
                break

        # Avoid updating timestamp of flaws without real changes
        has_changes = (
            flaw
            and (
                # ignore issue if query is outdated
                not flaw.task_updated_dt
                or flaw.task_updated_dt <= self.task_data["task_updated_dt"]
            )
            and (
                flaw.task_key != self.task_data["external_system_id"] or changed_fields
            )
        )

        if has_changes:
            flaw.task_key = self.task_data["external_system_id"]

            # NOTE: for some unexplainable reason, history record created timestamp
            #       can actually be later in the future (by milliseconds) than Jira issue updated
            #       timestamp, and thus we need to set the task_updated_dt to higher of
            #       those values since it would later in the next download fetch changes
            #       which were already downloaded and stored.
            if self.histories:
                latest_record_dt = datetime.strptime(
                    self.histories[-1].created, JIRA_DT_FULL_FMT
                )
                flaw.task_updated_dt = max(
                    latest_record_dt, self.task_data["task_updated_dt"]
                )
            else:
                flaw.task_updated_dt = self.task_data["task_updated_dt"]

            for field in changed_fields:
                setattr(flaw, field, self.task_data[field])
            flaw.adjust_acls(save=False)
            return JiraTaskSaver(flaw)
        return None


class JiraTaskSaver:
    def __init__(self, flaw):
        self.flaw = flaw

    def save(self):
        # only update the fields which are supposed
        # to be potentially influenced by the collector
        task_attributes = [
            "team_id",
            "task_key",
            "task_updated_dt",
            "owner",
            # the ACLs are not really directly fetched but can
            # get modified due to state or resolution changes
            "acl_read",
            "acl_write",
            # workflow name and state are mapped
            # from Jira state and resolution
            "workflow_name",
            "workflow_state",
        ]
        kwargs = {}
        # set only existing values
        for attribute in task_attributes:
            value = getattr(self.flaw, attribute)
            if value is not None:
                kwargs[attribute] = value

        Flaw.objects.filter(uuid=self.flaw.uuid).update(
            auto_timestamps=False,  # we do not want to touch updated_dt
            **kwargs,
        )


class TrackerSaver:
    """
    TrackerSaver is holder of the individual tracker parts provided by TrackerConvertor
    which knows how to correctly save and link them all as the resulting Django DB models
    it provides save method as an interface to perform the whole save operation
    """

    def __init__(
        self,
        tracker,
        affects,
        alerts,
    ):
        self.tracker = tracker
        self.affects = affects
        self.alerts = alerts

    def __str__(self):
        return f"TrackerSaver {self.tracker.type}:{self.tracker.external_system_id}"

    def save(self, **kwargs):
        """
        save the tracker with its context to DB
        """
        # wrap this in an atomic transaction so that
        # we don't query this tracker during the process
        with transaction.atomic():
            self.tracker.save(
                # we want to store the original timestamps
                # so we turn off assigning the automatic ones
                auto_timestamps=False,
                # we want to store all the data fetched by the collector
                # so we suppress the exception raising in favor of alerts
                raise_validation_error=False,
                **kwargs,
            )
            # re-create all affect links
            # in case some were removed
            self.tracker.affects.set(self.affects)

            # store alerts
            for alert in self.alerts:
                self.tracker.alert(**alert)


class TrackerConvertor:
    """
    generic raw tracker to OSIDB tracker convertor

    this class transforms raw data from a unified raw format into
    proper Tracker model records and saves them into the database
    """

    def __init__(
        self,
        tracker_data,
    ):
        self._alerts = []
        self._raw = tracker_data
        # important that this is last as it might require other fields on self
        self.tracker_data = self._normalize()
        # set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

    @property
    def type(self):
        """
        concrete tracker type has to be specified in the child classes
        """
        raise NotImplementedError

    def alert(self, alert) -> None:
        """
        store conversion alert
        """
        self._alerts.append(alert)

    @property
    def alerts(self) -> list:
        """
        return the list of conversion alerts
        """
        return self._alerts

    @property
    def _normalize(self):
        """
        to be implemented in the child classes
        """
        raise NotImplementedError

    def _gen_tracker_object(self) -> Tracker:
        """
        generate Tracker object from raw tracker data
        """
        # there maybe already existing tracker from the previous sync
        # if this is the periodic update however also when the flaw bug
        # has multiple CVEs the resulting flaws will share the trackers
        tracker = Tracker.objects.filter(
            type=self.type,
            external_system_id=self.tracker_data["external_system_id"],
        ).first()

        # Tracker already has latest data from BTS
        if tracker and tracker.updated_dt >= self.tracker_data["updated_dt"]:
            return None
        tracker = Tracker.objects.create_tracker(
            affect=None,
            _type=self.type,
            external_system_id=self.tracker_data["external_system_id"],
            status=self.tracker_data["status"],
            resolution=self.tracker_data["resolution"],
            not_affected_justification=self.tracker_data["not_affected_justification"],
            ps_update_stream=self.tracker_data["ps_update_stream"],
            meta_attr=self.tracker_data,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            resolved_dt=self.tracker_data["resolved_dt"],
            special_handling=self.tracker_data["special_handling"],
            raise_validation_error=False,  # do not raise exceptions here
        )
        # eventual save inside create_tracker would
        # override the timestamps so we have to set them here
        tracker.created_dt = self.tracker_data["created_dt"]
        tracker.updated_dt = (
            self.tracker_data["updated_dt"] or self.tracker_data["created_dt"]
        )
        return tracker

    @property
    def tracker(self) -> TrackerSaver:
        """
        the convertor interface to get the
        conversion result as a saveable object
        """
        tracker = self._gen_tracker_object()
        if not tracker:
            return None
        return TrackerSaver(
            tracker,
            [],  # Affects are linked later using sync managers
            self.alerts,
        )


class JiraTrackerConvertor(TrackerConvertor):
    """
    Jira tracker issue to OSIDB tracker convertor
    """

    @property
    def type(self):
        """
        concrete tracker specification
        """
        return Tracker.TrackerType.JIRA

    def get_field_attr(self, issue, field, attr):
        """
        field value getter helper

        it is possible that the value of a field is
        not always a Field object (can be None)
        """
        if hasattr(issue.fields, field):
            if hasattr(getattr(issue.fields, field), attr):
                return getattr(getattr(issue.fields, field), attr)

        return None

    def get_array_field_attr(self, issue, field, attr):
        """
        Field value getter helper for arrays.

        In some cases a Jira field contains an array of field values.
        This method unpacks every value in the array.
        """
        if hasattr(issue.fields, field):
            field = getattr(issue.fields, field)
            if isinstance(field, list):
                return [getattr(f, attr) for f in field if hasattr(f, attr)]

    def _normalize(self) -> dict:
        """
        raw data normalization
        """
        ps_module, ps_component = tracker_summary2module_component(
            self._raw.fields.summary
        )
        ps_update_stream = tracker_parse_update_stream_component(
            self._raw.fields.summary
        )[0]

        self.ps_module = ps_module
        self.ps_component = ps_component
        self.ps_update_stream = ps_update_stream

        created_dt = datetime.strptime(self._raw.fields.created, JIRA_DT_FULL_FMT)
        updated_dt = (
            self._raw.fields.updated
            if self._raw.fields.updated
            else self._raw.fields.created
        )
        updated_dt = datetime.strptime(updated_dt, JIRA_DT_FULL_FMT)
        resolved_dt = None
        if self._raw.fields.resolutiondate:
            resolved_dt = datetime.strptime(
                self._raw.fields.resolutiondate, JIRA_DT_FULL_FMT
            )

        return {
            "jira_issuetype": self.get_field_attr(self._raw, "issuetype", "name"),
            "external_system_id": self._raw.key,
            "labels": json.dumps(self._raw.fields.labels),
            "owner": self.get_field_attr(self._raw, "assignee", "displayName"),
            # QE Assignee corresponds to customfield_12316243
            # in RH Jira which is a field of schema type user
            "qe_owner": self.get_field_attr(
                self._raw, "customfield_12316243", "displayName"
            ),
            "ps_module": ps_module,
            "ps_component": ps_component,
            "ps_update_stream": ps_update_stream,
            "status": self.get_field_attr(self._raw, "status", "name"),
            "resolution": self.get_field_attr(self._raw, "resolution", "name"),
            "not_affected_justification": self.get_field_attr(
                self._raw, "customfield_10371", "value"
            ),
            "special_handling": self.get_array_field_attr(
                self._raw, "customfield_10294", "value"
            )
            or [],
            "resolved_dt": resolved_dt,
            "created_dt": created_dt,
            "updated_dt": updated_dt,
        }

    @property
    def groups_read(self):
        """
        appropriate read LDAP groups
        """
        security_level = self.get_field_attr(self._raw, "security", "name")
        # embargo can be defined by two possible values of the security field name
        # historically by Security Issue and more recently by Embargoed Security Issue
        if security_level and "Security Issue" in security_level:
            return [settings.EMBARGO_READ_GROUP]

        return settings.PUBLIC_READ_GROUPS

    @property
    def groups_write(self):
        """
        appropriate write LDAP groups
        """
        security_level = self.get_field_attr(self._raw, "security", "name")
        # embargo can be defined by two possible values of the security field name
        # historically by Security Issue and more recently by Embargoed Security Issue
        if security_level and "Security Issue" in security_level:
            return [settings.EMBARGO_WRITE_GROUP]

        return [settings.PUBLIC_WRITE_GROUP]

    @cached_property
    def acl_read(self):
        """
        get read ACL based on read groups

        it is necessary to generete UUIDs and not just hashes
        so the ACL validations may properly compare the result
        """
        return [uuid.UUID(acl) for acl in generate_acls(self.groups_read)]

    @cached_property
    def acl_write(self):
        """
        get write ACL based on write groups

        it is necessary to generete UUIDs and not just hashes
        so the ACL validations may properly compare the result
        """
        return [uuid.UUID(acl) for acl in generate_acls(self.groups_write)]
