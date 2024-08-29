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

logger = logging.getLogger(__name__)


class JiraTaskConvertor:
    def __init__(
        self,
        task_data,
    ):
        self._raw = task_data
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
            "team_id": self.get_field_attr(self._raw, "customfield_12313240", "id"),
            "group_key": self.get_field_attr(self._raw, "customfield_12311140"),
            "task_updated_dt": datetime.strptime(
                self.get_field_attr(self._raw, "updated"), "%Y-%m-%dT%H:%M:%S.%f%z"
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
        # Avoid updating timestamp of flaws without real changes
        has_changes = (
            flaw
            and (
                # ignore issue if query is outdated
                not flaw.task_updated_dt
                or flaw.task_updated_dt <= self.task_data["task_updated_dt"]
            )
            and (
                flaw.team_id != self.task_data["team_id"]
                or flaw.owner != self.task_data["owner"]
                or flaw.task_key != self.task_data["external_system_id"]
                or flaw.group_key != self.task_data["group_key"]
                or flaw.workflow_name != self.task_data["workflow_name"]
                or flaw.workflow_state != self.task_data["workflow_state"]
            )
        )

        if has_changes:
            flaw.team_id = self.task_data["team_id"]
            flaw.owner = self.task_data["owner"]
            flaw.task_key = self.task_data["external_system_id"]
            flaw.group_key = self.task_data["group_key"]
            flaw.workflow_name = self.task_data["workflow_name"]
            flaw.workflow_state = self.task_data["workflow_state"]
            flaw.task_updated_dt = self.task_data["task_updated_dt"]
            flaw.adjust_acls(save=False)
            return JiraTaskSaver(flaw)
        return None


class JiraTaskSaver:
    def __init__(self, flaw):
        self.flaw = flaw

    def save(self):
        self.flaw.save(
            auto_timestamps=False,
            raise_validation_error=False,
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
            # re-create all affect links
            # in case some were removed
            self.tracker.affects.clear()
            self.tracker.affects.add(*self.affects)  # bulk add
            self.tracker.save(
                # we want to store the original timestamps
                # so we turn off assigning the automatic ones
                auto_timestamps=False,
                # we want to store all the data fetched by the collector
                # so we suppress the exception raising in favor of alerts
                raise_validation_error=False,
                **kwargs,
            )

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
            ps_update_stream=self.tracker_data["ps_update_stream"],
            meta_attr=self.tracker_data,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
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

        created_dt = datetime.strptime(
            self._raw.fields.created, "%Y-%m-%dT%H:%M:%S.%f%z"
        )
        updated_dt = (
            self._raw.fields.updated
            if self._raw.fields.updated
            else self._raw.fields.created
        )
        updated_dt = datetime.strptime(updated_dt, "%Y-%m-%dT%H:%M:%S.%f%z")

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
