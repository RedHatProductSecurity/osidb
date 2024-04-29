"""
transform Jira issue into OSIDB tracker model
"""
import json
import uuid
from functools import cached_property

from django.conf import settings

from osidb.core import generate_acls, set_user_acls
from osidb.models import Tracker

from ..utils import (
    tracker_parse_update_stream_component,
    tracker_summary2module_component,
)


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

    @property
    def _normalize(self):
        """
        to be implemented in the child classes
        """
        raise NotImplementedError

    def _gen_tracker_object(self, affect) -> Tracker:
        """
        generate Tracker object from raw tracker data
        """
        # there maybe already existing tracker from the previous sync
        # if this is the periodic update however also when the flaw bug
        # has multiple CVEs the resulting flaws will share the trackers
        tracker = Tracker.objects.create_tracker(
            affect=affect,
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

    def convert(self, affect=None) -> Tracker:
        return self._gen_tracker_object(affect)


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

        return {
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
            "created_dt": self._raw.fields.created,
            "updated_dt": self._raw.fields.updated
            if self._raw.fields.updated
            else self._raw.fields.created,
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
