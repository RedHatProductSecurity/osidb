"""
transform Bugzilla flaw bug into OSIDB flaw model
"""

import json
import logging
import uuid
from datetime import datetime
from functools import cached_property

from django.conf import settings
from django.utils import timezone

from collectors.jiraffe.convertors import TrackerConvertor
from osidb.core import generate_acls
from osidb.models import Tracker

from ..utils import (
    tracker_parse_update_stream_component,
    tracker_summary2module_component,
)
from .constants import BZ_ENABLE_IMPORT_EMBARGOED

logger = logging.getLogger(__name__)


class BugzillaGroupsConvertorMixin:
    """
    shared functionality to convert Bugzilla groups to ACLs
    """

    @property
    def bz_id(self):
        """
        required property to be defined in the child classes
        """
        raise NotImplementedError

    @property
    def bug(self):
        """
        generic shortcut to be specified in the child classes
        """
        raise NotImplementedError

    @property
    def groups(self):
        """
        appropriate overall LDAP groups
        """
        return self.groups_read + self.groups_write

    @property
    def groups_read(self):
        """
        appropriate read LDAP groups
        """
        return self.get_group("read")

    @property
    def groups_write(self):
        """
        appropriate write LDAP groups
        """
        return self.get_group("write")

    def get_group(self, operation):
        """
        appropriate LDAP group
        """
        mapping = {
            "read": {
                "public": settings.PUBLIC_READ_GROUPS,
                "internal": [settings.INTERNAL_READ_GROUP],
                "embargo": [settings.EMBARGO_READ_GROUP],
            },
            "write": {
                "public": [settings.PUBLIC_WRITE_GROUP],
                "internal": [settings.INTERNAL_WRITE_GROUP],
                "embargo": [settings.EMBARGO_WRITE_GROUP],
            },
        }

        if not self.bug.get("groups", []):
            return mapping[operation]["public"]

        elif "security" not in self.bug.get("groups", []):
            return mapping[operation]["internal"]

        else:
            if not BZ_ENABLE_IMPORT_EMBARGOED:
                raise self.FlawConvertorException(
                    f"Bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
                )
            return mapping[operation]["embargo"]

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


class BugzillaTrackerConvertor(BugzillaGroupsConvertorMixin, TrackerConvertor):
    """
    Bugzilla tracker bug to OSIDB tracker convertor.
    """

    @property
    def type(self):
        """
        concrete tracker specification
        """
        return Tracker.TrackerType.BUGZILLA

    @property
    def bz_id(self):
        """
        Bugzilla ID
        """
        return self.bug["id"]

    @property
    def bug(self):
        """
        generic bug used in mixin context
        means the raw tracker data here
        """
        return self._raw

    def _normalize(self) -> dict:
        """
        raw data normalization
        """
        ps_module, ps_component = tracker_summary2module_component(self._raw["summary"])
        ps_update_stream = tracker_parse_update_stream_component(self._raw["summary"])[
            0
        ]

        self.ps_module = ps_module
        self.ps_component = ps_component
        self.ps_update_stream = ps_update_stream
        created_dt = datetime.strptime(self._raw["creation_time"], "%Y-%m-%dT%H:%M:%Sz")
        updated_dt = datetime.strptime(
            self._raw["last_change_time"], "%Y-%m-%dT%H:%M:%Sz"
        )
        resolved_dt = None
        if self._raw["cf_last_closed"]:
            resolved_dt = datetime.strptime(
                self._raw["cf_last_closed"], "%Y-%m-%dT%H:%M:%Sz"
            ).replace(tzinfo=timezone.get_current_timezone())
        return {
            "external_system_id": self._raw["id"],
            "owner": self._raw["assigned_to"],
            "qe_owner": self._raw["qa_contact"],
            "ps_module": ps_module,
            "ps_component": ps_component,
            "ps_update_stream": ps_update_stream,
            "status": self._raw["status"],
            "resolution": self._raw["resolution"],
            "not_affected_justification": None,
            "created_dt": created_dt.replace(tzinfo=timezone.get_current_timezone()),
            "updated_dt": updated_dt.replace(tzinfo=timezone.get_current_timezone()),
            "blocks": json.dumps(self._raw["blocks"]),
            "groups": json.dumps(self._raw["groups"]),
            "whiteboard": self._raw["whiteboard"],
            "resolved_dt": resolved_dt,
            "special_handling": [],
        }
