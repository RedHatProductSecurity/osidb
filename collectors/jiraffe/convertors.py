"""
transform Jira issue into OSIDB tracker model
"""
import json
import uuid
from functools import cached_property

from django.conf import settings
from django.db import transaction

from osidb.core import generate_acls, set_user_acls
from osidb.mixins import Alert
from osidb.models import Affect, Flaw, Tracker
from osidb.validators import CVE_RE_STR

from ..utils import (
    tracker_parse_update_stream_component,
    tracker_summary2module_component,
)
from .constants import JIRA_BZ_ID_LABEL_RE


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

    def save(self):
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

    @property
    def affects(self) -> list:
        """
        returns the list of related affects
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
        return TrackerSaver(
            self._gen_tracker_object(),
            self.affects,
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

    @property
    def affects(self) -> list:
        """
        returns the list of related affects
        """
        # to ensure the maximum possible linkage retrieval
        # we use multiple methods to find the related flaws
        #
        # this ensures the restoration of links
        # which has one of the sides broken
        flaws = set()

        # 1) linking from the flaw side
        for flaw in Flaw.objects.filter(
            meta_attr__jira_trackers__contains=self._raw.key
        ):
            # we need to double check the tracker ID
            # as eg. OSIDB-123 is contained in OSIDB-1234
            for item in json.loads(flaw.meta_attr["jira_trackers"]):
                if self._raw.key == item["key"]:
                    flaws.add(flaw)

        # 2) linking from the tracker side
        for label in self._raw.fields.labels:
            if CVE_RE_STR.match(label):
                try:
                    flaws.add(Flaw.objects.get(cve_id=label))
                except Flaw.DoesNotExist:
                    # tracker created against
                    # non-existing CVE ID
                    self.alert(
                        {
                            "name": "tracker_no_flaw",
                            "description": (
                                f"Jira tracker {self._raw.key} is supposed to be associated with "
                                f"flaw {label} which however does not exist"
                            ),
                            "alert_type": Alert.AlertType.ERROR,
                        }
                    )
                    continue

            if match := JIRA_BZ_ID_LABEL_RE.match(label):
                if not (
                    linked_flaws := Flaw.objects.filter(meta_attr__bz_id=match.group(1))
                ):
                    # tracker created against
                    # non-existing BZ ID
                    self.alert(
                        {
                            "name": "tracker_no_flaw",
                            "description": (
                                f"Jira tracker {self._raw.key} is supposed to be associated with "
                                f"flaw {match.group(1)} which however does not exist"
                            ),
                            "alert_type": Alert.AlertType.ERROR,
                        }
                    )
                    continue

                flaws.update(linked_flaws)

        affects = []
        for flaw in flaws:
            try:
                affect = flaw.affects.get(
                    ps_module=self.ps_module,
                    ps_component=self.ps_component,
                )
            except Affect.DoesNotExist:
                # tracker created against
                # non-existing affect
                self.alert(
                    {
                        "name": "tracker_no_affect",
                        "description": (
                            f"Jira tracker {self._raw.key} is associated with flaw "
                            f"{flaw.cve_id or flaw.bz_id} but there is no associated affect "
                            f"({self.ps_module}:{self.ps_component})"
                        ),
                        "alert_type": Alert.AlertType.ERROR,
                    }
                )
                continue

            affects.append(affect)
        return affects
