"""
Bugzilla tracker funtionality module
"""

import logging
from datetime import datetime

from django.utils import timezone

from apps.bbsync.save import BugzillaSaver
from osidb.constants import DATETIME_FMT
from osidb.models import Tracker

from .query import TrackerBugzillaQueryBuilder

logger = logging.getLogger(__name__)


class TrackerBugzillaSaver(BugzillaSaver):
    """
    Bugzilla tracker bug save handler
    """

    @property
    def tracker(self):
        """
        concrete name shortcut
        """
        return self.instance

    @property
    def model(self):
        """
        Tracker model class getter
        """
        return Tracker

    @property
    def query_builder(self):
        """
        query builder class getter
        """
        return TrackerBugzillaQueryBuilder

    def create(self):
        """
        create a Bugzilla tracker and copy BTS timestamps onto the model

        createbug only returns an id; without a follow-up fetch the tracker
        keeps the Unix-epoch placeholder used before BTS sync (OSIDB-5468).
        """
        instance = super().create()
        try:
            bug_data = self.get_bug_data(
                instance.bz_id,
                include_fields=["creation_time", "last_change_time"],
            )
            created_dt = datetime.strptime(
                bug_data["creation_time"], DATETIME_FMT
            ).replace(tzinfo=timezone.get_current_timezone())
            updated_dt = datetime.strptime(
                bug_data["last_change_time"], DATETIME_FMT
            ).replace(tzinfo=timezone.get_current_timezone())
            instance.created_dt = created_dt
            instance.updated_dt = updated_dt
        except (KeyError, TypeError, ValueError):
            logger.warning(
                "Unable to copy Bugzilla timestamps for tracker %s (bz_id=%s)",
                getattr(instance, "uuid", None),
                getattr(instance, "bz_id", None),
                exc_info=True,
            )
            now = timezone.now()
            instance.created_dt = now
            instance.updated_dt = now
        return instance
