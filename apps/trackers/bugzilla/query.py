from functools import cached_property

from apps.bbsync.exceptions import ProductDataError
from apps.bbsync.query import BugzillaQueryBuilder
from osidb.models import PsModule, PsUpdateStream


class TrackerBugzillaQueryBuilder(BugzillaQueryBuilder):
    """
    Bugzilla tracker bug query builder
    to generate general tracker save query
    """

    @property
    def tracker(self):
        """
        concrete name shortcut
        """
        return self.instance

    @property
    def old_tracker(self):
        """
        concrete name shortcut
        """
        return self.old_instance

    @cached_property
    def ps_module(self):
        """
        cached PS module getter
        """
        # even when multiple affects they must all have the same PS module
        return PsModule.objects.get(name=self.tracker.affects.first().ps_module)

    @cached_property
    def ps_component(self):
        """
        cached PS component getter
        """
        # even when multiple affects they must all have the same PS component
        return self.tracker.affects.first().ps_component

    @cached_property
    def ps_update_stream(self):
        """
        cached PS update stream getter
        """
        return PsUpdateStream.objects.get(name=self.tracker.ps_update_stream)

    def generate(self):
        """
        generate query
        """
        self.generate_base()
        self.generate_cc()
        self.generate_component()  # TODO sub_components
        self.generate_deadline()
        self.generate_description()
        self.generate_flags()
        self.generate_groups()
        self.generate_keywords()
        self.generate_summary()
        self.generate_version()

    def generate_base(self):
        """
        generate static base of the query
        """
        self._query = {
            "product": self.ps_module.bts_key,
        }
        # priority and severity is mirrored
        self._query["priority"] = self._query[
            "severity"
        ] = self.IMPACT_TO_SEVERITY_PRIORITY[self.tracker.aggregated_impact]

    def generate_cc(self):
        """
        generate query for CC list
        """
        # TODO CC list module

    def generate_component(self):
        """
        generate Bugzilla component
        """
        # TODO not so simple for RHSCL or RHEL
        self._query["component"] = self.ps_component

    def generate_deadline(self):
        """
        generate query for Bugzilla deadline
        """
        # TODO SLA module
        pass

    def generate_description(self):
        """
        generate query for flaw description on create
        """
        if self.creation:
            self._query["description"] = "TODO"
            # auto-created description should be always public
            self._query["comment_is_private"] = False

        # TODO update comments

    def generate_flags(self):
        """
        generate query for Bugzilla flags
        """
        # we add flags on creation only
        if not self.creation:
            return

        self._query["flags"] = []
        # TODO set_pm_ack
        # TODO set_prodces_priority
        # TODO sfm2.sla.py:330

    def generate_groups(self):
        """
        generate query for Bugzilla groups which control the access to the tracker
        they are based on the product definitions for both public and embargoed
        """
        groups = []

        if self.tracker.embargoed:
            groups = self.ps_module.bts_groups["embargoed"]
            if not groups:
                # safety check for the theoretical case of misconfigured PS module
                # without groups the embargoed tracker would be public and so leaking
                raise ProductDataError(
                    "Cannot create EMBARGOED trackers without group restrictions!"
                    " (empty bts_groups.embargoed for PSModule {})".format(
                        self.ps_module.name
                    )
                )
        else:
            groups = self.ps_module.bts_groups["public"]

        # on creation we provide a list of groups
        if self.creation:
            self._query["groups"] = groups

        # otherwise we provide the differences
        else:
            # TODO we change the tracker groups on unembargo only
            pass

    def generate_keywords(self):
        """
        generate keywords query based on creation|update
        """
        self._query["keywords"] = (
            ["Security", "SecurityTracking"]
            if self.old_tracker is None
            else {"add": ["Security", "SecurityTracking"]}
        )

    def generate_summary(self):
        """
        generate query for tracker summary
        """
        # TODO
        self._query[
            "summary"
        ] = f"{self.ps_component}: TODO [{self.ps_update_stream.name}]"

    def generate_version(self):
        """
        generate Bugzilla component
        """
        # TODO RHSCL can override this
        self._query["version"] = self.ps_update_stream.version
