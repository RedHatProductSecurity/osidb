import logging

from apps.bbsync.cc import AffectCCBuilder, RHSCLAffectCCBuilder
from apps.bbsync.exceptions import ProductDataError
from apps.bbsync.models import BugzillaComponent
from apps.bbsync.query import BugzillaQueryBuilder
from apps.trackers.common import TrackerQueryBuilder

logger = logging.getLogger(__name__)


class TrackerBugzillaQueryBuilder(BugzillaQueryBuilder, TrackerQueryBuilder):
    """
    Bugzilla tracker bug query builder
    to generate general tracker save query
    """

    @property
    def old_tracker(self):
        """
        concrete name shortcut
        """
        return self.old_instance

    def generate(self):
        """
        generate query
        """
        self.generate_base()
        self.generate_cc()
        self.generate_components()
        self.generate_deadline()
        self.generate_description()
        self.generate_flags()
        self.generate_groups()
        self.generate_keywords()
        self.generate_summary()

    def generate_base(self):
        """
        generate static base of the query
        """
        self._query = {
            "product": self.ps_module.bts_key,
            "version": self.ps_update_stream.version,
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

    def generate_components(self):
        """
        generate Bugzilla component and subcomponent

        CC list builder already implements Bugzilla component
        generation (and more) so let us reuse it here
        """
        # (1) RHSCL special component handling
        if self.ps_module.is_rhscl:
            collection, self._query["component"] = RHSCLAffectCCBuilder(
                self.tracker.affects.first(), None  # embargoed is unused here
            ).collection_component()

            # RHSCL overrides the version
            if collection:
                self._query["version"] = collection
            else:
                # in SFM2 this was not a blocking error so I am keeping the behavior the same way
                # even though it probably means that someone should fix the affect or product definitions
                logger.warning(
                    f"Component {self._query['component']} does not start with valid "
                    f"collection for update stream {self.ps_update_stream.name}"
                )
                self._query["version"] = "unspecified"

        # (2) common component handling
        else:
            self._query["component"] = AffectCCBuilder(
                self.tracker.affects.first(), None  # embargoed is unused here
            ).ps2bz_component()

        # (3) define subcomponent
        # TODO subcomponents are to be provided through the API query
        # which is however to be defined so they are empty here for now
        sub_components = []

        # (4) override with default subcomponent
        default_subcomponent = self.ps_module.subcomponent(self.ps_component)
        if default_subcomponent:
            sub_components = [default_subcomponent]

        # (5) set subcomponents
        if sub_components:
            # subcomponents are hash containing an array of strings
            # where the key in the hash is the component name
            self._query["sub_components"] = {self._query["component"]: sub_components}

        # (6) check and eventually replace non-existing Bugzilla component
        elif (
            # try to find a matching Bugzilla component
            not BugzillaComponent.objects.filter(
                name=self._query["component"], product__name=self.ps_module.bts_key
            ).exists()
            and self.ps_module.default_component
        ):
            # use default component if the generated component does not match with Bugzilla
            self._query["component"] = self.ps_module.default_component
            # in SFM2 this was not a blocking error so I am keeping the behavior the same way
            # even though it probably means that someone should fix the affect or product definitions
            logger.warning(
                f'Component "{self.ps_component}" overridden to default '
                f'"{self.ps_module.default_component}" for "{self.ps_update_stream.name}"'
            )

    def generate_deadline(self):
        """
        generate query for Bugzilla deadline
        """
        # TODO SLA module
        pass

    def generate_description(self):
        """
        generate query for flaw description
        """
        if self.creation:
            self._query["description"] = self.description
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
        self._query["summary"] = self.summary
