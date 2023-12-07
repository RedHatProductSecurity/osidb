"""
SLA policy model definitions
"""

from apps.workflows.models import Check
from osidb.models import Affect, Flaw, Tracker

from .exceptions import SLAExecutionError
from .time import add_business_days, add_days


class SLA:
    """
    SLA definition and computation class
    """

    ADD_DAYS = {
        "business days": add_business_days,
        "calendar days": add_days,
    }

    GET_START = {
        "earliest": min,
        "latest": max,
    }

    def __init__(self, sla_desc):
        self.duration = int(sla_desc["duration"])
        self.add_days = self.ADD_DAYS[sla_desc["type"]]
        self._init_start(sla_desc["start"])

    def _init_start(self, start_desc):
        """
        SLA start obtaining description parsing
        """
        # allow the parsering of the shorter
        # style definitions the same way
        if isinstance(start_desc, str):
            start_desc = {"latest": [start_desc]}

        def parse_date(date_desc):
            """
            translate human-readable date description into the attribute name
            """
            return date_desc.lower().strip().replace(" ", "_").replace("_date", "_dt")

        # the dictionary should have only a single item but we do not
        # run any validations here so just assume it is all correct
        for get_start_desc, date_desc_list in start_desc.items():
            self.get_start = self.GET_START[get_start_desc]
            self.dates = [parse_date(date_desc) for date_desc in date_desc_list]

    def start(self, instance):
        """
        compute SLA start moment for the given instance
        """
        return self.get_start(getattr(instance, date) for date in self.dates)

    def end(self, instance):
        """
        compute SLA end moment for the given instance
        """
        return self.add_days(
            self.start(instance),
            self.duration,
        )


class SLAContext(dict):
    """
    SLA context holder
    """

    def __init__(self, **kwargs):
        """
        initialize the context based on given entities

        keyword arguments should comply with ENTITY2CLASS
        mapping defined within the SLAPolicy class
        """
        for name, obj in kwargs.items():
            self[name] = obj

        # empty initial SLA
        self.sla = None

    def __eq__(self, other):
        """
        empty SLA contexts are not equal
        otherwise compare the end dates
        """
        if self.sla is None or other.sla is None:
            return False
        return self.end == other.end

    def __lt__(self, other):
        """
        empty SLA context is greater
        otherwise compare the end dates
        """
        if self.sla is None:
            return False
        if other.sla is None:
            return True
        return self.end < other.end

    @property
    def start(self):
        """
        compute SLA start for the given instance

        returns None if there is no SLA policy
        assigned possibly meaning that this SLA
        context is accepted by no SLA policy
        """
        # for now we only compute SLA based on Flaw
        if not self.get("flaw"):
            raise SLAExecutionError("Missing required SLA context")

        return self.sla.start(self["flaw"]) if self.sla is not None else None

    @property
    def end(self):
        """
        compute SLA end for the given instance

        returns None if there is no SLA policy
        assigned possibly meaning that this SLA
        context is accepted by no SLA policy
        """
        # for now we only compute SLA based on Flaw
        if not self.get("flaw"):
            raise SLAExecutionError("Missing required SLA context")

        return self.sla.end(self["flaw"]) if self.sla is not None else None


class SLAPolicy:
    """
    SLA policy

    has name and description
    has conditions which is a list of checks
    has SLA definition

    provides SLA start and end computation
    """

    ENTITY2CLASS = {
        "affect": Affect,
        "flaw": Flaw,
        "tracker": Tracker,
    }

    def __init__(self, policy_desc):
        self.name = policy_desc["name"]
        self.description = policy_desc["description"]
        self._init_conditions(policy_desc["conditions"])
        self.sla = SLA(policy_desc["sla"])

    def _init_conditions(self, conditions_desc):
        """
        the conditions need to be split entity-wise
        """
        self.conditions = {}
        for entity, conditions in conditions_desc.items():
            self.conditions[entity] = [
                Check(condition_desc, self.ENTITY2CLASS[entity])
                for condition_desc in conditions
            ]

    def accepts(self, sla_context):
        """
        accepts the SLA context if it contains all the entities required
        by the SLA policy and each of them meets all the defined conditions
        """
        for entity, conditions in self.conditions.items():
            if entity not in sla_context:
                return False

            if not all(condition(sla_context[entity]) for condition in conditions):
                return False

        else:
            # all conditions were met
            # SLA context is accepted
            return True

    def context(self, instance):
        """
        find the right SLA context as there may be multiple ones
        which is the one resulting in the earliest deadline
        """
        # for now we only support Tracker SLAs
        if not isinstance(instance, Tracker):
            raise SLAExecutionError(f"Unsupported SLA instance type: {type(instance)}")

        # computing the SLA is not simple as we have to consider multi-flaw trackers where
        # the SLA start must be computed for the flaw which results in the earlist SLA end
        sla_contexts = [
            SLAContext(affect=affect, flaw=affect.flaw, tracker=instance)
            for affect in instance.affects.all()
        ]

        # filter out the SLA contexts not accepted by this SLA policy
        sla_contexts = [context for context in sla_contexts if self.accepts(context)]
        if not sla_contexts:
            # return an empty context
            # if none is accepted
            return SLAContext()

        # assign SLA policies
        for context in sla_contexts:
            context.sla = self.sla

        # return the context resulting
        # in the earliest deadline
        return min(sla_contexts)
