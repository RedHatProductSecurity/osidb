"""
SLA policy model definitions
"""

from functools import cached_property

from django.db import models

from apps.workflows.models import Check
from osidb.models import Affect, Flaw, PsUpdateStream, Tracker

from .exceptions import SLAExecutionError
from .time import add_business_days, add_days, skip_week_ending


class TemporalPolicy(models.Model):
    """
    Abstract temporal policy definition and computation model
    """

    class DurationTypes(models.TextChoices):
        BUSINESS_DAYS = "Business Days"
        CALENDAR_DAYS = "Calendar Days"

    class EndingTypes(models.TextChoices):
        ANY_DAY = "any day"
        # this currently means Moday-Thursday as the purpose is to exclude Friday and weekend
        # releases and this is the best naming I was able to come up with for this range
        NO_WEEK_ENDING = "no week ending"

    class StartCriteria(models.TextChoices):
        EARLIEST = "Earliest"
        LATEST = "Latest"

    ADD_DAYS = {
        "business days": add_business_days,
        "calendar days": add_days,
    }

    GET_START = {
        "earliest": min,
        "latest": max,
    }

    SET_ENDING = {
        "any day": lambda x: x,  # noop
        "no week ending": skip_week_ending,
    }

    VALID_DATE_SOURCES = ("flaw", "affect", "tracker")

    duration = models.IntegerField()
    duration_type = models.CharField(max_length=20, choices=DurationTypes.choices)
    ending = models.CharField(
        max_length=20, choices=EndingTypes.choices, default=EndingTypes.ANY_DAY
    )
    start_criteria = models.CharField(max_length=20, choices=StartCriteria.choices)
    start_dates = models.JSONField(default=dict)

    class Meta:
        abstract = True

    @classmethod
    def create_from_description(cls, desc):
        def parse_date(date_desc):
            """
            translate human-readable date description into the attribute name
            """
            return date_desc.lower().strip().replace(" ", "_").replace("_date", "_dt")

        def parse_type(type_desc):
            """
            translate human-readable description into the actual
            TemporalPolicy type and its optional ending
            """
            ending = cls.EndingTypes.ANY_DAY
            for ending_type, _ in cls.EndingTypes.choices:
                if ending_type in type_desc:
                    ending = ending_type
                    type_desc = type_desc.replace(ending_type, "").strip()
                    break

            return type_desc, ending

        if desc is None:
            return None

        duration = int(desc["duration"])
        policy_type, ending = parse_type(desc["type"])

        start_desc = desc["start"]
        if isinstance(start_desc, str):
            start_desc = {"latest": [start_desc]}

        # the dictionary should have only a single item but we do not
        # run any validations here so just assume it is all correct
        get_start_desc, date_source_desc = next(iter(start_desc.items()))
        start_criteria = get_start_desc
        # No source specified, default to flaw
        if isinstance(date_source_desc, list):
            date_source_desc = {"flaw": date_source_desc}

        start_dates = {}
        for date_source, date_desc_list in date_source_desc.items():
            if date_source not in cls.VALID_DATE_SOURCES:
                raise SLAExecutionError(
                    "Policy contains an invalid start date source. "
                    f"Valid sources: {', '.join(cls.VALID_DATE_SOURCES)}"
                )
            start_dates[date_source] = [parse_date(d) for d in date_desc_list]

        obj = cls(
            duration=duration,
            duration_type=policy_type,
            ending=ending,
            start_criteria=start_criteria,
            start_dates=start_dates,
        )

        return obj

    def start(self, context):
        """
        compute start moment for the given instance
        """
        start_dates = []
        for model, dates in self.start_dates.items():
            instance = context.get(model, None)
            start_dates += [
                getattr(instance, date) for date in dates if instance is not None
            ]

        if not start_dates:
            return None

        return self.get_start(start_dates)

    def end(self, context):
        """
        compute end moment for the given instance
        """
        return self.SET_ENDING[self.ending](
            self.add_days(self.start(context), self.duration)
        )

    @property
    def get_start(self):
        return self.GET_START[self.start_criteria]

    @property
    def add_days(self):
        return self.ADD_DAYS[self.duration_type]


class TemporalContext(dict):
    """
    temporal policy context holder
    """

    def __init__(self, **kwargs):
        """
        initialize the context based on given entities

        keyword arguments should comply with ENTITY2CLASS
        mapping defined within the TemporalPolicy class
        """
        for name, obj in kwargs.items():
            self[name] = obj

        # empty initial policy
        self.policy = None
        # this flag determines if this should take priority over other
        # policies as it's used to exclude certain trackers from SLA/SLO
        self.is_exclusion = False

    def __eq__(self, other):
        """
        empty policies contexts are not equal
        otherwise compare the end dates
        """
        if self.policy is None or other.policy is None:
            return False
        return self.end == other.end

    def __lt__(self, other):
        """
        empty policy context is greater,
        exclusion policy is smaller,
        otherwise compare the end dates
        """
        # Exclusion takes priority
        if self.is_exclusion:
            return True
        if other.is_exclusion:
            return False
        # Policies that didn't match but are not exclusion policy
        if self.policy is None:
            return False
        if other.policy is None:
            return True
        return self.end < other.end

    @property
    def start(self):
        """
        compute policy start for the given instance

        returns None if there is no policy
        assigned possibly meaning that this
        context is accepted by no policy
        """
        if self.policy is None:
            return None

        return self.policy.start(self)

    @property
    def end(self):
        """
        compute policy end for the given instance

        returns None if there is no policy
        assigned possibly meaning that this
        context is accepted by no policy
        """
        if self.policy is None:
            return None

        return self.policy.end(self)


class PolicyBase(models.Model):
    """
    Generic temporal policy

    has name and description
    has conditions which is a list of checks
    has policy definition

    provides policy start and end computation
    """

    ENTITY2CLASS = {
        "affect": Affect,
        "flaw": Flaw,
        "tracker": Tracker,
    }

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    condition_descriptions = models.JSONField(default=dict)
    order = models.IntegerField(unique=True)

    class Meta:
        # Order of the policy is important, so by default retrieve them using the order field
        ordering = ["order"]
        abstract = True

    def __str__(self):
        return self.name

    @property
    def temporal_policy(self) -> TemporalPolicy:
        """
        Concrete subclasses (e.g. SLAPolicy) must
        return the bound TemporalPolicy instance (or None for exclusions).
        """
        raise NotImplementedError

    @classmethod
    def classify(cls, instance: models.Model):
        """
        Evaluate all policies of this concrete subclass against the instance
        and return the TemporalContext that yields the earliest end.
        Returns an empty TemporalContext if there are no policies.
        """

        policies = cls.objects.all()
        if not policies.exists():
            return TemporalContext()
        return min(policy.context(instance) for policy in policies)

    @classmethod
    def create_from_description(cls, policy_desc, order=None):
        """Creates an SLA policy from a YAML description."""
        raise NotImplementedError

    @cached_property
    def conditions(self):
        # The conditions need to be split entity-wise
        conditions = {}
        for entity, condition_list in self.condition_descriptions.items():
            conditions[entity] = [
                Check(condition_desc, self.ENTITY2CLASS[entity])
                for condition_desc in condition_list
            ]
        return conditions

    def accepts(self, context):
        """
        accepts the context if it contains all the entities required
        by the policy and each of them meets all the defined conditions
        """
        for entity, conditions in self.conditions.items():
            if entity not in context:
                return False

            if not all(condition(context[entity]) for condition in conditions):
                return False

        else:
            # all conditions were met
            # context is accepted
            return True

    def context(self, instance) -> TemporalContext:
        """
        find the right context as there may be multiple ones
        which is the one resulting in the earliest deadline
        """
        raise NotImplementedError


class SLA(TemporalPolicy):
    """
    SLA definition and computation model
    """


class SLAPolicy(PolicyBase):
    """
    SLA policy model responsible for interpreting description fields and context
    """

    sla = models.ForeignKey(
        SLA, on_delete=models.CASCADE, null=True, related_name="policies"
    )

    @property
    def temporal_policy(self) -> TemporalPolicy:
        return self.sla

    @classmethod
    def create_from_description(cls, policy_desc, order=None):
        """Creates an SLA policy from a YAML description."""
        name = policy_desc["name"]
        description = policy_desc["description"]
        sla = SLA.create_from_description(policy_desc["sla"])
        if sla is not None:
            sla.save()

        if order is None:
            order = SLAPolicy.objects.count()

        return SLAPolicy(
            name=name,
            description=description,
            condition_descriptions=policy_desc["conditions"],
            sla=sla,
            order=order,
        )

    def context(self, instance):
        """
        find the right SLA context as there may be multiple ones
        which is the one resulting in the earliest deadline
        """
        # for now we only support Tracker SLAs
        if not isinstance(instance, Tracker):
            raise SLAExecutionError(f"Unsupported SLA instance type: {type(instance)}")

        ps_update_stream = PsUpdateStream.objects.get(name=instance.ps_update_stream)
        if not ps_update_stream.rhsa_sla_applicable:
            return TemporalContext()

        # computing the SLA is not simple as we have to consider multi-flaw trackers where
        # the SLA start must be computed for the flaw which results in the earlist SLA end
        sla_contexts = []
        for affect in instance.affects.all():
            # Make sure we are getting the latest data from the database and not the possibly
            # incomplete data from the tracker which may be being saved
            affect = Affect.objects.get(uuid=affect.uuid)
            sla_contexts.append(
                TemporalContext(affect=affect, flaw=affect.flaw, tracker=instance)
            )

        # filter out the SLA contexts not accepted by this SLA policy
        sla_contexts = [context for context in sla_contexts if self.accepts(context)]
        if not sla_contexts:
            # return an empty context
            # if none is accepted
            return TemporalContext()

        # assign SLA policies
        for context in sla_contexts:
            context.policy = self.sla
            if self.sla is None:
                # Exclusion SLA is defined as null in the policy
                context.is_exclusion = True

        # return the context resulting
        # in the earliest deadline
        return min(sla_contexts)
