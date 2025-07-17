"""
SLA policy model definitions
"""

from functools import cached_property

from django.db import models

from apps.workflows.models import Check
from osidb.models import Affect, Flaw, PsUpdateStream, Tracker

from .exceptions import SLAExecutionError
from .time import add_business_days, add_days, skip_week_ending


class SLA(models.Model):
    """
    SLA definition and computation model
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

    @classmethod
    def create_from_description(cls, sla_desc):
        def parse_date(date_desc):
            """
            translate human-readable date description into the attribute name
            """
            return date_desc.lower().strip().replace(" ", "_").replace("_date", "_dt")

        def parse_type(type_desc):
            """
            translate human-readable SLA type description
            into the actual SLA type and its optional ending
            """
            ending = cls.EndingTypes.ANY_DAY
            for ending_type, _ in cls.EndingTypes.choices:
                if ending_type in type_desc:
                    ending = ending_type
                    type_desc = type_desc.replace(ending_type, "").strip()
                    break

            return type_desc, ending

        if sla_desc is None:
            return None

        duration = int(sla_desc["duration"])
        sla_type, ending = parse_type(sla_desc["type"])

        start_desc = sla_desc["start"]
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
                    f"SLA contains an invalid start date source. Valid sources: {', '.join(cls.VALID_DATE_SOURCES)}"
                )
            start_dates[date_source] = [
                parse_date(date_desc) for date_desc in date_desc_list
            ]

        sla = SLA(
            duration=duration,
            duration_type=sla_type,
            ending=ending,
            start_criteria=start_criteria,
            start_dates=start_dates,
        )

        return sla

    def start(self, sla_context):
        """
        compute SLA start moment for the given instance
        """
        # Populate with the actual dates
        start_dates = []
        for model, dates in self.start_dates.items():
            instance = sla_context.get(model, None)
            start_dates += [
                getattr(instance, date) for date in dates if instance is not None
            ]

        if not start_dates:
            return None

        return self.get_start(start_dates)

    def end(self, sla_context):
        """
        compute SLA end moment for the given instance
        """
        return self.SET_ENDING[self.ending](
            self.add_days(
                self.start(sla_context),
                self.duration,
            )
        )

    @property
    def get_start(self):
        return self.GET_START[self.start_criteria]

    @property
    def add_days(self):
        return self.ADD_DAYS[self.duration_type]


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
        # this flag determines if this should take priority over other
        # SLAs as it's used to exclude certain trackers from SLA
        self.is_exclusion = False

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
        empty SLA context is greater,
        exclusion SLA is smaller,
        otherwise compare the end dates
        """
        # Exclusion takes priority
        if self.is_exclusion:
            return True
        if other.is_exclusion:
            return False
        # SLAs that didn't match but are not exclusion SLAs
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
        if self.sla is None:
            return None

        return self.sla.start(self)

    @property
    def end(self):
        """
        compute SLA end for the given instance

        returns None if there is no SLA policy
        assigned possibly meaning that this SLA
        context is accepted by no SLA policy
        """
        if self.sla is None:
            return None

        return self.sla.end(self)


class SLAPolicy(models.Model):
    """
    SLA policy model

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

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    sla = models.ForeignKey(
        SLA, on_delete=models.CASCADE, null=True, related_name="policies"
    )
    condition_descriptions = models.JSONField(default=dict)
    order = models.IntegerField(unique=True)

    class Meta:
        # Order of SLA is important, so by default retrieve them using the order field
        ordering = ["order"]

    def __str__(self):
        return self.name

    @classmethod
    def create_from_description(self, policy_desc, order=None):
        """Creates an SLA policy from a YAML description."""
        name = policy_desc["name"]
        description = policy_desc["description"]
        sla = SLA.create_from_description(policy_desc["sla"])
        if sla is not None:
            sla.save()

        if order is None:
            # Order is implied by the number of already existing SLA policies
            order = SLAPolicy.objects.count()

        policy = SLAPolicy(
            name=name,
            description=description,
            condition_descriptions=policy_desc["conditions"],
            sla=sla,
            order=order,
        )
        return policy

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

        ps_update_stream = PsUpdateStream.objects.get(name=instance.ps_update_stream)
        if not ps_update_stream.rhsa_sla_applicable:
            return SLAContext()

        # computing the SLA is not simple as we have to consider multi-flaw trackers where
        # the SLA start must be computed for the flaw which results in the earlist SLA end
        sla_contexts = []
        for affect in instance.affects.all():
            # Make sure we are getting the latest data from the database and not the possibly
            # incomplete data from the tracker which may be being saved
            affect = Affect.objects.get(uuid=affect.uuid)
            sla_contexts.append(
                SLAContext(affect=affect, flaw=affect.flaw, tracker=instance)
            )

        # filter out the SLA contexts not accepted by this SLA policy
        sla_contexts = [context for context in sla_contexts if self.accepts(context)]
        if not sla_contexts:
            # return an empty context
            # if none is accepted
            return SLAContext()

        # assign SLA policies
        for context in sla_contexts:
            context.sla = self.sla
            if self.sla is None:
                # Exclusion SLA is defined as null in the policy
                context.is_exclusion = True

        # return the context resulting
        # in the earliest deadline
        return min(sla_contexts)
