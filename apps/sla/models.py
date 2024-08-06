"""
SLA policy model definitions
"""

from functools import cached_property

from django.contrib.postgres import fields
from django.db import models

from apps.workflows.models import Check
from osidb.models import Affect, Flaw, PsUpdateStream, Tracker

from .exceptions import SLAExecutionError
from .time import add_business_days, add_days


class SLA(models.Model):
    """
    SLA definition and computation model
    """

    class DurationTypes(models.TextChoices):
        BUSINESS_DAYS = "Business Days"
        CALENDAR_DAYS = "Calendar Days"

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

    duration = models.IntegerField()
    duration_type = models.CharField(max_length=20, choices=DurationTypes.choices)
    start_criteria = models.CharField(max_length=20, choices=StartCriteria.choices)
    start_dates = fields.ArrayField(models.CharField(max_length=100), default=list)

    @classmethod
    def create_from_description(self, sla_desc):
        def parse_date(date_desc):
            """
            translate human-readable date description into the attribute name
            """
            return date_desc.lower().strip().replace(" ", "_").replace("_date", "_dt")

        duration = int(sla_desc["duration"])
        sla_type = sla_desc["type"]

        start_desc = sla_desc["start"]
        if isinstance(start_desc, str):
            start_desc = {"latest": [start_desc]}

        # the dictionary should have only a single item but we do not
        # run any validations here so just assume it is all correct
        for get_start_desc, date_desc_list in start_desc.items():
            start_criteria = get_start_desc
            start_dates = [parse_date(date_desc) for date_desc in date_desc_list]

        sla = SLA(
            duration=duration,
            duration_type=sla_type,
            start_criteria=start_criteria,
            start_dates=start_dates,
        )

        return sla

    def start(self, instance):
        """
        compute SLA start moment for the given instance
        """
        return self.get_start(
            getattr(instance, date)
            for date in self.start_dates
            if getattr(instance, date) is not None
        )

    def end(self, instance):
        """
        compute SLA end moment for the given instance
        """
        return self.add_days(
            self.start(instance),
            self.duration,
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
    sla = models.ForeignKey(SLA, on_delete=models.CASCADE, related_name="policies")
    condition_descriptions = models.JSONField(default=dict)
    order = models.IntegerField(unique=True)

    class Meta:
        # Order of SLA is important, so by default retrieve them using the order field
        ordering = ["order"]

    @classmethod
    def create_from_description(self, policy_desc, order=None):
        """Creates an SLA policy from a YAML description."""
        name = policy_desc["name"]
        description = policy_desc["description"]
        sla = SLA.create_from_description(policy_desc["sla"])
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

    def __str__(self):
        return self.name
