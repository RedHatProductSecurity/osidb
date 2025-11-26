import uuid
from typing import List

from django.contrib.postgres import fields
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models
from django.db.models import Q

from apps.workflows.workflow import WorkflowModel
from osidb.mixins import TrackingMixin, TrackingMixinManager
from osidb.models import Affect, Flaw
from osidb.query_sets import CustomQuerySetUpdatedDt


class FlawLabelManager(models.Manager):
    @staticmethod
    def get_filtered(ps_modules: List[str], ps_components: List[str], *args):
        """Get product family labels based on the ps_modules and ps_components"""
        return FlawLabel.objects.filter(
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY
        ).filter(
            (
                Q(ps_modules__overlap=list(set(ps_modules)))
                | Q(ps_components__overlap=list(set(ps_components)))
            )
            & ~(
                Q(ps_modules_exclude__overlap=list(set(ps_modules)))
                | Q(ps_components_exclude__overlap=list(set(ps_components)))
            ),
            *args,
        )


class FlawLabel(models.Model):
    class FlawLabelType(models.TextChoices):
        CONTEXT_BASED = "context_based"
        PRODUCT_FAMILY = "product_family"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Label name
    name = models.CharField(max_length=255, unique=True)

    # Label type
    type = models.CharField(
        max_length=20,
        choices=FlawLabelType.choices,
        editable=False,
    )

    ps_components = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_components_exclude = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_modules = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_modules_exclude = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    objects = FlawLabelManager()

    def __str__(self):
        return self.name


class FlawCollaboratorManager(TrackingMixinManager):
    """collaborator manager"""

    @staticmethod
    def create_from_affect(affect: Affect):
        """Add new labels to the flaw based on the affect"""

        labels = FlawLabel.objects.get_filtered(
            [affect.ps_module],
            [affect.ps_component],
            ~Q(name__in=affect.flaw.labels.values_list("label", flat=True)),
        )

        for label in labels:
            FlawCollaborator.objects.create(
                flaw=affect.flaw,
                label=label.name,
                state=FlawCollaborator.FlawCollaboratorState.NEW,
                type=label.type,
            )

    @staticmethod
    def create_from_flaw(flaw: Flaw):
        """Add new labels to the flaw based on the flaw"""

        ps_values = Affect.objects.filter(flaw=flaw).values_list(
            "ps_module", "ps_component"
        )

        if not ps_values:
            return []

        [ps_modules, ps_components] = list(zip(*ps_values))
        labels = FlawLabel.objects.get_filtered(ps_modules, ps_components)

        for label in labels:
            FlawCollaborator.objects.get_or_create(
                flaw=flaw,
                label=label.name,
                type=label.type,
                defaults={"state": FlawCollaborator.FlawCollaboratorState.NEW},
            )

        return labels

    @staticmethod
    def mark_irrelevant(flaw: Flaw):
        """Mark labels as irrelevant based on the current affects"""

        collaborators = FlawCollaborator.objects.filter(
            flaw=flaw, type=FlawLabel.FlawLabelType.PRODUCT_FAMILY
        )
        new_labels = [
            label.name for label in FlawCollaborator.objects.create_from_flaw(flaw)
        ]
        for collaborator in collaborators:
            if collaborator.label not in new_labels:
                collaborator.relevant = False
                collaborator.save()


class FlawCollaborator(TrackingMixin):
    class FlawCollaboratorState(models.TextChoices):
        NEW = "NEW"
        REQ = "REQ"
        SKIP = "SKIP"
        DONE = "DONE"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        Flaw,
        on_delete=models.CASCADE,
        related_name="labels",
    )

    label = models.CharField(max_length=255)

    type = models.CharField(
        max_length=20,
        choices=FlawLabel.FlawLabelType.choices,
        editable=False,
        default=FlawLabel.FlawLabelType.CONTEXT_BASED,
    )

    state = models.CharField(
        max_length=10,
        choices=FlawCollaboratorState.choices,
        default=FlawCollaboratorState.NEW,
    )

    contributor = models.CharField(max_length=255, blank=True)

    relevant = models.BooleanField(default=True)

    objects = FlawCollaboratorManager.from_queryset(CustomQuerySetUpdatedDt)()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "label"], name="unique label per flaw"
            ),
        ]

    def create(self, *args, **kwargs):
        self._validate_label()
        super().create(*args, **kwargs)

    def save(self, *args, **kwargs):
        try:
            self._validate_workflow_state()
            super().save(*args, **kwargs)
        except IntegrityError as e:
            ex_msg = str(e)
            if "duplicate key value violates unique constraint" in ex_msg:
                raise ValidationError(
                    {"label": f"Label '{self.label}' already exists."}
                )

    def _validate_workflow_state(self):
        """Flaw labels can only be added/updated in the pre-secondary assessment state"""
        if (
            self.flaw.workflow_state
            != WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        ):
            raise ValidationError(
                {"flaw": "Flaw must be in pre-secondary assessment state."}
            )

    def _validate_label(self):
        """Validate the label"""
        if not FlawLabel.objects.filter(name=self.label).exists():
            raise ValidationError({"label": f"Label '{self.label}' does not exist."})
