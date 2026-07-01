"""
Polymorphic label models to replace FlawCollaborator.

This is the new implementation using proper type hierarchy.
During transition, these models coexist with FlawCollaborator.
"""
# TODO after this is released and the data migrated from old labes
# to new models, the old models should be deleted and replaced by these

import uuid

import pghistory
from django.contrib.postgres import fields
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from polymorphic.models import PolymorphicModel

from osidb.mixins import TrackingMixin, ValidateMixin, validator


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    model_name="FlawLabelV2Audit",
)
class FlawLabelV2(PolymorphicModel, TrackingMixin, ValidateMixin):
    """
    Base polymorphic label model.

    All label types inherit from this model. The polymorphic_ctype field
    automatically tracks which subclass each instance belongs to.
    """

    class LabelType(models.TextChoices):
        ALIAS = "alias"
        BU = "bu"
        CONTEXT_BASED = "context_based"
        PRODUCT_FAMILY = "product_family"
        WORKFLOW = "workflow"

    # Internal primary key (matches FlawCollaborator for migration)
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Relationship to flaw
    # Using labels_v2 temporarily during migration
    flaw = models.ForeignKey(
        "Flaw",
        on_delete=models.CASCADE,
        related_name="labels_v2",
    )

    # Label name/text
    name = models.CharField(max_length=255)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "name"], name="unique_label_per_flaw_v2"
            )
        ]
        indexes = [
            models.Index(fields=["flaw"]),
            models.Index(fields=["name"]),
        ]

    # Subclasses must define their type
    type = None

    def __str__(self):
        return f"{self.name} ({self.type})"

    def validate(self):
        """
        Run custom validators and standard Django validations.
        (AlertMixin seems to be a bit heavy for label needs)

        This overrides ValidateMixin.validate()
        to call @validator methods before full_clean().
        """
        # Run custom validators first
        for validator_name in self._validators:
            getattr(self, validator_name)()

        # Then run standard Django validations
        super().validate()


class AliasLabel(FlawLabelV2):
    """
    Free-form alias labels.

    These labels don't require pre-registration and can be any text.
    Used for incident IDs, bug tracker references, or any free-form tagging.

    No additional fields needed.
    """

    type = FlawLabelV2.LabelType.ALIAS

    class Meta:
        verbose_name = "Alias Label"
        verbose_name_plural = "Alias Labels"


class BULabel(FlawLabelV2):
    """
    Business unit labels with state tracking.

    Similar to CollaboratorLabel but for business unit-specific workflows.
    Requires pre-registration in BULabelDefinition.
    """

    type = FlawLabelV2.LabelType.BU

    class State(models.TextChoices):
        NEW = "NEW"
        REQ = "REQ"
        SKIP = "SKIP"
        DONE = "DONE"

    state = models.CharField(
        max_length=10,
        choices=State.choices,
        default=State.NEW,
    )
    contributor = models.CharField(max_length=255, blank=True)
    relevant = models.BooleanField(default=True)

    class Meta:
        verbose_name = "BU Label"
        verbose_name_plural = "BU Labels"

    @validator
    def _validate_pre_registration(self, **kwargs):
        """Validate that the label name is pre-registered"""
        if not BULabelDefinition.objects.filter(name=self.name).exists():
            raise ValidationError(
                {"name": f"BU label '{self.name}' must be pre-registered."}
            )


class CollaboratorLabel(FlawLabelV2):
    """
    Context-based labels with full state management.

    These are manually created labels that require pre-registration
    in CollaboratorLabelDefinition and support full workflow state tracking.
    """

    type = FlawLabelV2.LabelType.CONTEXT_BASED

    class State(models.TextChoices):
        NEW = "NEW"
        REQ = "REQ"
        SKIP = "SKIP"
        DONE = "DONE"

    state = models.CharField(
        max_length=10,
        choices=State.choices,
        default=State.NEW,
    )
    contributor = models.CharField(max_length=255, blank=True)
    relevant = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Collaborator Label"
        verbose_name_plural = "Collaborator Labels"

    @validator
    def _validate_pre_registration(self, **kwargs):
        """Validate that the label name is pre-registered"""
        if not CollaboratorLabelDefinition.objects.filter(name=self.name).exists():
            raise ValidationError(
                {"name": f"Collaborator label '{self.name}' must be pre-registered."}
            )


class ProductFamilyLabel(FlawLabelV2):
    """
    Auto-created labels based on product definitions.

    These labels are automatically created from affects based on
    ps_module/ps_component matching rules defined in ProductFamilyLabelDefinition.
    They cannot be manually deleted via API.
    """

    type = FlawLabelV2.LabelType.PRODUCT_FAMILY

    relevant = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Product Family Label"
        verbose_name_plural = "Product Family Labels"

    @staticmethod
    def create_from_affect(affect):
        """
        Add new product family labels to the flaw based on the affect
        """
        existing = set(
            affect.flaw.labels_v2.filter(
                productfamilylabel__isnull=False,
            ).values_list("name", flat=True)
        )

        definitions = ProductFamilyLabelDefinition.get_matching(
            [affect.ps_module], [affect.ps_component]
        )

        for definition in definitions:
            if definition.name not in existing:
                ProductFamilyLabel.objects.create(
                    flaw=affect.flaw,
                    name=definition.name,
                )

    @staticmethod
    def update_relevance(flaw):
        """
        Update product family label relevance based on current affects
        """
        from osidb.models import Affect

        ps_values = Affect.objects.filter(flaw=flaw).values_list(
            "ps_module", "ps_component"
        )

        if not ps_values:
            current_names = set()
        else:
            ps_modules, ps_components = zip(*ps_values)
            definitions = ProductFamilyLabelDefinition.get_matching(
                ps_modules, ps_components
            )
            current_names = {d.name for d in definitions}

        for label in ProductFamilyLabel.objects.filter(flaw=flaw):
            new_relevant = label.name in current_names
            if label.relevant != new_relevant:
                label.relevant = new_relevant
                label.save()

            if label.name in current_names:
                current_names.discard(label.name)

        for name in current_names:
            ProductFamilyLabel.objects.create(flaw=flaw, name=name)


class WorkflowLabel(FlawLabelV2):
    """
    Workflow classification markers.

    These labels don't require pre-registration and represent binary flags.
    Presence of the label(s) navigates the workflow classification.

    No additional fields needed.
    """

    type = FlawLabelV2.LabelType.WORKFLOW

    class Meta:
        verbose_name = "Workflow Label"
        verbose_name_plural = "Workflow Labels"


# Label Definition Registry
# Only label types that require pre-registration have definition models.
# ALIAS and WORKFLOW labels are free-form and have no definition models.


class BaseLabelDefinition(models.Model):
    """
    Abstract base class for label definitions.

    Provides common fields for all definition types.
    Only types that require pre-registration inherit from this.
    """

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name


class BULabelDefinition(BaseLabelDefinition):
    """
    Registry for Business Unit labels.

    These labels must be pre-registered before they can be used.
    No additional fields needed - just name validation.
    """

    class Meta:
        verbose_name = "BU Label Definition"
        verbose_name_plural = "BU Label Definitions"


class CollaboratorLabelDefinition(BaseLabelDefinition):
    """
    Registry for context-based labels.

    These labels must be pre-registered before they can be used.
    No additional fields needed - just name validation.
    """

    class Meta:
        verbose_name = "Collaborator Label Definition"
        verbose_name_plural = "Collaborator Label Definitions"


class ProductFamilyLabelDefinition(BaseLabelDefinition):
    """
    Registry for product family labels with auto-creation filters.

    These labels are automatically created on flaws when affects match
    the ps_module/ps_component filter criteria defined here.
    """

    # Inclusion filters - affect must match these
    ps_components = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_modules = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    # Exclusion filters - affect must NOT match these
    ps_components_exclude = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_modules_exclude = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    class Meta:
        verbose_name = "Product Family Label Definition"
        verbose_name_plural = "Product Family Label Definitions"

    @staticmethod
    def get_matching(ps_modules, ps_components):
        """
        Get definitions matching given ps_modules and ps_components
        """
        return ProductFamilyLabelDefinition.objects.filter(
            (
                Q(ps_modules__overlap=list(set(ps_modules)))
                | Q(ps_components__overlap=list(set(ps_components)))
            )
            & ~(
                Q(ps_modules_exclude__overlap=list(set(ps_modules)))
                | Q(ps_components_exclude__overlap=list(set(ps_components)))
            )
        )
