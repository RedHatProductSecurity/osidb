"""
Polymorphic label models for flaws.

Each label type is a proper Django subclass of the base FlawLabel model.
The polymorphic content type field automatically tracks which subclass
each instance belongs to.
"""

import uuid

import pghistory
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from polymorphic.managers import PolymorphicManager
from polymorphic.models import PolymorphicModel

from osidb.mixins import (
    ACLMixin,
    TrackingMixin,
    TrackingMixinManager,
    ValidateMixin,
    validator,
)


class FlawLabelManager(PolymorphicManager, TrackingMixinManager):
    """Manager combining ACL annotations with polymorphic queries."""


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    # Legacy name kept to match the existing audit table and its RLS policies;
    # registered_audit_tables() discovers it via this model_name.
    model_name="FlawLabelV2Audit",
)
class FlawLabel(PolymorphicModel, ACLMixin, TrackingMixin, ValidateMixin):
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

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        "Flaw",
        on_delete=models.CASCADE,
        related_name="labels",
    )

    name = models.CharField(max_length=255)

    objects = FlawLabelManager()

    class Meta:
        db_table = "osidb_flawlabelv2"
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "name"], name="unique_label_per_flaw"
            )
        ]
        indexes = TrackingMixin.Meta.indexes + [
            models.Index(fields=["flaw"]),
            models.Index(fields=["name"]),
            GinIndex(fields=["acl_read"]),
        ]

    type = None

    def __str__(self):
        return f"{self.name} ({self.type})"

    def save(self, *args, **kwargs):
        self.inherit_parent_flaw_acls()
        super().save(*args, **kwargs)

    def validate(self):
        """
        Run custom validators and standard Django validations.
        (AlertMixin seems to be a bit heavy for label needs)

        This overrides ValidateMixin.validate()
        to call @validator methods before full_clean().
        """
        for validator_name in self._validators:
            getattr(self, validator_name)()
        super().validate()


class AliasLabel(FlawLabel):
    """
    Free-form alias labels.

    These labels don't require pre-registration and can be any text.
    Used for incident IDs, bug tracker references, or any free-form tagging.

    No additional fields needed.
    """

    flawlabel_ptr = models.OneToOneField(
        FlawLabel,
        on_delete=models.CASCADE,
        parent_link=True,
        primary_key=True,
        serialize=False,
        db_column="flawlabelv2_ptr_id",
    )

    type = FlawLabel.LabelType.ALIAS

    class Meta:
        verbose_name = "Alias Label"
        verbose_name_plural = "Alias Labels"


class BULabel(FlawLabel):
    """
    Business unit labels with state tracking.

    Similar to CollaboratorLabel but for business unit-specific workflows.
    Requires pre-registration in BULabelDefinition.
    """

    flawlabel_ptr = models.OneToOneField(
        FlawLabel,
        on_delete=models.CASCADE,
        parent_link=True,
        primary_key=True,
        serialize=False,
        db_column="flawlabelv2_ptr_id",
    )

    type = FlawLabel.LabelType.BU

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


class CollaboratorLabel(FlawLabel):
    """
    Context-based labels with full state management.

    These are manually created labels that require pre-registration
    in CollaboratorLabelDefinition and support full workflow state tracking.
    """

    flawlabel_ptr = models.OneToOneField(
        FlawLabel,
        on_delete=models.CASCADE,
        parent_link=True,
        primary_key=True,
        serialize=False,
        db_column="flawlabelv2_ptr_id",
    )

    type = FlawLabel.LabelType.CONTEXT_BASED

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


class ProductFamilyLabel(FlawLabel):
    """
    Auto-created labels based on product definitions.

    These labels are automatically created from affects based on
    ps_module/ps_component matching rules defined in ProductFamilyLabelDefinition.
    They cannot be manually deleted via API.
    """

    flawlabel_ptr = models.OneToOneField(
        FlawLabel,
        on_delete=models.CASCADE,
        parent_link=True,
        primary_key=True,
        serialize=False,
        db_column="flawlabelv2_ptr_id",
    )

    type = FlawLabel.LabelType.PRODUCT_FAMILY

    relevant = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Product Family Label"
        verbose_name_plural = "Product Family Labels"

    @staticmethod
    def create_from_affect(affect):
        """
        Add new product family labels to the flaw based on the affect
        """
        existing = set(affect.flaw.labels.values_list("name", flat=True))

        definitions = ProductFamilyLabelDefinition.get_matching(
            [affect.ps_module], [affect.ps_component]
        )

        for definition in definitions:
            if definition.name not in existing:
                ProductFamilyLabel.objects.create(
                    flaw=affect.flaw,
                    name=definition.name,
                    acl_read=list(affect.flaw.acl_read),
                    acl_write=list(affect.flaw.acl_write),
                )
            else:
                ProductFamilyLabel.objects.filter(
                    flaw=affect.flaw, name=definition.name, relevant=False
                ).update(relevant=True)

    @staticmethod
    def update_relevance(flaw):
        """
        Update product family label relevance based on current affects.

        Exclusions are evaluated per-affect so that an excluded module on
        one affect does not suppress a definition matched by another affect.
        """
        from osidb.models import Affect

        ps_values = list(
            Affect.objects.filter(flaw=flaw).values_list("ps_module", "ps_component")
        )

        definitions = list(ProductFamilyLabelDefinition.objects.all())

        current_names = set()
        for ps_module, ps_component in ps_values:
            for definition in definitions:
                if definition.matches(ps_module, ps_component):
                    current_names.add(definition.name)

        for label in ProductFamilyLabel.objects.filter(flaw=flaw):
            new_relevant = label.name in current_names
            if label.relevant != new_relevant:
                label.relevant = new_relevant
                label.save()

            if new_relevant:
                current_names.discard(label.name)

        existing_names = set(flaw.labels.values_list("name", flat=True))

        for name in current_names:
            if name not in existing_names:
                ProductFamilyLabel.objects.create(
                    flaw=flaw,
                    name=name,
                    acl_read=list(flaw.acl_read),
                    acl_write=list(flaw.acl_write),
                )


class WorkflowLabel(FlawLabel):
    """
    Workflow classification markers.

    These labels don't require pre-registration and represent binary flags.
    Presence of the label(s) navigates the workflow classification.
    """

    flawlabel_ptr = models.OneToOneField(
        FlawLabel,
        on_delete=models.CASCADE,
        parent_link=True,
        primary_key=True,
        serialize=False,
        db_column="flawlabelv2_ptr_id",
    )

    type = FlawLabel.LabelType.WORKFLOW

    reason = models.TextField(
        blank=True,
        default="",
        help_text="Explanation for why this workflow label was applied (set by automation).",
    )

    class Meta:
        verbose_name = "Workflow Label"
        verbose_name_plural = "Workflow Labels"


FlawLabel.TYPE_TO_MODEL = {
    FlawLabel.LabelType.ALIAS: AliasLabel,
    FlawLabel.LabelType.BU: BULabel,
    FlawLabel.LabelType.CONTEXT_BASED: CollaboratorLabel,
    FlawLabel.LabelType.PRODUCT_FAMILY: ProductFamilyLabel,
    FlawLabel.LabelType.WORKFLOW: WorkflowLabel,
}


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

    ps_components = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_modules = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_components_exclude = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    ps_modules_exclude = fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )

    class Meta:
        verbose_name = "Product Family Label Definition"
        verbose_name_plural = "Product Family Label Definitions"

    def matches(self, ps_module, ps_component):
        """Check if a single ps_module/ps_component pair matches this definition."""
        included = ps_module in self.ps_modules or ps_component in self.ps_components
        excluded = (
            ps_module in self.ps_modules_exclude
            or ps_component in self.ps_components_exclude
        )
        return included and not excluded

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
