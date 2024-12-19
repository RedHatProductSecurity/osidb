import uuid

from django.contrib.postgres import fields
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models

from osidb.mixins import TrackingMixin
from osidb.models import Flaw


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

    def __str__(self):
        return self.name


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

    label = models.ForeignKey(
        FlawLabel,
        to_field="name",
        on_delete=models.CASCADE,
    )

    state = models.CharField(
        max_length=10,
        choices=FlawCollaboratorState.choices,
        default=FlawCollaboratorState.NEW,
    )

    contributor = models.CharField(max_length=255, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "label"], name="unique label per flaw"
            ),
        ]

    def save(self, *args, **kwargs):
        try:
            super().save(*args, **kwargs)
        except IntegrityError as e:
            ex_msg = str(e)
            if "duplicate key value violates unique constraint" in ex_msg:
                raise ValidationError(
                    {"label": f"Label '{self.label}' already exists."}
                )
