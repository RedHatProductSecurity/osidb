import uuid

from django.contrib.postgres import fields
from django.db import models


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
