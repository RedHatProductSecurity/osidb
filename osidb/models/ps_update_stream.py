import uuid

from django.contrib.postgres import fields
from django.db import models

from osidb.mixins import NullStrFieldsMixin, ValidateMixin

from .ps_module import PsModule


class PsUpdateStream(NullStrFieldsMixin, ValidateMixin):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=100, unique=True)
    version = models.CharField(max_length=50, blank=True)
    target_release = models.CharField(max_length=50, blank=True)
    rhsa_sla_applicable = models.BooleanField(default=True)

    additional_fields = models.JSONField(default=dict, blank=True)
    collections = fields.ArrayField(models.TextField(), default=list, blank=True)
    flags = fields.ArrayField(models.TextField(), default=list, blank=True)

    # related PS Module
    ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="ps_update_streams",
        null=True,
        blank=True,
    )

    # special PS Module relations
    active_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="active_ps_update_streams",
        null=True,
        blank=True,
    )
    default_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="default_ps_update_streams",
        null=True,
        blank=True,
    )
    aus_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="aus_ps_update_streams",
        null=True,
        blank=True,
    )
    eus_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="eus_ps_update_streams",
        null=True,
        blank=True,
    )
    # there is only one unacked PS update stream
    # but let us link it the same way so it is unified
    unacked_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="unacked_ps_update_stream",
        null=True,
        blank=True,
    )
    # moderate streams are going to replace unacked eventually
    # but for now we keep both for the backwards compatibility
    moderate_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="moderate_ps_update_streams",
        null=True,
        blank=True,
    )
