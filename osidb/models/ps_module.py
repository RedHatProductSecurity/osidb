import uuid
from typing import Union

from django.contrib.postgres import fields
from django.db import models
from django.utils import timezone

from apps.bbsync.constants import RHSCL_BTS_KEY
from osidb.helpers import ps_update_stream_natural_keys
from osidb.mixins import NullStrFieldsMixin, ValidateMixin

from .ps_product import PsProduct


class PsModule(NullStrFieldsMixin, ValidateMixin):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # name of the module
    name = models.CharField(max_length=100, unique=True)

    public_description = models.TextField()
    cpe = fields.ArrayField(models.TextField(), default=list, blank=True)

    # Flags
    private_trackers_allowed = models.BooleanField(default=False)
    autofile_trackers = models.BooleanField(default=False)
    special_handling_features = fields.ArrayField(
        models.TextField(), default=list, blank=True
    )

    # BTS
    bts_name = models.CharField(max_length=50)
    bts_key = models.CharField(max_length=100)
    bts_groups = models.JSONField(default=dict)

    # Lifecycle
    supported_from_dt = models.DateTimeField(null=True, blank=True)
    supported_until_dt = models.DateTimeField(null=True, blank=True)

    # CC Lists
    default_cc = fields.ArrayField(
        models.CharField(max_length=50), default=list, blank=True
    )
    component_cc = models.JSONField(default=dict, blank=True)
    private_tracker_cc = fields.ArrayField(
        models.CharField(max_length=50), default=list, blank=True
    )

    # Component overrides
    default_component = models.CharField(max_length=100, blank=True)
    component_overrides = models.JSONField(default=dict, blank=True)

    # Update Streams
    # implicit:
    # ps_update_streams
    # active_ps_update_streams
    # default_ps_update_streams
    # aus_ps_update_streams
    # unacked_ps_update_stream

    ps_product = models.ForeignKey(
        PsProduct, on_delete=models.CASCADE, related_name="ps_modules"
    )

    @property
    def is_rhscl(self) -> bool:
        """
        check and return whether the PS module is RHSCL one

        Red Hat Software Collections represent an extra layer in
        the component hierarchy and may require special handling
        """
        return self.bts_key == RHSCL_BTS_KEY

    @property
    def is_prodsec_supported(self) -> bool:
        """
        check and return whether the PS module is supported now by ProdSec

        which is different from the general support scope as ProdSec often
        needs to support the security fixes even before the product is GA
        """
        # unsupported if no more supported
        if self.supported_until_dt and self.supported_until_dt < timezone.now():
            return False

        # supported otherwise even if no dates specified
        # as no support date means unrestricted support
        return True

    @property
    def is_middleware(self) -> bool:
        return self.ps_product.is_middleware

    @property
    def y_streams(self):
        """Current Y-stream(s) - it can be more of them"""

        return list(self.active_ps_update_streams.exclude(name__endswith="z"))

    @property
    def z_stream(self):
        """Current Z-stream"""
        z_streams = self.active_ps_update_streams.filter(name__endswith="z")
        return (
            max(list(z_streams), key=ps_update_stream_natural_keys)
            if z_streams
            else None
        )

    def subcomponent(self, component) -> Union[str, None]:
        """
        return the subcomponent for the given component or None if not present
        """
        if (
            self.component_overrides
            and component in self.component_overrides
            and isinstance(self.component_overrides[component], dict)
            and self.component_overrides[component].get("sub_component")
        ):
            return self.component_overrides[component]["sub_component"]
