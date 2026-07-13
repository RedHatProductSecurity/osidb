from django.utils import timezone

from osidb.mixins import ACLMixinQuerySet


class CustomQuerySetUpdatedDt(ACLMixinQuerySet):
    """Extend QuerySet to inject updated_dt on update"""

    def update(self, auto_timestamps=True, **kwargs):
        """
        if auto_timestamps is True and updated_dt is NOT present in kwargs updated_dt is set to now
        """
        if auto_timestamps:
            if getattr(self.model, "updated_dt", False):
                if "updated_dt" not in kwargs:
                    kwargs["updated_dt"] = timezone.now().replace(microsecond=0)

        return super().update(**kwargs)
