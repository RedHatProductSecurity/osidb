from django.db import models
from django.utils import timezone


class CustomQuerySetUpdatedDt(models.QuerySet):
    """Extend QuerySet to inject updated_dt on update"""

    def update(self, **kwargs):
        if getattr(self.model, "updated_dt", False):
            if "updated_dt" not in kwargs:
                kwargs["updated_dt"] = timezone.now().replace(microsecond=0)

        return super().update(**kwargs)
