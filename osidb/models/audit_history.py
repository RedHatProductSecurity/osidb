from django.db import models
from pghistory import models as pg_models


class CustomHistoryBase(pg_models.Event):
    """
    Base model for all pghistory event tables
    """

    class Meta:
        abstract = True
        indexes = [
            models.Index(
                fields=["pgh_obj_id", "-pgh_created_at"],
                name="idx_%(class)s_obj_lookup",
            ),
        ]
