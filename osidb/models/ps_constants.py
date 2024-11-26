import uuid

from django.db import models


class SpecialConsiderationPackage(models.Model):
    """
    An instance of this model represents one
    entry in special consideration packages list
    from PS_Constant project
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # PsComponent name
    name = models.CharField(max_length=255, unique=True)
