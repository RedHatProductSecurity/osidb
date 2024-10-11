import uuid

from django.db import models

from osidb.mixins import NullStrFieldsMixin, ValidateMixin


class PsContact(NullStrFieldsMixin, ValidateMixin):

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # base RedHat username, also known as id in SFM2
    username = models.CharField(max_length=100, unique=True)

    # BTS usernames
    bz_username = models.CharField(max_length=100, blank=True)
    jboss_username = models.CharField(max_length=100, blank=True)
