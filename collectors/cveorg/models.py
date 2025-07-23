import uuid

from django.db import models


class Keyword(models.Model):
    """
    An instance of this model represents a keyword of a given type
    collected from `data/cveorg_keywords.yml` in the `ps-constants` repository.

    These keywords determine whether the CVEorg collector should create a flaw.
    """

    class Type(models.TextChoices):
        ALLOWLIST = "ALLOWLIST"
        ALLOWLIST_SPECIAL_CASE = "ALLOWLIST_SPECIAL_CASE"
        BLOCKLIST = "BLOCKLIST"
        BLOCKLIST_SPECIAL_CASE = "BLOCKLIST_SPECIAL_CASE"
        CNA_ASSIGNERORGID_BLOCKLIST = "CNA_ASSIGNERORGID_BLOCKLIST"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keyword = models.CharField(max_length=255, unique=True)
    type = models.CharField(choices=Type.choices, max_length=25)
