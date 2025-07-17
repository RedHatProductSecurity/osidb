"""
Custom model fields for OSIDB
"""

from django.db import models

from osidb.validators import validate_cve_id


class CVEIDField(models.CharField):
    """
    Custom field for CVE IDs that encompasses all CVE ID functionality.

    This field automatically handles:
    - CVE ID validation using the validate_cve_id validator
    - Null and blank handling
    - Unique constraint
    """

    description = "A field for storing CVE identifiers"

    def __init__(self, *args, **kwargs):
        # Set default values for CVE ID fields
        kwargs.setdefault("max_length", None)
        kwargs.setdefault("null", True)
        kwargs.setdefault("unique", True)
        kwargs.setdefault("blank", True)
        kwargs.setdefault("validators", []).append(validate_cve_id)

        super().__init__(*args, **kwargs)

    def deconstruct(self):
        """
        Return the field's parameters for migrations.
        Remove the default validators since they're added automatically.
        """
        name, path, args, kwargs = super().deconstruct()

        # the `is not True` is deliberate, as `True` is the Field's default
        # value for the unique attribute
        if getattr(self, "_unique") is not True:
            # this is necessary because Django's default implementation of
            # deconstruct() hardcodes the default values of all common
            # attributes for all field types, meaning that if a developer
            # explicitly sets cve_id = CVEIDField(unique=False) for whatever
            # reason, the deconstruct() method will *not* include it in the
            # final migration, as it assumes that's the default, whereas in
            # the case of CVEIDField the default is True
            kwargs["unique"] = False

        # Remove validators that we add automatically to prevent duplication in migrations
        if "validators" in kwargs:
            kwargs["validators"] = [
                v for v in kwargs["validators"] if v != validate_cve_id
            ]
            if not kwargs["validators"]:
                del kwargs["validators"]

        return name, path, args, kwargs
