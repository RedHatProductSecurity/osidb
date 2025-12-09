"""
Custom model fields for OSIDB
"""

from typing import Optional

from django.core.exceptions import ValidationError
from django.db import models
from packageurl import PackageURL

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


class PURLField(models.CharField):
    """
    Custom field for Package URLs (PURLs) that automatically handles
    conversion between string representation and PackageURL objects.

    This field:
    - Stores PURLs as strings in the database (using to_string())
    - Returns PackageURL objects when accessed through the ORM
    - Validates PURLs using PackageURL.from_string()
    - Handles None/empty values appropriately
    """

    description = "A field for storing Package URLs (PURLs)"

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_length", None)
        kwargs.setdefault("blank", True)
        super().__init__(*args, **kwargs)

    def to_python(self, value: None | str | PackageURL) -> Optional[PackageURL]:
        if value is None or value == "":
            # in case of PURL being blank we return None as well in order
            # to avoid type confusion, as blank is not a valid PURL
            return None

        if isinstance(value, PackageURL):
            return value

        try:
            return PackageURL.from_string(value)
        except ValueError as e:
            raise ValidationError(f"Invalid PURL: {e}")

    def get_prep_value(self, value):
        if value is None or value == "":
            return ""

        if isinstance(value, PackageURL):
            return value.to_string()

        try:
            # here we ensure that before querying / saving to the database
            # we normalize the string so that the order of e.g. qualifiers
            # is consistent
            return PackageURL.from_string(value).to_string()
        except ValueError as e:
            raise ValidationError(f"Invalid PURL: {e}")

    def from_db_value(self, value, expression, connection):
        return self.to_python(value)
