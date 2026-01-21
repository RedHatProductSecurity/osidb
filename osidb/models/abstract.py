"""
abstract models here are not necessarily that in the Django sense
however they are not meant to be the data holders themselves but
rather building blocks of the other models or model structures
"""

import uuid

from cvss import CVSS2, CVSS3, CVSS4, CVSSError
from django.core.exceptions import ValidationError
from django.db import models

from osidb.mixins import (
    ACLMixin,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    validator,
)


class ComparableTextChoices(models.TextChoices):
    """
    extension of the models.TextChoices classes
    making them comparable with the standard operators

    the comparison order is defined simply by the
    top-down order in which the choices are written
    """

    @classmethod
    def get_choices(cls):
        """
        get processed choices
        """
        return [choice[0] for choice in cls.choices]

    @property
    def weight(self):
        """
        weight of the instance for the comparison
        defined by the order of the definition of the choices
        """
        return self.get_choices().index(str(self))

    def incomparable_with(self, other):
        """
        to ensure that that we are comparing the instances of the same type as
        comparing different types (even two ComparableTextChoices) is undefined
        """
        return type(self) is not type(other)

    def __hash__(self):
        return super().__hash__()

    def __eq__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight == other.weight

    def __ne__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight != other.weight

    def __lt__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight < other.weight

    def __gt__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight > other.weight

    def __le__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self == other or self.__lt__(other)

    def __ge__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self == other or self.__gt__(other)


class CVSS(AlertMixin, ACLMixin, NullStrFieldsMixin, TrackingMixin):
    class CVSSVersion(models.TextChoices):
        VERSION2 = "V2", "version 2"
        VERSION3 = "V3", "version 3"
        VERSION4 = "V4", "version 4"

    class CVSSIssuer(models.TextChoices):
        CVEORG = "CVEORG", "CVEORG"
        REDHAT = "RH", "Red Hat"
        NIST = "NIST", "NIST"
        OSV = "OSV", "OSV"
        CISA = "CISA", "CISA"

    CVSS_HANDLES = {
        CVSSVersion.VERSION2: CVSS2,
        CVSSVersion.VERSION3: CVSS3,
        CVSSVersion.VERSION4: CVSS4,
    }

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    vector = models.CharField(max_length=200, blank=False)

    version = models.CharField(choices=CVSSVersion.choices, max_length=10)

    issuer = models.CharField(choices=CVSSIssuer.choices, max_length=16)

    comment = models.TextField(blank=True)

    # populated by the pre_save signal
    score = models.FloatField(default=0)

    def __str__(self):
        return f"{self.score}/{self.vector}"

    @property
    def full_version(self):
        """Full name of the CVSS version."""
        return f"CVSS{self.version[1:]}"

    @property
    def cvss_object(self):
        """
        CVSS object from CVSS library parsed from the vector.
        """
        cvss_handle = self.CVSS_HANDLES[self.version]
        return cvss_handle(self.vector)

    @validator
    def _validate_cvss_string(self, **kwargs):
        """
        Use the cvss library to validate the CVSS vector string.
        """
        try:
            self.cvss_object
        except CVSSError as e:
            raise ValidationError(
                f"Invalid CVSS: Malformed {self.full_version} string: {e}"
            )

    @validator
    def _validate_cvss_comment(self, **kwargs):
        """
        For non-Red-Hat-issued CVSSs, the comment attribute should be blank.
        """
        if self.comment and self.issuer != self.CVSSIssuer.REDHAT:
            raise ValidationError(
                "CVSS comment can be set only for CVSSs issued by Red Hat."
            )

    class Meta:
        abstract = True


class Impact(ComparableTextChoices):
    """allowable impact"""

    NOVALUE = ""
    LOW = "LOW"
    MODERATE = "MODERATE"
    IMPORTANT = "IMPORTANT"
    CRITICAL = "CRITICAL"
