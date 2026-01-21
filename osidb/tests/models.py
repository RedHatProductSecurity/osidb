import uuid

from django.db import models

from osidb.mixins import AlertMixin, validator
from osidb.models import ComparableTextChoices
from osidb.models.fields import PURLField


class AlertableModelBasic(AlertMixin):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)


class AlertableModel(AlertMixin):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    @validator
    def _validate_test(self, **kwargs):
        """
        Creates a new alert when validate() method runs.
        """
        self.alert("new_alert", "This is a new alert.", **kwargs)


class ComparableTextChoices_1(ComparableTextChoices):
    TEST = "TEST"


class ComparableTextChoices_2(ComparableTextChoices):
    TEST = "TEST"


class PURLTestModel(models.Model):
    """Test model for PURLField"""

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    purl = PURLField()

    class Meta:  # type: ignore
        app_label = "tests"
