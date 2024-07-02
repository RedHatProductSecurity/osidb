import uuid

from django.core.cache import caches
from django.db import models
from rest_framework.throttling import UserRateThrottle

from config.settings import DEBUG
from osidb.mixins import AlertMixin
from osidb.models import ComparableTextChoices


class AlertableModelBasic(AlertMixin):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)


class AlertableModel(AlertMixin):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    def _validate_test(self):
        """
        Creates a new alert when validate() method runs.
        """
        self.alert("new_alert", "This is a new alert.")


class ComparableTextChoices_1(ComparableTextChoices):
    TEST = "TEST"


class ComparableTextChoices_2(ComparableTextChoices):
    TEST = "TEST"


class LowRateThrottle(UserRateThrottle):
    """Throttle class with very low rate to test that throttling works."""

    rate = "2/day"
    # In the test env there is no cache but for throttling to work a cache is required
    if DEBUG:
        cache = caches["locmem"]
