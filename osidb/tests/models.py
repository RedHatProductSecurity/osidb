from osidb.mixins import AlertMixin
from osidb.models import ComparableTextChoices


class AlertModelBasic(AlertMixin):
    pass


class AlertModel(AlertMixin):
    def _validate_test(self):
        """
        Creates a new alert when validate() method runs.
        """
        self.alert("new_alert", "This is a new alert.")


class ComparableTextChoices_1(ComparableTextChoices):
    TEST = "TEST"


class ComparableTextChoices_2(ComparableTextChoices):
    TEST = "TEST"
