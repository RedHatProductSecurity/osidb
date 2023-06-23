from osidb.mixins import AlertMixin
from osidb.models import ComparableTextChoices


class TestAlertModelBasic(AlertMixin):
    pass


class TestAlertModel(AlertMixin):
    def _validate_test(self):
        """
        Creates a new alert when validate() method runs.
        """
        self.alert("new_alert", "This is a new alert.")


class TestComparableTextChoices_1(ComparableTextChoices):
    TEST = "TEST"


class TestComparableTextChoices_2(ComparableTextChoices):
    TEST = "TEST"
