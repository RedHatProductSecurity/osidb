from osidb.mixins import AlertMixin


class TestAlertModelBasic(AlertMixin):
    pass


class TestAlertModel(AlertMixin):
    def _validate_test(self):
        """
        Creates a new alert when validate() method runs.
        """
        self.alert("new_alert", "This is a new alert.")
