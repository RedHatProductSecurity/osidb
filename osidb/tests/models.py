from osidb.mixins import AlertMixin


class TestAlertModel(AlertMixin):
    def save(self, *args, **kwargs):
        self.alert("my_alert", "This alert be danger")
        super().save(*args, **kwargs)
