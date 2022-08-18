from osidb.mixins import AlertMixin


class TestAlertModelBasic(AlertMixin):
    pass


class TestAlertModel(AlertMixin):
    def save(self, *args, **kwargs):
        self.alert("my_alert", "This alert be danger")
        super().save(*args, **kwargs)
