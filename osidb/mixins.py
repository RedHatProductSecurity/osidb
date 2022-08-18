from enum import Enum

from django.db import models
from django.utils import timezone

from osidb.exceptions import DataInconsistencyException


class TrackingMixin(models.Model):
    """
    Mixin for tracking create/update datetimes and other changes to records.
    """

    created_dt = models.DateTimeField(blank=True)
    updated_dt = models.DateTimeField(blank=True)

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["-updated_dt"]),
        ]

    def save(self, *args, auto_timestamps=True, **kwargs):
        """
        save created_dt as now on creation
        save updated_dt as now on update

        the timestamps may be set to specified
        values by setting auto_timestamps=False
        """
        # allow disabling timestamp auto-updates
        if auto_timestamps:

            # get DB counterpart of self if any
            db_self = type(self).objects.filter(pk=self.pk).first()

            # auto-set created_dt as now on creation and never change it otherwise
            self.created_dt = timezone.now() if db_self is None else db_self.created_dt

            # updated_dt should never change from the DB version
            # otherwise assume that there was a conflicting parallel change
            if db_self is not None and db_self.updated_dt != self.updated_dt:
                raise DataInconsistencyException(
                    "Save operation based on an outdated model instance"
                )

            # auto-set updated_dt as now on any change
            self.updated_dt = timezone.now()

        super().save(*args, **kwargs)


class NullStrFieldsMixin(models.Model):
    """
    Mixin which implements replacing the None (null) values of
    string based fields (Char/Text) with not allowed None (null)
    values

    This mixin is used for compatibility purposes because in SFM2,
    None (null) values are allowed for the Char/Text fields.
    Django itself really discourages usage of the null=True for the
    string based fields since two possible empty values are then
    possible (empty string vs. None/null).
    See https://docs.djangoproject.com/en/4.0/ref/models/fields/#django.db.models.Field.null
    """

    # TODO: Once OSIDB is autoritative source, we can stop using this compatibility
    # mixin as we would not allow the null values for the Char/Text fields anymore
    def clean(self):
        super().clean()

        str_based_fields = [
            field
            for field in self._meta.get_fields()
            if isinstance(field, (models.CharField, models.TextField))
            and not field.null
        ]
        for field in str_based_fields:
            if getattr(self, field.attname) is None:
                setattr(self, field.attname, "")

    class Meta:
        abstract = True


class AlertMixin(models.Model):
    """
    This mixin implements the necessary mechanisms to have validation alerts.

    The way that this mixin works is simple, any model that inherits from this mixin
    will have a field in which alerts are stored in JSON, this field is re-populated
    on each save when the validations are run.

    The mixin provides a helper function for creating said alerts, this also serves
    as an abstraction layer to enforce a schema on the JSON field and guarantee that
    the alerts are somewhat constant in their content.
    """

    _alerts = models.JSONField(default=dict, blank=True)

    class AlertType(Enum):
        WARNING = "warning"
        ERROR = "error"

    def alert(self, name, description, _type="warning", resolution_steps=""):
        """
        Helper for creating validation alerts on the current object.

        Any and all alerts should be created through this helper method as it
        guarantees a certain level consistency in the structure of each alert.

        The _alerts column should only be modified manually if you really
        **really** know what you're doing, as manual modification might break
        the "schema" and create issues for downstream consumers.
        """
        # verify that _type is valid
        try:
            self.AlertType(_type)
        except ValueError:
            _t = [t.value for t in self.AlertType]
            raise ValueError(f"Alert type '{_type}' is not valid, use one of {_t}")
        self._alerts[name] = {
            "type": _type,
            "description": description,
            "resolution_steps": resolution_steps,
        }

    class Meta:
        abstract = True
