import uuid
from enum import Enum
from functools import cached_property

from django.conf import settings
from django.contrib.postgres import fields
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from osidb.exceptions import DataInconsistencyException

from .core import generate_acls


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
            # cut off the microseconds to allow mid-air
            # collision comparison as API works in seconds
            self.updated_dt = timezone.now().replace(microsecond=0)

        super().save(*args, **kwargs)


class TrackingMixinManager(models.Manager):
    """
    TrackingMixin companion changing the QuerySet accordingly
    """

    def get_or_create(self, defaults=None, **kwargs):
        """
        filter out auto_timestamps from the defaults
        """
        defaults.pop("auto_timestamps", None)
        return super().get_or_create(defaults, **kwargs)

    def create(self, **kwargs):
        """
        rewrite the default create taking the auto_timestamps
        into account as some instances are build this way

        specifically the factories would otherwise not work
        """
        auto_timestamps = kwargs.pop("auto_timestamps", None)
        obj = self.model(**kwargs)
        self._for_write = True
        # re-add the auto_timestamps argument only if it was actually present before
        new_kwargs = (
            {"auto_timestamps": auto_timestamps} if auto_timestamps is not None else {}
        )
        obj.save(force_insert=True, using=self.db, **new_kwargs)
        return obj


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


class ValidateMixin(models.Model):
    """
    generic validate mixin to run standard Django validations potentially
    raising ValidationError to ensure minimal necessary data quality
    """

    def validate(self):
        """
        validate model
        """
        # standard validations
        # exclude meta attributes
        self.full_clean(exclude=["meta_attr"])

    def save(self, *args, **kwargs):
        """
        save with validate call
        """
        self.validate()
        super().save(*args, **kwargs)

    class Meta:
        abstract = True


class AlertMixin(ValidateMixin):
    """
    This mixin implements the necessary mechanisms to have validation alerts.

    The way that this mixin works is simple, any model that inherits from this mixin
    will have a field in which alerts are stored in JSON, this field is re-populated
    on each save when the validations are automatically run.

    The mixin provides a helper function for creating said alerts, this also serves
    as an abstraction layer to enforce a schema on the JSON field and guarantee that
    the alerts are somewhat constant in their content.

    It also provides the automatic validation mechanism on every save.
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

    def validate(self, raise_validation_error=True):
        """
        run standard Django validations first potentially raising ValidationError
        these ensure minimal necessary data quality and thus cannot be suppressed

        then custom validations are run either raising ValidationError exceptions
        for error level invalidities or storing the alerts for warning level ones

        for error level invalidities the default behavior may be changed by setting
        raise_validation_error option to false resulting in suppressesing all the
        exceptions and instead storing them as error level alerts
        """
        # standard validations
        # exclude meta attributes
        self.full_clean(exclude=["meta_attr"])

        # clean all alerts before a new validation
        self._alerts = {}

        # custom validations
        for validation_name in [
            item for item in dir(self) if item.startswith("_validate_")
        ]:
            try:
                getattr(self, validation_name)()
            except ValidationError as e:
                if raise_validation_error:
                    raise

                # do not raise but
                # store alert as error
                self.alert(
                    name=validation_name,
                    description=e.message,
                    _type=AlertMixin.AlertType.ERROR.value,
                )

    def save(self, *args, **kwargs):
        """
        save with validate call parametrized by raise_validation_error
        """
        self.validate(raise_validation_error=kwargs.pop("raise_validation_error", True))
        # here we have to skip ValidateMixin level save as otherwise
        # it would run validate again and without proper arguments
        super(ValidateMixin, self).save(*args, **kwargs)

    class Meta:
        abstract = True


class ACLMixinManager(models.Manager):
    def get_queryset(self):
        """define base queryset for retrieving models that uses ACLs"""
        return (
            super()
            .get_queryset()
            .annotate(
                # annotate queryset with embargoed pseudo-attribute as it is fully based on the ACLs
                embargoed=models.Case(
                    models.When(
                        acl_read=[
                            uuid.UUID(acl)
                            for acl in generate_acls([settings.EMBARGO_READ_GROUP])
                        ],
                        then=True,
                    ),
                    default=False,
                    output_field=models.BooleanField(),
                )
            )
        )


class ACLMixin(models.Model):
    """
    mixin for models requiring access controls
    defining necessary attributes and validations
    """

    objects = ACLMixinManager()
    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

    # to be able to meaningfully print the ACL related alerts
    # we have to keep the mapping from the hashes to names
    acl_group_map = {}

    def __init__(self, *args, **kwargs):
        """
        init the ACLs and the group mapping
        """
        super().__init__(*args, **kwargs)
        # requesting all the ACLs performs the init
        # caching the ACLs and building the group map
        self.acls_all

    def get_embargoed_acl():
        return [uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_READ_GROUP])]

    @property
    def is_embargoed(self):
        return self.acl_read == ACLMixin.get_embargoed_acl()

    def acl2group(self, acl):
        """
        transform back to human readable group name or
        return the ACL to be printed itself if no group name
        """
        return self.acl_group_map.get(acl, acl)

    def group2acl(self, group):
        """
        transform group name to ACL record
        """
        acl = uuid.UUID(generate_acls([group])[0])
        # store for printing
        self.acl_group_map[acl] = group
        return acl

    def set_acl_read(self, *groups):
        """
        Shortcut method for setting acl_read attribute.

        This method takes in at least one plain-text group as argument and then
        does the necessary steps to convert it to a UUID and set the acl_read
        attribute to the generated UUIDs.

        Returns a list of read acls that were set.

        e.g.:
            >>> acls = my_flaw.set_acl_read("top-secret-data", "prodsec-data")
            >>> my_flaw.acl_read
            ... [UUID(...), UUID(...)]
            >>> acls == my_flaw.acl_read
            ... True
        """
        acls = [self.group2acl(group) for group in groups]
        self.acl_read = acls
        return acls

    def set_acl_write(self, *groups):
        """
        Shortcut method for setting acl_write attribute.

        This method takes in at least one plain-text group as argument and then
        does the necessary steps to convert it to a UUID and set the acl_write
        attribute to the generated UUIDs.

        Returns a list of read acls that were set.

        e.g.:
            >>> acls = my_flaw.set_acl_write("top-secret-data", "prodsec-data")
            >>> my_flaw.acl_write
            ... [UUID(...), UUID(...)]
            >>> acls == my_flaw.acl_write
            ... True
        """
        acls = [self.group2acl(group) for group in groups]
        self.acl_write = acls
        return acls

    def set_public(self):
        """
        Shortcut method for making an ACL-enabled entity public.

        Calling this method on an entity will **overwrite** its acl_read
        and acl_write attributes to the default public ones.

        e.g.:
            >>> my_flaw.acl_read
            ... [UUID(...), UUID(...), UUID(...), UUID(...)]
            >>> my_flaw.set_public()
            >>> # note that the acl_read have been completely replaced by the
            >>> # public ACLs only, other ones are not kept.
            >>> my_flaw.acl_read
            ... [UUID(...), UUID(...)]
        """
        self.set_acl_read(*settings.PUBLIC_READ_GROUPS)
        self.set_acl_write(settings.PUBLIC_WRITE_GROUP)

    def set_embargoed(self):
        """
        Shortcut method for making an ACL-enabled entity embargoed.

        Calling this method on an entity will **overwrite** its acl_read
        and acl_write attributes to the default embargoed ones.

        e.g.:
            >>> my_flaw.acl_read
            ... [UUID(...), UUID(...), UUID(...), UUID(...)]
            >>> my_flaw.set_embargoed()
            >>> # note that the acl_read have been completely replaced by the
            >>> # embargoed ACLs only, other ones are not kept.
            >>> my_flaw.acl_read
            ... [UUID(...), UUID(...)]
        """
        self.set_acl_read(settings.EMBARGO_READ_GROUP)
        self.set_acl_write(settings.EMBARGO_WRITE_GROUP)

    @cached_property
    def acls_public_read(self):
        """
        get set of public read ACLs
        """
        return {self.group2acl(group) for group in settings.PUBLIC_READ_GROUPS}

    @cached_property
    def acls_public_write(self):
        """
        get set of public write ACLs
        """
        return {self.group2acl(settings.PUBLIC_WRITE_GROUP)}

    @cached_property
    def acls_embargo_read(self):
        """
        get set of embargo read ACLs
        """
        return {self.group2acl(settings.EMBARGO_READ_GROUP)}

    @cached_property
    def acls_embargo_write(self):
        """
        get set of embargo write ACLs
        """
        return {self.group2acl(settings.EMBARGO_WRITE_GROUP)}

    @cached_property
    def acls_read(self):
        """
        get set of read ACLs
        """
        return self.acls_public_read | self.acls_embargo_read

    @cached_property
    def acls_write(self):
        """
        get set of write ACLs
        """
        return self.acls_public_write | self.acls_embargo_write

    @cached_property
    def acls_public(self):
        """
        get set of public ACLs
        """
        return self.acls_public_read | self.acls_public_write

    @cached_property
    def acls_embargo(self):
        """
        get set of embargo ACLs
        """
        return self.acls_embargo_read | self.acls_embargo_write

    @cached_property
    def acls_all(self):
        """
        get set of all ACLs
        """
        return self.acls_read | self.acls_write

    def _validate_acls_known(self):
        """
        check that all the ACLs are known
        """
        for acl in self.acl_read + self.acl_write:
            if acl not in self.acls_all:
                groups = ", ".join([self.acl2group(acl) for acl in self.acls_all])
                raise ValidationError(
                    # here the printing of the actual group is problematic
                    # as it is already a hash so we at least print all known
                    f"Unknown ACL group given - known are: {groups}"
                )

    def _validate_acl_read_meaningful(self):
        """
        validate that the read ACL is set meaninfully in a way that it contains read groups only
        """
        for acl in self.acl_read:
            if acl not in self.acls_read:
                raise ValidationError(
                    f"Read ACL contains non-read ACL group: {self.acl2group(acl)}"
                )

    def _validate_acl_write_meaningful(self):
        """
        validate that the write ACL is set meaninfully in a way that it contains write groups only
        """
        for acl in self.acl_write:
            if acl not in self.acls_write:
                raise ValidationError(
                    f"Write ACL contains non-write ACL group: {self.acl2group(acl)}"
                )

    def _validate_acl_expected(self):
        """
        validate that the ACLs corresponds to Bugzilla groups as there
        is no other access granularity (CC lists are differnt concept)

        it is either public or embargoed and nothing else
        """
        # we do not have to check the ACL emptyness
        # as it is enforced by the model definition
        # so Django throws ValidationError itself

        if self.is_embargoed:
            # here we do not have to check the read ACL as the definition
            # of is_embargoed ensures it has the proper ACL groups
            for acl in self.acl_write:
                if acl not in self.acls_embargo:
                    raise ValidationError(
                        f"Unexpected ACL group in embargoed ACLs: {self.acl2group(acl)}"
                    )

        else:
            for acl in self.acl_read + self.acl_write:
                if acl not in self.acls_public:
                    raise ValidationError(
                        f"Unexpected ACL group in non-embargoed ACLs: {self.acl2group(acl)}"
                    )

    # in Bugzilla or Jira world there is no read|write granularity and
    # we are still no authoritative source of data so we have to respect
    # that the mapping from non-identical read|write is undefined
    #
    # however we do not have to additionally validate it as it is
    # a conclusion of being non-empty with only known meaningful
    # groups and both ACLs either public or embargoed

    def _validate_acl_duplicite(self):
        """
        validate that the ACLs do not contain duplicite groups
        """
        if len(self.acl_read + self.acl_write) != len(
            set(self.acl_read + self.acl_write)
        ):
            raise ValidationError("ACLs must not contain duplicit ACL groups")

    # additionally in Bugzilla all the flaw related entities are at the end
    # stored as part of the flaw metadata so for the time being it does
    # not make any sense to have a different visibility of them

    def _validate_acl_identical_to_parent_flaw(self):
        """
        validate that the eventual parent flaw has the identical ACLs
        """
        if hasattr(self, "flaw"):
            if not self.is_embargoed == self.flaw.is_embargoed:
                raise ValidationError(
                    "ACLs must correspond to the parrent flaw: "
                    + ("embargoed" if self.flaw.is_embargoed else "public")
                )

    class Meta:
        abstract = True
