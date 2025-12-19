import uuid
from functools import cached_property
from itertools import chain

import pghistory
import pgtrigger
from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import IntegrityError, models, transaction
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
                    "Save operation based on an outdated model instance: "
                    f"Updated datetime in the request {self.updated_dt} "
                    f"differes from the DB {db_self.updated_dt}. "
                    "You need to refresh."
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

    class Meta:
        abstract = True

    # TODO: Once OSIDB is autoritative source, we can stop using this compatibility
    # mixin as we would not allow the null values for the Char/Text fields anymore
    def clean(self):
        super().clean()
        self.convert_to_python()

    def convert_to_python(self):
        str_based_fields = [
            field
            for field in self._meta.get_fields()
            if isinstance(field, (models.CharField, models.TextField))
            and not field.null
        ]
        for field in str_based_fields:
            if getattr(self, field.attname) is None:
                setattr(self, field.attname, "")


class ValidateMixin(models.Model):
    """
    generic validate mixin to run standard Django validations potentially
    raising ValidationError to ensure minimal necessary data quality
    """

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        save with validate call
        """
        self.validate()
        super().save(*args, **kwargs)

    def validate(self):
        """
        validate model
        """
        # standard validations
        # exclude meta attributes
        self.full_clean(exclude=["meta_attr"])


class ACLMixinVisibility(models.TextChoices):
    """Visibility levels based on ACL read groups"""

    EMBARGOED = "EMBARGOED", "Embargoed"
    INTERNAL = "INTERNAL", "Internal"
    PUBLIC = "PUBLIC", "Public"


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
                ),
                # annotate queryset with visibility pseudo-attribute based on ACL read groups
                visibility=models.Case(
                    models.When(
                        acl_read=[
                            uuid.UUID(acl)
                            for acl in generate_acls([settings.EMBARGO_READ_GROUP])
                        ],
                        then=models.Value(ACLMixinVisibility.EMBARGOED),
                    ),
                    models.When(
                        acl_read=[
                            uuid.UUID(acl)
                            for acl in generate_acls([settings.INTERNAL_READ_GROUP])
                        ],
                        then=models.Value(ACLMixinVisibility.INTERNAL),
                    ),
                    models.When(
                        acl_read=[
                            uuid.UUID(acl)
                            for acl in generate_acls(settings.PUBLIC_READ_GROUPS)
                        ],
                        then=models.Value(ACLMixinVisibility.PUBLIC),
                    ),
                    default=models.Value(ACLMixinVisibility.PUBLIC),
                    output_field=models.CharField(),
                ),
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

    class Meta:
        abstract = True

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

    @property
    def is_internal(self):
        return set(self.acl_read + self.acl_write) == self.acls_internal

    @property
    def is_public(self):
        return set(self.acl_read + self.acl_write) == self.acls_public

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
        # Update the embargoed annotation to reflect the new ACL state
        self.embargoed = False

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
        # Update the embargoed annotation to reflect the new ACL state
        self.embargoed = True

    def set_internal(self):
        """
        Shortcut method for making an ACL-enabled entity internal.

        Calling this method on an entity will **overwrite** its acl_read
        and acl_write attributes to the default internal ones.

        e.g.:
            >>> my_flaw.acl_read
            ... [UUID(...), UUID(...), UUID(...), UUID(...)]
            >>> my_flaw.set_internal()
            >>> # note that the acl_read have been completely replaced by the
            >>> # internal ACLs only, other ones are not kept.
            >>> my_flaw.acl_read
            ... [UUID(...), UUID(...)]
        """
        self.set_acl_read(settings.INTERNAL_READ_GROUP)
        self.set_acl_write(settings.INTERNAL_WRITE_GROUP)
        # Update the embargoed annotation to reflect the new ACL state
        self.embargoed = False

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
    def acls_internal_read(self):
        """
        Get set of internal read ACLs
        """
        return {self.group2acl(settings.INTERNAL_READ_GROUP)}

    @cached_property
    def acls_internal_write(self):
        """
        Get set of internal write ACLs
        """
        return {self.group2acl(settings.INTERNAL_WRITE_GROUP)}

    @cached_property
    def acls_read(self):
        """
        get set of read ACLs
        """
        return self.acls_public_read | self.acls_embargo_read | self.acls_internal_read

    @cached_property
    def acls_write(self):
        """
        get set of write ACLs
        """
        return (
            self.acls_public_write | self.acls_embargo_write | self.acls_internal_write
        )

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
    def acls_internal(self):
        """
        Get set of internal ACLs
        """
        return self.acls_internal_read | self.acls_internal_write

    @cached_property
    def acls_all(self):
        """
        get set of all ACLs
        """
        return self.acls_read | self.acls_write

    def _validate_acls_known(self, **kwargs):
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

    def _validate_acl_read_meaningful(self, **kwargs):
        """
        validate that the read ACL is set meaninfully in a way that it contains read groups only
        """
        for acl in self.acl_read:
            if acl not in self.acls_read:
                raise ValidationError(
                    f"Read ACL contains non-read ACL group: {self.acl2group(acl)}"
                )

    def _validate_acl_write_meaningful(self, **kwargs):
        """
        validate that the write ACL is set meaninfully in a way that it contains write groups only
        """
        for acl in self.acl_write:
            if acl not in self.acls_write:
                raise ValidationError(
                    f"Write ACL contains non-write ACL group: {self.acl2group(acl)}"
                )

    def _validate_acl_expected(self, **kwargs):
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
                # TODO: this is a temporary solution for handling internal ACLs
                if acl in self.acls_internal:
                    continue
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

    def _validate_acl_duplicite(self, **kwargs):
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

    def _validate_acl_identical_to_parent_flaw(self, **kwargs):
        """
        validate that the eventual parent flaw has the identical ACLs
        """
        if hasattr(self, "flaw") and self.flaw:
            if self.is_embargoed != self.flaw.is_embargoed:
                raise ValidationError(
                    "ACLs must correspond to the parent flaw: "
                    + ("embargoed" if self.flaw.is_embargoed else "public")
                )

    def set_history_public(self):
        """
        set the history to public
        """
        refs = pghistory.models.Events.objects.tracks(self).all()
        for ref in refs:
            model_audit = apps.get_model(ref.pgh_model).objects.filter(
                pgh_id=ref.pgh_id
            )

            with pgtrigger.ignore(f"{ref.pgh_model}:append_only"):
                model_audit.update(
                    acl_read=list(self.acls_public_read),
                    acl_write=list(self.acls_public_write),
                )

    def unembargo(self):
        """
        unembargo the whole instance context internally

        in the Bugzilla world a lot of OSIDB entities are actually parts
        of the flaw bug and we will update them by a single query afterwards
        """
        # Since ACLMixin is used across related classes, each must be permitted to implement their own
        # visibility logic. Bailing out allows for unique visibility handling across such classes
        isnt_embargoed = not self.is_embargoed
        cant_unembargo = hasattr(self, "can_unembargo") and not self.can_unembargo()
        if isnt_embargoed or cant_unembargo:
            return

        # unembargo
        self.set_public()
        self.set_history_public()

        kwargs = {}
        if issubclass(type(self), AlertMixin):
            # suppress the validation errors as we expect that during
            # the update the parent and child ACLs will not equal
            kwargs["raise_validation_error"] = False
        if issubclass(type(self), TrackingMixin):
            # do not auto-update the updated_dt timestamp as the
            # followup update would fail on a mid-air collision
            kwargs["auto_timestamps"] = False

        self.save(**kwargs)

        # chain all the related instances in reverse relationships (o2m, m2m)
        # as we only care for the ACLs which are unified
        for related_instance in chain.from_iterable(
            getattr(self, name).all()
            for name in [
                related.related_name
                for related in self._meta.related_objects
                # only the models with ACLs are subject of this
                if issubclass(related.related_model, ACLMixin)
            ]
        ):
            # continue deeper into the related context
            related_instance.unembargo()

        # chain related instances in forward relationships (m2o, o2o)
        for field in self._meta.concrete_fields:
            if isinstance(
                field, (models.ForeignKey, models.OneToOneField)
            ) and issubclass(field.related_model, ACLMixin):
                related_instance = getattr(self, field.name)
                if related_instance:
                    related_instance.unembargo()

    def set_public_nested(self):
        """
        Change internal ACLs to public ACLs for all related Flaw objects and save them.
        The only exception is "snippets", which should always have internal ACLs.
        The Flaw itself will be saved later to avoid duplicate operations.
        """
        from osidb.models import Flaw

        if not isinstance(self, Flaw):
            if not self.is_internal:
                return
            kwargs = {}
            if issubclass(type(self), AlertMixin):
                # suppress the validation errors as we expect that during
                # the update the parent and child ACLs will not equal
                kwargs["raise_validation_error"] = False
            if issubclass(type(self), TrackingMixin):
                # do not auto-update the updated_dt timestamp as the
                # followup update would fail on a mid-air collision
                kwargs["auto_timestamps"] = False
            self.set_public()
            self.set_history_public()
            self.save(**kwargs)

        # chain all the related instances in reverse relationships (o2m, m2m)
        # as we only care for the ACLs which are unified
        for related_instance in chain.from_iterable(
            getattr(self, name).all()
            for name in [
                related.related_name
                for related in self._meta.related_objects
                # only the models with ACLs other than "snippets" are subject of this
                if (
                    issubclass(related.related_model, ACLMixin)
                    and related.related_name != "snippets"
                )
            ]
        ):
            # continue deeper into the related context
            related_instance.set_public_nested()

        # chain related instances in forward relationships (m2o, o2o)
        for field in self._meta.concrete_fields:
            if isinstance(
                field, (models.ForeignKey, models.OneToOneField)
            ) and issubclass(field.related_model, ACLMixin):
                related_instance = getattr(self, field.name)
                if related_instance:
                    related_instance.set_public_nested()


class AlertManager(ACLMixinManager):
    """Alert manager"""

    def get_queryset(self):
        """Add content_type select_related to avoid N+1 queries"""
        return (
            super()
            .get_queryset()
            .select_related("content_type")  # This fixes the ContentType N+1 issue
        )

    @staticmethod
    def create_alert(name, object_id, content_type, **extra_fields):
        """
        Returns the alert with the given data, or a new alert if it does not exist
        in the database.
        """
        try:
            # Alerts are uniquely defined by their name and their parent object
            alert = Alert.objects.get(
                name=name, object_id=object_id, content_type=content_type
            )
            for attr, value in extra_fields.items():
                setattr(alert, attr, value)
            return alert
        except ObjectDoesNotExist:
            return Alert(
                name=name,
                object_id=object_id,
                content_type=content_type,
                **extra_fields,
            )


class Alert(ACLMixin):
    """
    Model to store alerts issued by any model that implements the AlertMixin.
    """

    class AlertType(models.TextChoices):
        WARNING = "WARNING"
        ERROR = "ERROR"

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField()
    alert_type = models.CharField(
        max_length=10, choices=AlertType.choices, default=AlertType.WARNING
    )
    resolution_steps = models.TextField(blank=True)

    # Use of contenttype framework to allow any model to have alerts
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    # UUIDs are 36 characters long including hyphens
    object_id = models.CharField(max_length=36)
    content_object = GenericForeignKey("content_type", "object_id")

    created_dt = models.DateTimeField(blank=True, default=timezone.now)

    objects = AlertManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["name", "object_id", "content_type"],
                name="unique Alert for name and object",
            ),
        ]
        indexes = [
            GinIndex(fields=["acl_read"]),
        ]

    def __str__(self):
        """String representaion of an alert."""
        return self.name

    def _validate_acl_identical_to_parent(self, **kwargs):
        if (
            self.acl_read != self.content_object.acl_read
            or self.acl_write != self.content_object.acl_write
        ):
            raise ValidationError("Alert ACLs must match the parent object's ACLs.")


class AlertMixin(ValidateMixin):
    """
    This mixin implements the necessary mechanisms to have validation alerts.

    This mixin adds an alerts field to any model that inherits from it, from which we
    can get all alerts related to each instance of the model. The alerts are re-created
    on each save when the validations are automatically run.

    It also provides the automatic validation mechanism on every save.
    """

    alerts = GenericRelation(Alert)

    last_validated_dt = models.DateTimeField(blank=True, default=timezone.now)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        Save with validate call parametrized by raise_validation_error
        """

        dry_run = kwargs.pop("no_alerts", False)
        if not dry_run:
            self.last_validated_dt = timezone.now()

        self.validate(
            raise_validation_error=kwargs.pop("raise_validation_error", True),
            dry_run=dry_run,
        )
        # here we have to skip ValidateMixin level save as otherwise
        # it would run validate again and without proper arguments
        super(ValidateMixin, self).save(*args, **kwargs)

    @property
    def valid_alerts(self):
        """
        Get all alerts that are valid
        """
        return self.alerts.filter(created_dt__gte=self.last_validated_dt)

    def alert(
        self,
        name,
        description,
        alert_type=Alert.AlertType.WARNING,
        resolution_steps="",
        dry_run=False,
    ):
        """
        Helper for creating validation alerts on the current object.
        """
        if dry_run:
            return
        # Inherit ACLs from parent object, as long as it uses ACLs
        if isinstance(self, ACLMixin):
            acl_read = self.acl_read
            acl_write = self.acl_write
        else:
            acl_read = [
                uuid.UUID(acl) for acl in generate_acls(settings.PUBLIC_READ_GROUPS)
            ]
            acl_write = [
                uuid.UUID(acl) for acl in generate_acls([settings.PUBLIC_WRITE_GROUP])
            ]

        # When Alert.objects.create_alert().save() raises IntegrityError,
        # multiple threads tried creating the same DB row *at the same time*
        # (after each thread checking it doesn't exist from the threads'
        # perspectives, then DB cancelling 2nd, 3rd, ... concurrent requests
        # because of the UniquenessConstraint).
        #
        # The DB itself ensures (using locks internally) that only one
        # such row (Alert) can exist even if multiple clients try to create
        # one concurrently, so we don't have to handle maintaining
        # data consistency and correctness by locking the table ourselves.
        #
        # Semantics of Django and the DB force us to use a method similar
        # to _optimistic concurrency control_ - the operation is assumed
        # to succeed and a check with potential fail is performed at the end.
        #
        # Since the only time this fails is when multiple *equally old*
        # Alerts are created, such Alerts inevitably have the same meaning.
        # Therefore, retry to update(!) the Alert is not necessary: The other
        # thread created it just fine.
        # ((!): It started as creation, but when retrying, it would be updating.)
        #
        # Also for posterity why select_for_update() is not used:
        # select_for_update() (which locks the row) is both unnecessary
        # (would force serialized orderly rewriting of data by the same data)
        # and wouldn't solve the main problem of handling the uniqueness
        # constraint gracefully (if the row doesn't exist yet, there's nothing
        # to lock).
        #
        # transaction.atomic() is there because after IntegrityError, the
        # transaction can't continue and OSIDB uses ATOMIC_REQUESTS, see
        # https://stackoverflow.com/a/48836554 for use of nested tx.
        #
        # References:
        # - https://www.postgresql.org/docs/16/index-unique-checks.html#:~:text=At%20present%2C%20only-,b%2Dtree,-supports%20it.)%20Columns
        # - https://www.postgresql.org/docs/16/locking-indexes.html#:~:text=B%2Dtree%2C,without%20deadlock%20conditions.
        # - https://www.postgresql.org/files/developer/concurrency.pdf
        # - https://en.wikipedia.org/wiki/Optimistic_concurrency_control

        try:
            with transaction.atomic():
                Alert.objects.create_alert(
                    name=name,
                    object_id=self.uuid,
                    content_type=ContentType.objects.get_for_model(self),
                    description=description,
                    alert_type=alert_type,
                    resolution_steps=resolution_steps,
                    acl_read=acl_read,
                    acl_write=acl_write,
                    created_dt=timezone.now(),
                ).save()
        except IntegrityError:
            # alerts of the same name, object_id and age have the same meaning
            pass

    def convert_to_python(self, exclude=None):
        """
        run mass to_python conversion without any validations which is necessary to be able
        to run custom validations before the standard ones as they convert on top of validating

        for more details on why is this needed and how it was created see
        https://github.com/django/django/blob/stable/4.2.x/django/db/models/base.py#L1457
        https://github.com/django/django/blob/stable/4.2.x/django/db/models/base.py#L1504
        """
        # parent conversions first
        # in case it is available
        if hasattr(super(), "convert_to_python"):
            super().convert_to_python()

        if exclude is None:
            exclude = set()

        for f in self._meta.fields:
            if f.name in exclude:
                continue

            # ValidationError may be raised here
            setattr(self, f.attname, f.to_python(getattr(self, f.attname)))

    def validate(self, raise_validation_error=True, dry_run=False):
        """
        Run custom validations first and then standard Django validations as the
        custom ones offer more specific errors. This may raise ValidationError.

        Custom validations either raise ValidationError exceptions for error level
        invalidities or store the alerts for warning level ones.

        For error level invalidities the default behavior may be changed by setting
        raise_validation_error option to false, resulting in suppressing all the
        exceptions and instead storing them as error level alerts. The standard
        validations ensure minimal necessary data quality and cannot be suppressed.

        When dry_run is true no changes in alert table will be made, this option
        does not prevent validations from raising errors.
        """
        # convert the field values without validating
        self.convert_to_python(exclude=["meta_attr"])
        # but perform the full validation for the array fields
        # as the conversion does not behave the same way here
        self.full_clean(
            exclude=[
                f.name
                for f in self._meta.fields
                if not isinstance(f, fields.ArrayField)
            ]
        )

        # custom validations
        for validation_name in [
            item for item in dir(self) if item.startswith("_validate_")
        ]:
            try:
                getattr(self, validation_name)(dry_run=dry_run)
            except ValidationError as e:
                if raise_validation_error:
                    raise

                if not dry_run:
                    # do not raise but
                    # store alert as error
                    self.alert(
                        name=validation_name,
                        description=e.message,
                        alert_type=Alert.AlertType.ERROR,
                        **(e.params or {}),
                    )

        # standard validations
        # exclude meta attributes
        self.full_clean(
            exclude=["meta_attr"]
            # array fields were already validated before
            + [f.name for f in self._meta.fields if isinstance(f, fields.ArrayField)]
        )
