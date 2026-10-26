import logging
import uuid
from collections import defaultdict
from functools import cached_property
from itertools import batched, chain

import pghistory
import pgtrigger
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.core.exceptions import (
    ImproperlyConfigured,
    ObjectDoesNotExist,
    ValidationError,
)
from django.db import IntegrityError, models, transaction
from django.dispatch import receiver
from django.utils import timezone

from osidb.acls import ACL
from osidb.exceptions import DataInconsistencyException

from .core import generate_acls

logger = logging.getLogger(__name__)


def validator(func):
    """
    Decorator to register a method as a validator that will be automatically
    called during save() / full_clean() operations.

    Usage:
        @validator
        def _validate_something(self, **kwargs):
            # validation logic here
            pass
    """
    # Mark the function as a validator
    func._is_validator = True
    return func


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
                actual_event_user = self._get_actual_user()

                message = (
                    f"Save operation based on an outdated model instance by "
                    f"{actual_event_user} with updated_dt {self.updated_dt} "
                    f"differs from the DB {db_self.updated_dt} check in history for details."
                )
                raise DataInconsistencyException(f"{message} You need to refresh.")

            # auto-set updated_dt as now on any change
            # cut off the microseconds to allow mid-air
            # collision comparison as API works in seconds
            self.updated_dt = timezone.now().replace(microsecond=0)

        super().save(*args, **kwargs)

    def _get_actual_user(self):
        ctx = getattr(
            pghistory.runtime._tracker, "value", None
        )  # active context for this thread, if any
        actual_user = (ctx.metadata.get("user") if ctx else None) or "unknown"
        return actual_user


class TrackingMixinManager(models.Manager):
    """
    TrackingMixin companion changing the QuerySet accordingly
    """

    def get_or_create(self, defaults=None, **kwargs):
        """
        filter out auto_timestamps from the defaults
        """
        # Copy so None is safe (Django allows defaults=None) and callers'
        # dicts are not mutated.
        defaults = dict(defaults or {})
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


_SEARCH_VECTOR_WEIGHTS = {"A", "B", "C", "D"}


def _search_vector_trigger(
    *fields: tuple[str, str],
    name: str = "update_search_vector",
    config: str = "english",
) -> pgtrigger.Trigger:
    """
    Build a BEFORE INSERT/UPDATE trigger that keeps a `search_vector` column updated from
    weighted document fields, e.g. _search_vector_trigger(("title", "A"), ("comment_zero", "B")).

    Unlike pgtrigger.UpdateSearchVector (backed by Postgres' tsvector_update_trigger), this
    supports per-field weights, which OSIDB search ranking relies on.
    """
    for column, weight in fields:
        if weight not in _SEARCH_VECTOR_WEIGHTS:
            raise ValueError(
                f"Invalid tsvector weight {weight!r} for column {column!r}"
            )
    setweights = " || ".join(
        f"setweight(to_tsvector('{config}', COALESCE(NEW.{column}, '')), '{weight}')"
        for column, weight in fields
    )
    columns = [column for column, _ in fields]
    return pgtrigger.Trigger(
        name=name,
        when=pgtrigger.Before,
        operation=pgtrigger.Insert | pgtrigger.UpdateOf(*columns),
        func=f"NEW.search_vector := {setweights}; RETURN NEW;",
    )


class SearchVectorMixin(models.Model):
    """
    Mixin adding a stored `search_vector` column for Postgres full-text search.

    Subclasses declare the weighted fields to index, e.g.:

        class Flaw(SearchVectorMixin, ...):
            search_vector_fields = (("title", "A"), ("comment_zero", "B"))

    A BEFORE INSERT/UPDATE trigger keeping the column in sync is registered automatically
    once the model class is prepared; search_vector must never be set in application code.
    """

    search_vector = SearchVectorField(null=True, editable=False)
    search_vector_fields: tuple = ()
    search_vector_config: str = "english"

    class Meta:
        abstract = True
        # unnamed so Django auto-generates a per-table name, avoiding collisions
        # across the multiple concrete models that inherit this mixin
        indexes = [GinIndex(fields=["search_vector"])]


@receiver(models.signals.class_prepared)
def _register_search_vector_trigger(sender, **kwargs):
    """
    Build and register the trigger for any concrete SearchVectorMixin subclass that
    declares search_vector_fields. Runs on class_prepared (after _meta exists) rather
    than from the mixin's own class body, since Meta.triggers set here would only take
    effect for subclasses that don't define their own Meta class.

    class_prepared is only sent for concrete models, so an abstract intermediate
    subclass (one that doesn't set search_vector_fields itself but expects a further
    subclass to) never reaches here.
    """
    if issubclass(sender, SearchVectorMixin):
        if not sender.search_vector_fields:
            raise ImproperlyConfigured(
                f"{sender.__name__} inherits from SearchVectorMixin but does not "
                "define search_vector_fields."
            )
        _search_vector_trigger(
            *sender.search_vector_fields, config=sender.search_vector_config
        ).register(sender)


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

    def __init_subclass__(cls, **kwargs):
        """
        Initialize the validators list for each subclass.
        This collects all methods decorated with @validator once
        during subclass initialization.
        """
        super().__init_subclass__(**kwargs)
        validators_list = []
        for name in dir(cls):
            try:
                method = getattr(cls, name)
                if getattr(method, "_is_validator", False):
                    validators_list.append(name)
            except AttributeError:
                # Skip attributes that can't be accessed
                continue
        cls._validators = validators_list

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


class ComparableTextChoices(models.TextChoices):
    """
    extension of the models.TextChoices classes
    making them comparable with the standard operators

    the comparison order is defined simply by the
    top-down order in which the choices are written
    """

    @classmethod
    def get_choices(cls):
        """
        get processed choices
        """
        return [choice[0] for choice in cls.choices]

    @property
    def weight(self):
        """
        weight of the instance for the comparison
        defined by the order of the definition of the choices
        """
        return self.get_choices().index(str(self))

    def incomparable_with(self, other):
        """
        to ensure that that we are comparing the instances of the same type as
        comparing different types (even two ComparableTextChoices) is undefined
        """
        return type(self) is not type(other)

    def __hash__(self):
        return super().__hash__()

    def __eq__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight == other.weight

    def __ne__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight != other.weight

    def __lt__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight < other.weight

    def __gt__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight > other.weight

    def __le__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self == other or self.__lt__(other)

    def __ge__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self == other or self.__gt__(other)


class ACLMixinVisibility(ComparableTextChoices):
    """
    ACLMixinVisibility levels based on ACL read groups

    ordered from least visible to most visible
    """

    EMBARGOED = "EMBARGOED", "Embargoed"
    INTERNAL = "INTERNAL", "Internal"
    PUBLIC = "PUBLIC", "Public"


class ACLMixin(models.Model):
    """
    mixin for models requiring access controls
    defining necessary attributes and validations
    """

    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

    embargoed = models.GeneratedField(
        expression=models.Case(
            models.When(acl_read=ACL.EMBARGO.uuid_read, then=True),
            default=False,
            output_field=models.BooleanField(),
        ),
        output_field=models.BooleanField(),
        db_persist=True,
    )

    visibility = models.GeneratedField(
        expression=models.Case(
            models.When(
                acl_read=ACL.EMBARGO.uuid_read,
                then=models.Value(ACLMixinVisibility.EMBARGOED),
            ),
            models.When(
                acl_read=ACL.INTERNAL.uuid_read,
                then=models.Value(ACLMixinVisibility.INTERNAL),
            ),
            models.When(
                acl_read=ACL.PUBLIC.uuid_read,
                then=models.Value(ACLMixinVisibility.PUBLIC),
            ),
            default=models.Value(ACLMixinVisibility.PUBLIC),
            output_field=models.CharField(),
        ),
        output_field=models.CharField(max_length=10),
        db_persist=True,
    )

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

    def inherit_parent_flaw_acls(self):
        """
        Copy acl_read/acl_write from the parent Flaw when both are unset.
        """
        if getattr(self, "flaw_id", None) and not self.acl_read and not self.acl_write:
            self.acl_read = list(self.flaw.acl_read)
            self.acl_write = list(self.flaw.acl_write)

    @property
    def current_acl(self):
        return ACL.from_acl_read(self.acl_read)

    @property
    def is_embargoed(self):
        return self.current_acl == ACL.EMBARGO

    @property
    def is_internal(self):
        return self.current_acl == ACL.INTERNAL

    @property
    def is_public(self):
        return self.current_acl == ACL.PUBLIC

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
        acls = sorted(self.group2acl(group) for group in groups)
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
        acls = sorted(self.group2acl(group) for group in groups)
        self.acl_write = acls
        return acls

    def set_acls(self, acl: ACL):
        """
        Set entity ACLs to those defined by the given ACL member.

        Ungated primitive: overwrites acl_read/acl_write unconditionally,
        including narrowing. For call sites that must never narrow
        visibility, use widen_acls (or set_public/set_internal) instead.
        """
        self.acl_read = acl.uuid_read
        self.acl_write = acl.uuid_write

    def widen_acls(self, acl: ACL):
        """
        Set entity ACLs to those defined by the given ACL member, unless the
        entity is already at or beyond that visibility, in which case this
        is a no-op. Never narrows.
        """
        if self.current_acl >= acl:
            return
        self.set_acls(acl)

    def set_public(self):
        """
        Shortcut for widen_acls(ACL.PUBLIC).
        """
        self.widen_acls(ACL.PUBLIC)

    def set_internal(self):
        """
        Shortcut for widen_acls(ACL.INTERNAL).
        """
        self.widen_acls(ACL.INTERNAL)

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
        return {self.group2acl(group) for group in settings.PUBLIC_WRITE_GROUPS}

    @cached_property
    def acls_embargo_read(self):
        """
        get set of embargo read ACLs
        """
        return {self.group2acl(group) for group in settings.EMBARGO_READ_GROUPS}

    @cached_property
    def acls_embargo_write(self):
        """
        get set of embargo write ACLs
        """
        return {self.group2acl(group) for group in settings.EMBARGO_WRITE_GROUPS}

    @cached_property
    def acls_internal_read(self):
        """
        Get set of internal read ACLs
        """
        return {self.group2acl(group) for group in settings.INTERNAL_READ_GROUPS}

    @cached_property
    def acls_internal_write(self):
        """
        Get set of internal write ACLs
        """
        return {self.group2acl(group) for group in settings.INTERNAL_WRITE_GROUPS}

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

    @validator
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

    @validator
    def _validate_acl_read_meaningful(self, **kwargs):
        """
        validate that the read ACL is set meaninfully in a way that it contains read groups only
        """
        for acl in self.acl_read:
            if acl not in self.acls_read:
                raise ValidationError(
                    f"Read ACL contains non-read ACL group: {self.acl2group(acl)}"
                )

    @validator
    def _validate_acl_write_meaningful(self, **kwargs):
        """
        validate that the write ACL is set meaninfully in a way that it contains write groups only
        """
        for acl in self.acl_write:
            if acl not in self.acls_write:
                raise ValidationError(
                    f"Write ACL contains non-write ACL group: {self.acl2group(acl)}"
                )

    @validator
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

    @validator
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

    @validator
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

    def unembargo(self):
        """
        Unembargo this instance and all its related ACL-managed objects.

        Instead of recursively calling .save() on every related object
        individually (which causes ~250 saves with signal handlers and
        non-deterministic row lock ordering leading to OSIDB-5456 deadlocks),
        this saves only the root object and then delegates to set_acls_nested()
        which performs a single bulk UPDATE per model class.
        """
        isnt_embargoed = not self.is_embargoed
        cant_unembargo = hasattr(self, "can_unembargo") and not self.can_unembargo()
        if isnt_embargoed or cant_unembargo:
            return

        with transaction.atomic():
            self.set_acls(ACL.PUBLIC)

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
            # mirror the auto_timestamps=False above: the old recursive
            # unembargo() never bumped a descendant's updated_dt either (each
            # level applied the same auto_timestamps=False to its own save()),
            # so a client holding a pre-unembargo updated_dt for a nested
            # object would not hit TrackingMixin's mid-air collision check
            self.set_acls_nested(auto_timestamps=False)

    def set_public_nested(self, max_chunk_size=5000):
        """
        Change internal ACLs to public ACLs for all related Flaw objects and save them.
        The only exception is "snippets", which should always have internal ACLs.
        The Flaw itself will be saved later to avoid duplicate operations.
        """
        self.set_acls_nested(
            [uuid.UUID(acl) for acl in generate_acls(settings.PUBLIC_READ_GROUPS)],
            [uuid.UUID(acl) for acl in generate_acls([settings.PUBLIC_WRITE_GROUP])],
            max_chunk_size=max_chunk_size,
        )

    def set_acls_nested(
        self, acl_read=None, acl_write=None, max_chunk_size=5000, auto_timestamps=True
    ):
        """
        Propagate ACLs to all related objects. Uses the given ACLs or
        falls back to the current instance's ACLs.

        Collects all related objects that need updating and performs
        chunked queryset updates to minimize database queries.

        auto_timestamps mirrors TrackingMixin.save(): when False, the
        updated_dt of nested TrackingMixin objects is left untouched instead
        of being bumped to now.
        """
        acl_read = list(acl_read if acl_read is not None else self.acl_read)
        acl_write = list(acl_write if acl_write is not None else self.acl_write)

        from osidb.models import Flaw
        from osidb.models.affect import Affect
        from osidb.models.tracker import Tracker

        root_flaw_pk = self.pk if isinstance(self, Flaw) else None

        objects_to_update = defaultdict(set)
        visited = set()
        self._collect_objects_for_acl_update(
            objects_to_update, visited, root_flaw_pk=root_flaw_pk
        )

        if not any(objects_to_update.values()):
            return

        # Guard against widening Affects that belong to other flaws.
        # The traversal walks through shared Trackers and collects
        # cross-flaw Affects; keep only those belonging to this flaw.
        if Affect in objects_to_update and objects_to_update[Affect]:
            if root_flaw_pk is not None:
                own_affect_pks = set(
                    Affect.objects.filter(
                        pk__in=objects_to_update[Affect],
                        flaw_id=root_flaw_pk,
                    ).values_list("pk", flat=True)
                )
                objects_to_update[Affect] = own_affect_pks

        # Guard against prematurely widening Trackers that are shared with
        # other embargoed Flaws.  A Tracker linked to Affects from multiple
        # Flaws must stay embargoed as long as ANY of its parent Affects
        # (from Flaws NOT being updated in this operation) are still
        # embargoed.
        if Tracker in objects_to_update and objects_to_update[Tracker]:
            if root_flaw_pk is not None:
                blocked_tracker_pks = set(
                    Affect.objects.filter(
                        tracker_id__in=objects_to_update[Tracker],
                        embargoed=True,
                    )
                    .exclude(flaw_id=root_flaw_pk)
                    .values_list("tracker_id", flat=True)
                    .distinct()
                )
                objects_to_update[Tracker] -= blocked_tracker_pks

        now = timezone.now().replace(microsecond=0)
        any_updated = False

        for model_class, object_ids in sorted(
            objects_to_update.items(), key=lambda item: item[0]._meta.label_lower
        ):
            if not object_ids:
                continue

            if not issubclass(model_class, ACLMixin):
                continue

            update_kwargs = {"acl_read": acl_read, "acl_write": acl_write}
            if issubclass(model_class, TrackingMixin):
                # Several models' default manager uses
                # CustomQuerySetUpdatedDt, whose update() auto-injects
                # updated_dt=now() whenever it is absent from kwargs. Passing
                # models.F("updated_dt") keeps this a true no-op (and is a
                # harmless explicit no-op for the models that don't use that
                # queryset either) while still opting out of the bump.
                update_kwargs["updated_dt"] = (
                    now if auto_timestamps else models.F("updated_dt")
                )

            updated_pks = []
            for pk_chunk in batched(sorted(object_ids, key=str), max_chunk_size):
                # Sorting pk_chunk only orders the Python-side list; it does
                # not constrain the lock order of the plain SELECT below or
                # of the bulk UPDATE further down, since Postgres is free to
                # scan/lock a `pk IN (...)` match in whatever order its query
                # plan picks (e.g. bitmap heap scans visit rows in physical,
                # not logical, order). Two concurrent callers touching
                # overlapping rows could then lock them in different orders
                # and deadlock -- the exact OSIDB-5456 failure mode this
                # bulk approach is meant to remove. select_for_update()
                # combined with order_by("pk") makes Postgres lock the rows
                # in pk order up front (via an index scan on the pk index),
                # so the later bulk UPDATE -- which only touches rows this
                # same transaction already holds the lock on -- can't
                # introduce a different lock order. no_key=True since this
                # only ever updates non-key columns (acl_read, acl_write,
                # updated_dt), matching the select_for_update() usage
                # elsewhere in the codebase. skip_locked is deliberately not
                # used: skipping a locked-but-not-yet-updated row would leave
                # it with stale ACLs instead of just being slower.
                queryset = (
                    model_class.objects.select_for_update(no_key=True)
                    .filter(pk__in=pk_chunk)
                    .exclude(acl_read=acl_read, acl_write=acl_write)
                )
                pk_chunk_to_update = list(
                    queryset.order_by("pk").values_list("pk", flat=True)
                )
                if not pk_chunk_to_update:
                    continue

                model_class.objects.filter(pk__in=pk_chunk_to_update).exclude(
                    acl_read=acl_read,
                    acl_write=acl_write,
                ).update(**update_kwargs)
                updated_pks.extend(pk_chunk_to_update)

                # Alert is attached via a GenericRelation (content_type +
                # object_id), so it is never visited by
                # _collect_objects_for_acl_update and its own acl_read/
                # acl_write would otherwise go stale here. Propagate
                # explicitly for now, chunked the same way as the update
                # above so this stays bounded by max_chunk_size too.
                #
                # Longer term, Alert is a strong candidate for the same
                # treatment given to the audit tables in
                # osidb/migrations/0276_rls_audit_delegation.py: have its RLS
                # policies delegate to the parent object's ACL (via a
                # SECURITY DEFINER lookup keyed on content_type/object_id)
                # instead of storing/propagating its own ACL columns. An
                # Alert is rarely, if ever, meaningful outside the context of
                # its parent, so delegating removes this whole class of bug.
                if issubclass(model_class, AlertMixin):
                    Alert.objects.filter(
                        content_type=ContentType.objects.get_for_model(model_class),
                        object_id__in=[str(pk) for pk in pk_chunk_to_update],
                    ).update(acl_read=acl_read, acl_write=acl_write)

            if updated_pks:
                any_updated = True

        # Deliberately not re-dispatching post_save per updated row here: doing
        # so would re-save the parent Flaw once per child (via the
        # *_update_local_updated_dt receivers in signals.py), reintroducing
        # the O(n) save pattern this bulk approach replaces. The one effect
        # those receivers provide that matters here -- keeping the root
        # Flaw's local_updated_dt (used by the changed_after/changed_before
        # API filters) in sync with its nested entities -- is applied once
        # below instead. updated_dt=F("updated_dt") keeps this a no-op for
        # Flaw's own mid-air collision timestamp (see comment above).
        #
        # Note this also means any *other* pre_save/post_save side effect on
        # a bulk-updated model (label maintenance, denormalized fields,
        # impact tracking, etc.) does not run here, same as it already
        # doesn't for the pre_save side given QuerySet.update() bypasses
        # Django signals entirely. As of writing, every such receiver on the
        # affected models is gated on a field this bulk ACL-only update never
        # touches, so none has a missing side effect in practice -- but a
        # future receiver that reacts to acl_read/acl_write specifically
        # would need its own bulk-safe handling here.
        if any_updated and root_flaw_pk is not None:
            Flaw.objects.filter(pk=root_flaw_pk).update(
                local_updated_dt=now, updated_dt=models.F("updated_dt")
            )

    def _collect_objects_for_acl_update(
        self, objects_to_update, visited, root_flaw_pk=None
    ):
        """
        Recursively collect all related objects that need to have their ACLs
        updated. The Flaw itself is not collected as it's saved separately.

        Uses a defaultdict(set) keyed by model class to collect pks.
        Uses a set of (type, pk) to prevent infinite recursion.

        When root_flaw_pk is set, the traversal will not cross flaw
        boundaries: foreign Flaws and Affects belonging to other Flaws
        are skipped so their children are never collected.
        """
        from osidb.models import Flaw

        if self.pk is None:
            return

        if root_flaw_pk is not None:
            if isinstance(self, Flaw) and self.pk != root_flaw_pk:
                return
            if hasattr(self, "flaw_id") and self.flaw_id != root_flaw_pk:
                return

        visit_key = (type(self), self.pk)

        if visit_key in visited:
            return

        visited.add(visit_key)

        if not isinstance(self, Flaw):
            objects_to_update[type(self)].add(self.pk)

        for related_instance in chain.from_iterable(
            getattr(self, name).all()
            for name in [
                related.related_name
                for related in self._meta.related_objects
                if (
                    issubclass(related.related_model, ACLMixin)
                    and related.related_name is not None
                    and related.related_name != "snippets"
                )
            ]
        ):
            related_instance._collect_objects_for_acl_update(
                objects_to_update, visited, root_flaw_pk=root_flaw_pk
            )
        for field in self._meta.concrete_fields:
            if isinstance(
                field, (models.ForeignKey, models.OneToOneField)
            ) and issubclass(field.related_model, ACLMixin):
                related_instance = getattr(self, field.name)
                if related_instance:
                    related_instance._collect_objects_for_acl_update(
                        objects_to_update, visited, root_flaw_pk=root_flaw_pk
                    )


class AlertManager(models.Manager):
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

    @validator
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
                uuid.UUID(acl) for acl in generate_acls(settings.PUBLIC_WRITE_GROUPS)
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
            if f.name in exclude or f.generated:
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
        for validator_name in self._validators:
            try:
                getattr(self, validator_name)(dry_run=dry_run)
            except ValidationError as e:
                if raise_validation_error:
                    raise

                if not dry_run:
                    # do not raise but
                    # store alert as error
                    self.alert(
                        name=validator_name,
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
