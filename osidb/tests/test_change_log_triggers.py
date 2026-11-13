"""Exercise the installed triggers, not a Python approximation of their SQL."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event

import pgtrigger
import pytest
from django.apps import apps
from django.conf import settings
from django.db import DatabaseError, connection, transaction
from django.db.models import F
from django.db.utils import ProgrammingError
from django.utils import timezone

from osidb.core import set_user_acls
from osidb.models import (
    Affect,
    AffectCVSS,
    AliasLabel,
    BULabel,
    BULabelDefinition,
    CollaboratorLabel,
    CollaboratorLabelDefinition,
    Flaw,
    FlawChangeEvent,
    FlawComment,
    FlawLabel,
    FlawSource,
    ProductFamilyLabel,
    Tracker,
    WorkflowLabel,
)
from osidb.tests.event_helpers import latest_event, reset_events
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
    UpstreamDataFactory,
)
from osidb.watermark_triggers import EXCLUDED_FIELDS, tracked_fields

pytestmark = pytest.mark.unit


def stamp(flaw):
    return latest_event(flaw).local_updated_dt


def reset_stamp(*flaws):
    """Set a known past baseline without changing source data."""
    baseline = timezone.now() - timedelta(days=1)
    reset_events(flaws, baseline)
    return baseline


def db_now():
    with connection.cursor() as cursor:
        cursor.execute("SELECT statement_timestamp()")
        return cursor.fetchone()[0]


@pytest.mark.parametrize("method", ["save", "update", "bulk_update", "raw"])
def test_flaw_business_changes_all_write_paths(method, monkeypatch):
    flaw = FlawFactory()
    baseline = reset_stamp(flaw)
    before = db_now()
    original_updated = flaw.updated_dt
    if method == "save":
        flaw.title = "changed through save"
        flaw.save(auto_timestamps=False, no_alerts=True)
    else:
        monkeypatch.setattr(Flaw, "save", lambda *a, **kw: pytest.fail("Flaw save"))
        if method == "update":
            Flaw.objects.filter(pk=flaw.pk).update(title="changed through update")
        elif method == "bulk_update":
            flaw.title = "changed through bulk update"
            Flaw.objects.bulk_update([flaw], ["title"])
        else:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE osidb_flaw SET title = 'changed through SQL' WHERE uuid = %s",
                    [flaw.pk],
                )
    assert baseline < before <= stamp(flaw) <= db_now()
    # The existing custom QuerySet injects updated_dt even inside bulk_update;
    # this is legacy behavior, not an UPDATE issued by the watermark trigger.
    if method in {"raw", "save"}:
        flaw.refresh_from_db()
        assert flaw.updated_dt == original_updated


def test_bulk_create_uses_db_clock_and_current_cve():
    objects = FlawFactory.build_batch(20)
    before = db_now()
    Flaw.objects.bulk_create(objects)
    assert FlawChangeEvent.objects.count() == 20
    for flaw in objects:
        watermark = latest_event(flaw)
        assert watermark.flaw_id == flaw.pk
        assert before <= watermark.local_updated_dt <= db_now()


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_key", "OSIM-5827"),
        ("bz_id", 1234567),
        ("mitre_cve_description", "New MITRE description"),
        ("reported_dt", timezone.now() - timedelta(days=10)),
        ("unembargo_dt", timezone.now() + timedelta(days=10)),
    ],
)
def test_required_and_domain_fields(field, value):
    flaw = FlawFactory()
    baseline = reset_stamp(flaw)
    Flaw.objects.filter(pk=flaw.pk).update(**{field: value})
    assert stamp(flaw) > baseline


@pytest.mark.parametrize(
    "field",
    sorted(
        (EXCLUDED_FIELDS & {f.name for f in Flaw._meta.local_concrete_fields})
        - {"embargoed", "search_vector"}
    ),
)
def test_explicit_exclusions(field):
    flaw = FlawFactory()
    baseline = reset_stamp(flaw)
    if field in {"acl_read", "acl_write"}:
        value = F(field)  # same-visibility ACL edits have separate coverage
    elif field == "meta_attr":
        value = {"watermark": "excluded"}
    elif field in {"aegis_meta", "assist_meta"}:
        value = {"watermark": "excluded"}
    elif field == "classification_meta":
        value = ["excluded"]
    else:
        value = timezone.now() + timedelta(days=1)
    Flaw.objects.filter(pk=flaw.pk).update(**{field: value})
    assert stamp(flaw) == baseline


def test_noop_empty_statement_and_computed_search_vector():
    flaw = FlawFactory()
    baseline = reset_stamp(flaw)
    Flaw.objects.filter(pk=flaw.pk).update(title=F("title"))
    Flaw.objects.filter(pk=flaw.pk).update(search_vector=None)
    Flaw.objects.none().update(title="nothing")
    assert stamp(flaw) == baseline


def test_visibility_counts_but_acl_only_same_visibility_does_not(
    public_read_groups, public_write_groups, embargoed_read_groups
):
    flaw = FlawFactory(embargoed=False)
    baseline = reset_stamp(flaw)
    # A noncanonical read array still maps to PUBLIC in the generated expression.
    Flaw.objects.filter(pk=flaw.pk).update(
        acl_read=public_read_groups + public_write_groups
    )
    assert stamp(flaw) == baseline
    Flaw.objects.filter(pk=flaw.pk).update(acl_read=embargoed_read_groups)
    assert stamp(flaw) > baseline


@pytest.mark.parametrize(
    "factory,field,value",
    [
        (AffectFactory, "impact", "LOW"),
        (FlawCommentFactory, "text", "edited comment"),
        (FlawReferenceFactory, "description", "edited reference"),
        (FlawAcknowledgmentFactory, "name", "edited acknowledgment"),
        (FlawCVSSFactory, "comment", "edited CVSS"),
    ],
)
def test_direct_child_create_update_reassign_delete(factory, field, value, monkeypatch):
    old, new = FlawFactory.create_batch(2, source=FlawSource.REDHAT)
    baseline = reset_stamp(old, new)
    child = factory(flaw=old)
    assert stamp(old) > baseline
    if field == "impact" and child.impact == value:
        value = "CRITICAL"
    monkeypatch.setattr(Flaw, "save", lambda *a, **kw: pytest.fail("Flaw save"))
    baseline = reset_stamp(old, new)
    type(child).objects.filter(pk=child.pk).update(**{field: value})
    assert stamp(old) > baseline
    assert stamp(new) == baseline
    baseline = reset_stamp(old, new)
    type(child).objects.filter(pk=child.pk).update(flaw=new)
    assert stamp(old) > baseline
    assert stamp(new) > baseline
    baseline = reset_stamp(old, new)
    child.refresh_from_db()
    child.delete()
    assert stamp(old) == baseline
    assert stamp(new) > baseline


def test_affect_cvss_old_and_new_parent():
    old, new = FlawFactory.create_batch(2)
    old_affect, new_affect = AffectFactory(flaw=old), AffectFactory(flaw=new)
    baseline = reset_stamp(old, new)
    child = AffectCVSSFactory(affect=old_affect)
    assert stamp(old) > baseline
    baseline = reset_stamp(old, new)
    AffectCVSS.objects.filter(pk=child.pk).update(affect=new_affect)
    assert stamp(old) > baseline and stamp(new) > baseline
    baseline = reset_stamp(old, new)
    child.delete()
    assert stamp(new) > baseline


@pytest.mark.parametrize(
    "model,kwargs,field,value",
    [
        (AliasLabel, {}, "name", "renamed alias"),
        (BULabel, {"state": "NEW"}, "state", "DONE"),
        (CollaboratorLabel, {"state": "NEW"}, "contributor", "analyst"),
        (ProductFamilyLabel, {"relevant": True}, "relevant", False),
        (WorkflowLabel, {"reason": "initial"}, "reason", "changed"),
    ],
)
def test_concrete_label_tables(model, kwargs, field, value):
    flaw = FlawFactory()
    if model is BULabel:
        BULabelDefinition.objects.create(name="watermark label")
    if model is CollaboratorLabel:
        CollaboratorLabelDefinition.objects.create(name="watermark label")
    baseline = reset_stamp(flaw)
    label = model.objects.create(flaw=flaw, name="watermark label", **kwargs)
    assert stamp(flaw) > baseline
    baseline = reset_stamp(flaw)
    # Updating local subclass fields alone never updates the base label table.
    model.objects.filter(pk=label.pk).update(**{field: value})
    assert stamp(flaw) > baseline
    baseline = reset_stamp(flaw)
    label.delete()
    assert stamp(flaw) > baseline


def test_base_label_reassignment():
    old, new = FlawFactory.create_batch(2)
    label = WorkflowLabel.objects.create(flaw=old, name="watermark", reason="why")
    baseline = reset_stamp(old, new)
    FlawLabel.objects.filter(pk=label.pk).update(flaw=new)
    assert stamp(old) > baseline and stamp(new) > baseline


def test_tracker_all_parents_and_fk_association_changes():
    flaws = FlawFactory.create_batch(3, embargoed=False)
    stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
    affects = [
        AffectFactory(
            flaw=f,
            ps_update_stream=stream.name,
            ps_module=stream.ps_module.name,
            ps_component="shared-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        for f in flaws[:2]
    ]
    tracker = TrackerFactory(
        affects=affects,
        ps_update_stream=stream.name,
        type=Tracker.TrackerType.BUGZILLA,
        embargoed=False,
    )
    baseline = reset_stamp(*flaws)
    Tracker.objects.filter(pk=tracker.pk).update(status="new tracker status")
    assert stamp(flaws[0]) > baseline and stamp(flaws[1]) > baseline
    assert stamp(flaws[2]) == baseline
    baseline = reset_stamp(*flaws)
    # Reverse FK manager .remove/.add/.clear/.set use bulk UPDATE, not signals.
    tracker.affects.remove(affects[0])
    assert stamp(flaws[0]) > baseline
    assert stamp(flaws[1]) > baseline  # surviving parent's Tracker Affect list changed
    baseline = reset_stamp(*flaws)
    tracker.affects.add(affects[0])
    assert stamp(flaws[0]) > baseline
    assert stamp(flaws[1]) > baseline
    baseline = reset_stamp(*flaws)
    tracker.affects.clear()
    assert stamp(flaws[0]) > baseline and stamp(flaws[1]) > baseline
    tracker.affects.set(affects)
    third_affect = AffectFactory(
        flaw=flaws[2],
        ps_update_stream=stream.name,
        ps_module=stream.ps_module.name,
        ps_component="shared-component",
        affectedness=Affect.AffectAffectedness.AFFECTED,
        resolution=Affect.AffectResolution.DELEGATED,
    )
    other_tracker = TrackerFactory(
        affects=[third_affect],
        ps_update_stream=stream.name,
        type=Tracker.TrackerType.BUGZILLA,
        embargoed=False,
    )
    baseline = reset_stamp(*flaws)
    Affect.objects.filter(pk=affects[0].pk).update(tracker=other_tracker)
    assert all(stamp(flaw) > baseline for flaw in flaws)
    Affect.objects.filter(pk=affects[0].pk).update(tracker=tracker)
    baseline = reset_stamp(*flaws)
    Affect.objects.filter(pk=affects[0].pk).update(
        affectedness_explanation="local edit"
    )
    assert stamp(flaws[0]) > baseline
    assert stamp(flaws[1]) == stamp(flaws[2]) == baseline
    baseline = reset_stamp(*flaws)
    tracker.delete()  # ORM SET_NULL on associated Affects
    assert stamp(flaws[0]) > baseline and stamp(flaws[1]) > baseline


def test_bulk_children_deduplicate_parent_and_skip_unchanged_rows():
    first, untouched = FlawFactory.create_batch(2)
    children = FlawCommentFactory.build_batch(50, flaw=first)
    baseline = reset_stamp(first, untouched)
    FlawComment.objects.bulk_create(children)
    assert stamp(first) > baseline
    assert stamp(untouched) == baseline
    # Count append rows directly; trigger installation itself requires the owner.
    baseline = reset_stamp(first, untouched)
    before_count = FlawChangeEvent.objects.filter(flaw=first).count()
    FlawComment.objects.filter(flaw=first).update(text="bulk changed")
    assert stamp(first) > baseline
    assert stamp(untouched) == baseline
    assert FlawChangeEvent.objects.filter(flaw=first).count() == before_count + 1
    baseline = stamp(first)
    FlawComment.objects.filter(flaw=first).update(text="bulk changed")
    assert stamp(first) == baseline


def test_monotonic_existing_and_source_timestamps():
    flaw = FlawFactory()
    future = timezone.now() + timedelta(days=2)
    FlawChangeEvent.objects.create(flaw_id=flaw.pk, local_updated_dt=future)
    Flaw.objects.filter(pk=flaw.pk).update(title="cannot regress")
    assert stamp(flaw) == future
    source_future = future + timedelta(days=1)
    Flaw.objects.filter(pk=flaw.pk).update(local_updated_dt=source_future)
    # An excluded-only legacy write is deliberately not a business change.
    assert stamp(flaw) == future
    FlawCommentFactory(flaw=flaw)
    # Runtime events use the mutation statement clock, not copied legacy dates.
    assert stamp(flaw) == future


def test_rollback_and_scoped_intentional_migration_suppression():
    flaw = FlawFactory()
    baseline = stamp(flaw)
    with transaction.atomic():
        Flaw.objects.filter(pk=flaw.pk).update(title="rolled back")
        transaction.set_rollback(True)
    assert stamp(flaw) == baseline
    with pgtrigger.ignore("osidb.Flaw:watermark_update"):
        Flaw.objects.filter(pk=flaw.pk).update(title="intentional migration repair")
    assert stamp(flaw) == baseline
    baseline = reset_stamp(flaw)
    Flaw.objects.filter(pk=flaw.pk).update(title="normal maintenance resumes")
    assert stamp(flaw) > baseline


def test_metadata_default_and_registered_coverage():
    assert {f.name for f in tracked_fields(Flaw)} >= {
        "task_key",
        "mitre_cve_description",
        "visibility",
        "title",
        "cve_id",
        "bz_id",
    }
    assert {f.name for f in tracked_fields(WorkflowLabel)} == {
        "flawlabel_ptr",
        "reason",
    }
    registered = [
        (model, trigger)
        for model, trigger in pgtrigger.registered()
        if trigger.name.startswith("watermark_")
    ]
    assert len(registered) == 42
    assert not any(model.__name__ == "UpstreamData" for model, _ in registered)
    for model in apps.get_models():
        if issubclass(model, FlawLabel) and not model._meta.proxy:
            assert len([m for m, _ in registered if m is model]) == 3


def test_upstream_data_is_not_part_of_relevant_tree():
    flaw = FlawFactory()
    baseline = reset_stamp(flaw)
    upstream = UpstreamDataFactory(flaw=flaw)
    type(upstream).objects.filter(pk=upstream.pk).update(upstream_purls=[])
    upstream.delete()
    assert stamp(flaw) == baseline


def test_security_definer_owner_search_path_and_revoked_execution(monkeypatch):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT p.prosecdef, r.rolsuper OR r.rolbypassrls, p.proconfig,
                   has_function_privilege(current_user, p.oid, 'EXECUTE')
            FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
            WHERE p.proname LIKE 'pgtrigger_watermark_%'
        """)
        rows = cursor.fetchall()
    assert len(rows) == 42
    assert all(
        secured and bypass and not executable for secured, bypass, _, executable in rows
    )
    assert all(
        "search_path=pg_catalog, osidb_admin, public, pg_temp" in config
        for _, _, config, _ in rows
    )
    # A dependency template change must fail closed, not silently install
    # invoker functions without a pinned search path or EXECUTE revocation.
    monkeypatch.setattr(
        "pgtrigger.compiler.UpsertTriggerSql.get_template",
        lambda self: "unexpected upstream template",
    )
    model, trigger = pgtrigger.registered("osidb.Tracker:watermark_update")[0]
    with pytest.raises(RuntimeError, match="security hardening"):
        trigger.compile(model)


@pytest.mark.enable_rls
def test_hidden_flaw_shared_tracker_propagates_with_flaw_root_security():
    set_user_acls(settings.ALL_GROUPS)
    visible = FlawFactory(embargoed=False)
    hidden = FlawFactory(embargoed=True)
    stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
    visible_affect = AffectFactory(
        flaw=visible,
        embargoed=False,
        ps_update_stream=stream.name,
        ps_module=stream.ps_module.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
        resolution=Affect.AffectResolution.DELEGATED,
    )
    tracker = TrackerFactory(
        affects=[visible_affect],
        embargoed=False,
        ps_update_stream=stream.name,
        type=Tracker.TrackerType.BUGZILLA,
    )
    hidden_affect = AffectFactory(flaw=hidden, embargoed=True)
    # A raw/bulk association is a supported database write path even when it
    # bypasses application validation of shared Tracker visibility.
    Affect.objects.filter(pk=hidden_affect.pk).update(tracker=tracker)
    baseline = reset_stamp(visible, hidden)
    set_user_acls(settings.PUBLIC_READ_GROUPS + settings.PUBLIC_WRITE_GROUPS)
    assert not Flaw.objects.filter(pk=hidden.pk).exists()
    Tracker.objects.filter(pk=tracker.pk).update(status="shared tracker changed")
    assert not Flaw.objects.filter(pk=hidden.pk).exists()
    assert stamp(visible) > baseline
    set_user_acls(settings.ALL_GROUPS)
    assert stamp(hidden) > baseline


def test_trigger_functions_cannot_be_attached_to_caller_table():
    model, trigger = pgtrigger.registered("osidb.Tracker:watermark_update")[0]
    function = trigger.get_pgid(model)
    with (
        pytest.raises(ProgrammingError, match="permission denied"),
        transaction.atomic(),
    ):
        with connection.cursor() as cursor:
            cursor.execute("CREATE TEMP TABLE malicious_tracker (uuid uuid)")
            cursor.execute(f"""
                CREATE TRIGGER attack AFTER UPDATE ON malicious_tracker
                REFERENCING OLD TABLE AS watermark_old NEW TABLE AS watermark_new
                FOR EACH STATEMENT EXECUTE FUNCTION {function}()
            """)


def test_installation_rejects_unprivileged_function_owner():
    model, trigger = pgtrigger.registered("osidb.Tracker:watermark_update")[0]
    with pytest.raises(DatabaseError, match="BYPASSRLS"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(trigger.compile(model).install_sql)


@pytest.mark.django_db(transaction=True)
def test_concurrent_shared_parent_statements_are_monotonic():
    flaw = FlawFactory()
    children = FlawCommentFactory.create_batch(2, flaw=flaw)
    baseline = reset_stamp(flaw)
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('osidb.acl')")
        acl = cursor.fetchone()[0]
    locked, attempted = Event(), Event()

    def writer(index):
        other = connection.copy()
        try:
            with other.cursor() as cursor:
                cursor.execute("SELECT set_config('osidb.acl', %s, false)", [acl])
                cursor.execute("SET statement_timeout = '10s'")
            other.set_autocommit(False)
            with other.cursor() as cursor:
                if index == 1:
                    assert locked.wait(5)
                    attempted.set()
                cursor.execute(
                    "UPDATE osidb_flawcomment SET text = %s WHERE uuid = %s",
                    [f"writer {index}", children[index].pk],
                )
                cursor.execute(
                    "SELECT MAX(local_updated_dt) FROM osidb_flawchangeevent WHERE flaw_id = %s",
                    [flaw.pk],
                )
                result = cursor.fetchone()[0]
                if index == 0:
                    locked.set()
                    assert attempted.wait(5)
            other.commit()
            return result
        finally:
            other.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(writer, i) for i in range(2)]
        stamps = [f.result(timeout=15) for f in futures]
    assert baseline < stamps[0] <= stamps[1] == stamp(flaw)


@pytest.mark.parametrize("raw", [False, True])
def test_parent_deletion_never_resurrects_live_flaw(raw):
    flaw = FlawFactory()
    pk = flaw.pk
    if not raw:
        affect = AffectFactory(flaw=flaw)
        AffectCVSSFactory(affect=affect)
        FlawCommentFactory(flaw=flaw)
        WorkflowLabel.objects.create(flaw=flaw, name="cascade")
        flaw.delete()
    else:
        # A raw deletion now intentionally leaves the internal projection orphan.
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM osidb_flaw WHERE uuid = %s", [flaw.pk])
    assert FlawChangeEvent.objects.filter(flaw_id=pk).exists()
    assert not Flaw.objects.filter(pk=pk).exists()
