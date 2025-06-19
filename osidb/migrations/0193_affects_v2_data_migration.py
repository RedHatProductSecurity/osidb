from django.conf import settings
from django.db import migrations
from osidb.core import set_user_acls

BATCH_SIZE = 1000


def migrate_trackers(apps, schema_editor):
    """
    Iterate over the existing trackers, migrating them to a v2 affect with
    its corresponding ps_update_stream if it exists.
    """
    Affect = apps.get_model("osidb", "Affect")
    Tracker = apps.get_model("osidb", "Tracker")
    
    print("\nStarting tracker migration...")
    for tracker in Tracker.objects.all().prefetch_related("affects"):
        current_affects = list(tracker.affects.all())
        for affect_v1 in current_affects:
            affects_v2 = Affect.objects.filter(
                affect_v1=affect_v1, ps_update_stream=tracker.ps_update_stream
            )
            if affects_v2.exists():
                tracker.affects.add(*affects_v2)

def forwards_func(apps, schema_editor):
    """
    Generate affects v2 from affects v1, by expanding the ps_modules into the available
    ps_update_streams.
    """
    set_user_acls(settings.ALL_GROUPS)

    Affect = apps.get_model("osidb", "Affect")
    PsModule = apps.get_model("osidb", "PsModule")

    v1_affects_processed = 0
    v2_affects_created_total = 0
    v2_affects_skipped_total = 0

    create_batch = []

    affects_v1 = Affect.objects.all()
    for affect in affects_v1:
        v1_affects_processed += 1

        try:
            ps_module = PsModule.objects.get(name=affect.ps_module)
        except PsModule.DoesNotExist:
            print(
                f"[Warning] Affect {affect.uuid} has no existing PsModule '{affect.ps_module}'."
            )
            continue

        ps_update_streams = ps_module.ps_update_streams.all()
        trackers = affect.trackers.all()
        if trackers.exists():
            # If trackers exist, only create those for existing trackers, otherwise expand to all streams
            ps_update_streams = ps_module.ps_update_streams.filter(
                name__in=trackers.values_list("ps_update_stream", flat=True)
            )

        v2_skipped_iter = 0
        for ps_update_stream in ps_update_streams:
            # Check if it already exists
            if Affect.objects.filter(
                flaw=affect.flaw,
                ps_update_stream=ps_update_stream.name,
                ps_component=affect.ps_component,
            ).exists():
                v2_skipped_iter += 1
                continue

            try:
                # Create a new affect v2 for each stream, linking back to the original v1 affect
                affect_v2 = Affect(
                    affect_v1=affect,
                    flaw=affect.flaw,
                    ps_update_stream=ps_update_stream.name,
                    ps_module=ps_module.name,
                    ps_component=affect.ps_component,
                    affectedness=affect.affectedness,
                    resolution=affect.resolution,
                    purl=affect.purl,
                    impact=affect.impact,
                    not_affected_justification=affect.not_affected_justification,
                    resolved_dt=affect.resolved_dt,
                    meta_attr=affect.meta_attr or {},
                    created_dt=affect.created_dt,
                    updated_dt=affect.updated_dt,
                    acl_read=affect.acl_read,
                    acl_write=affect.acl_write,
                )
                create_batch.append(affect_v2)
            except Exception as e:
                print(
                    f"[ERROR] creating AffectV2 for Affect {affect.uuid}, Stream {ps_update_stream.name}: {e}"
                )
                v2_skipped_iter += 1

            if len(create_batch) >= BATCH_SIZE:
                Affect.objects.bulk_create(create_batch)
                v2_affects_created_total += len(create_batch)
                v2_affects_skipped_total += v2_skipped_iter
                create_batch.clear()
                print(
                    f"Processed {v1_affects_processed} affects. Total V2 created: {v2_affects_created_total}, Total skipped: {v2_affects_skipped_total}"
                )

    # Create/update any remaining affects in the batch
    if create_batch:
        Affect.objects.bulk_create(create_batch)
        v2_affects_created_total += len(create_batch)
        create_batch.clear()

    print(f"Affects Processed: {v1_affects_processed}")
    print(f"Total V2 Affects Created: {v2_affects_created_total}")
    print(
        f"Total V2 Affects Skipped (already existed or error): {v2_affects_skipped_total}"
    )

    migrate_trackers(apps, schema_editor)


def backwards_func(apps, schema_editor):
    # Get affects v2 that come from a v1 affect and delete all but the first one
    Affect = apps.get_model("osidb", "Affect")
    deleted_count, _ = Affect.objects.filter(affect_v1__isnull=False).delete()
    print(f"Deleted {deleted_count} Affect V2 objects that were linked to a v1 affect.")


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0192_affects_v2"),
    ]

    operations = [
        migrations.RunPython(forwards_func, reverse_code=backwards_func),
    ]
