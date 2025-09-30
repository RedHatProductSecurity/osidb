from django.conf import settings
from django.db import migrations
from osidb.core import set_user_acls
from osidb.helpers import bypass_rls

BATCH_SIZE = 1000


def migrate_trackers(apps):
    """
    Iterate over the existing trackers, moving them to the corresponding v2 affect.
    """
    Affect = apps.get_model("osidb", "Affect")
    Tracker = apps.get_model("osidb", "Tracker")

    for tracker in Tracker.objects.all().prefetch_related("affects"):
        current_affects = list(tracker.affects.all())
        for affect in current_affects:
            if tracker.ps_update_stream != affect.ps_update_stream:
                try:
                    affect_v2 = Affect.objects.get(
                        flaw=affect.flaw,
                        ps_component=affect.ps_component,
                        ps_update_stream=tracker.ps_update_stream,
                    )
                    tracker.affects.remove(affect)
                    tracker.affects.add(affect_v2)
                except Affect.DoesNotExist:
                    continue


def migrate_cvss_scores(apps, new_affects_with_cvss):
    """
    Copy the CVSS scores of the v1 affect to the v2 affects.
    """
    Affect = apps.get_model("osidb", "Affect")
    AffectCVSS = apps.get_model("osidb", "AffectCVSS")

    cvss_create_batch = []
    for item in new_affects_with_cvss:
        affect = item["affect"]
        for cvss in item["cvss_scores"]:
            cvss_copy = AffectCVSS(
                affect=affect,
                issuer=cvss.issuer,
                score=cvss.score,
                vector=cvss.vector,
                version=cvss.version,
                comment=cvss.comment,
                created_dt=cvss.created_dt,
                updated_dt=cvss.updated_dt,
                acl_read=cvss.acl_read,
                acl_write=cvss.acl_write,
            )
            cvss_create_batch.append(cvss_copy)

        if len(cvss_create_batch) >= BATCH_SIZE:
            AffectCVSS.objects.bulk_create(cvss_create_batch)
            cvss_create_batch.clear()

    if cvss_create_batch:
        AffectCVSS.objects.bulk_create(cvss_create_batch)


@bypass_rls
def forwards_func(apps, schema_editor):
    """
    Generate affects v2 from affects v1, by expanding the ps_modules into the available
    ps_update_streams.
    """
    Affect = apps.get_model("osidb", "Affect")
    PsModule = apps.get_model("osidb", "PsModule")

    v1_affects_processed = 0
    v2_affects_created_total = 0
    v2_affects_skipped_total = 0

    update_batch = []
    create_batch = []
    new_affects_with_cvss = []

    affects_v1 = Affect.objects.all().prefetch_related("cvss_scores", "trackers")
    for affect in affects_v1:
        v1_affects_processed += 1

        try:
            ps_module = PsModule.objects.get(name=affect.ps_module)
        except PsModule.DoesNotExist:
            print(
                f"[Warning] Affect {affect.uuid} has no existing PsModule '{affect.ps_module}'."
            )
            continue

        # If trackers exist, only expand affects for the streams associated to those for existing
        # trackers, otherwise expand to all active streams
        ps_update_streams = ps_module.active_ps_update_streams.all()
        trackers = affect.trackers.all()
        if trackers.exists():
            ps_update_streams = ps_module.ps_update_streams.filter(
                name__in=trackers.values_list("ps_update_stream", flat=True)
            )

        cvss_scores = list(affect.cvss_scores.all())

        v2_skipped_iter = 0
        first = True
        for ps_update_stream in ps_update_streams:
            # Skip it if it already exists
            if Affect.objects.filter(
                flaw=affect.flaw,
                ps_update_stream=ps_update_stream.name,
                ps_component=affect.ps_component,
            ).exists():
                continue

            if first:
                # Reuse the existing affect for the first stream
                first = False
                affect.ps_update_stream = ps_update_stream.name
                update_batch.append(affect)
            else:
                try:
                    affect_v2 = Affect(
                        flaw=affect.flaw,
                        ps_update_stream=ps_update_stream.name,
                        ps_module=ps_module.name,
                        cve_id=affect.cve_id,
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
                    # If the original affect had CVSS scores, store a reference
                    # so we can copy them later
                    if cvss_scores:
                        new_affects_with_cvss.append(
                            {"affect": affect_v2, "cvss_scores": cvss_scores}
                        )
                except Exception as e:
                    print(
                        f"[ERROR] creating AffectV2 for Affect {affect.uuid}, Stream {ps_update_stream.name}: {e}"
                    )
                    v2_skipped_iter += 1

            if len(update_batch) >= BATCH_SIZE:
                Affect.objects.bulk_update(update_batch, ["ps_update_stream"])
                v2_affects_created_total += len(update_batch)
                update_batch.clear()
            if len(create_batch) >= BATCH_SIZE:
                Affect.objects.bulk_create(create_batch)

                migrate_cvss_scores(apps, new_affects_with_cvss)
                new_affects_with_cvss.clear()

                v2_affects_created_total += len(create_batch)
                v2_affects_skipped_total += v2_skipped_iter
                create_batch.clear()
                print(
                    f"Processed {v1_affects_processed} affects. Total V2 created: {v2_affects_created_total}, Total skipped: {v2_affects_skipped_total}"
                )

    # Create/update any remaining affects in the batch
    if update_batch:
        Affect.objects.bulk_update(update_batch, ["ps_update_stream"])
        v2_affects_created_total += len(update_batch)
        update_batch.clear()
    if create_batch:
        Affect.objects.bulk_create(create_batch)
        migrate_cvss_scores(apps, new_affects_with_cvss)
        v2_affects_created_total += len(create_batch)
        create_batch.clear()

    print(f"Affects processed: {v1_affects_processed}")
    print(f"Total V2 Affects created: {v2_affects_created_total}")
    print(f"Total V2 Affects skipped due to error: {v2_affects_skipped_total}")

    migrate_trackers(apps)


@bypass_rls
def backwards_func(apps, schema_editor):
    # Group affects by the old identifiers: flaw, ps_module and ps_component
    v1_affect_groups = Affect.objects.values(
        "flaw_id", "ps_module", "ps_component"
    ).distinct()

    for group in v1_affect_groups:
        if not group["flaw_id"] or not group["ps_module"] or not group["ps_component"]:
            continue

        # Get the first affect in the group and keep only that one
        v2_affects_in_group = Affect.objects.filter(**group)
        if not v2_affects_in_group.exists():
            continue

        v1_affect = v2_affects_in_group.first()
        redundant_affects = v2_affects_in_group.exclude(pk=v1_affect.pk)
        for affect in redundant_affects:
            for tracker in affect.trackers:
                tracker.affects.add(v1_affect)

        if redundant_affects.exists():
            redundant_affects.delete()


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0199_affects_v2_fields"),
    ]

    operations = [
        migrations.RunPython(forwards_func, backwards_func),
    ]
