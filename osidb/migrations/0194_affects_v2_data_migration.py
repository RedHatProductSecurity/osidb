import django.contrib.postgres.fields
from django.conf import settings
from django.db import migrations, models
from django.utils import timezone
from osidb.core import set_user_acls
import psqlextra.fields.hstore_field

BATCH_SIZE = 1000


def migrate_trackers(apps):
    """
    Iterate over the existing trackers, moving them to the corresponding v2 affect.
    """
    Affect = apps.get_model("osidb", "Affect")
    Tracker = apps.get_model("osidb", "Tracker")

    print("\nStarting tracker migration...")
    for tracker in Tracker.objects.all().prefetch_related("affects"):
        current_affects = list(tracker.affects.all())
        for affect in current_affects:
            if tracker.ps_update_stream != affect.ps_update_stream:
                affect_v2 = Affect.objects.filter(
                    flaw=affect.flaw,
                    ps_component=affect.ps_component,
                    ps_update_stream=tracker.ps_update_stream,
                ).first()
                if affect_v2:
                    tracker.affects.add(affect_v2)
                    tracker.affects.remove(affect)


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

    update_batch = []
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

        # If trackers exist, only expand affects for the streams associated to those for existing
        # trackers, otherwise expand to all active streams
        ps_update_streams = ps_module.active_ps_update_streams.all()
        trackers = affect.trackers.all()
        if trackers.exists():
            ps_update_streams = ps_module.ps_update_streams.filter(
                name__in=trackers.values_list("ps_update_stream", flat=True)
            )

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

            if len(update_batch) >= BATCH_SIZE:
                Affect.objects.bulk_update(update_batch, ["ps_update_stream"])
                v2_affects_created_total += len(update_batch)
                update_batch.clear()
            if len(create_batch) >= BATCH_SIZE:
                Affect.objects.bulk_create(create_batch)
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
        v2_affects_created_total += len(create_batch)
        create_batch.clear()

    print(f"Affects processed: {v1_affects_processed}")
    print(f"Total V2 Affects created: {v2_affects_created_total}")
    print(f"Total V2 Affects skipped due to error: {v2_affects_skipped_total}")

    migrate_trackers(apps)


CREATE_AFFECT_V1_VIEW = """
CREATE OR REPLACE VIEW affect_v1 AS
-- For all v2 affects, a candidate will be chosen to represent the v1 affect
WITH ranked_affects AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY flaw_id, ps_module
            ORDER BY
                -- Affected affects take priority
                CASE WHEN affectedness = 'NOTAFFECTED' THEN 2 ELSE 1 END,
                -- Higher impact affects take priority
                CASE impact
                    WHEN 'CRITICAL'  THEN 4
                    WHEN 'IMPORTANT' THEN 3
                    WHEN 'MODERATE'  THEN 2
                    WHEN 'LOW'       THEN 1
                    ELSE 0
                END DESC,
                -- If there's still a tie, take the most recent affect
                created_dt DESC,
                uuid DESC
        ) AS rn
    FROM
        osidb_affect
),
-- Group all trackers from v2 affects into the v1 affect
grouped_trackers AS (
    SELECT
        a.flaw_id,
        a.ps_module,
        array_agg(DISTINCT at.tracker_id) AS all_tracker_ids
    FROM
        osidb_affect a
    LEFT JOIN
        osidb_tracker_affects at ON a.uuid = at.affect_id
    GROUP BY
        a.flaw_id, a.ps_module
),
-- Group all cvss scores from v2 affects into the v1 affect
affect_cvss_ids AS (
    SELECT
        affect_id,
        array_agg(uuid) AS all_cvss_score_ids
    FROM
        osidb_affectcvss
    GROUP BY
        affect_id
)
-- Select the highest-ranked affect (rn = 1) and join with aggregated trackers
SELECT
    ra.uuid,
    ra.flaw_id,
    ra.affectedness,
    ra.resolution,
    ra.ps_module,
    ra.ps_update_stream,
    ra.ps_component,
    ra.impact,
    ra.purl,
    ra.not_affected_justification,
    ra.resolved_dt,
    ra.meta_attr,
    ra.created_dt,
    ra.updated_dt,
    ra.acl_read,
    ra.acl_write,
    ra.last_validated_dt,
    gt.all_tracker_ids,
    aci.all_cvss_score_ids
FROM
    ranked_affects ra
JOIN
    grouped_trackers gt ON ra.flaw_id = gt.flaw_id AND ra.ps_module = gt.ps_module
LEFT JOIN
    affect_cvss_ids aci ON ra.uuid = aci.affect_id
WHERE
    ra.rn = 1;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0193_affects_v2_fields"),
    ]

    operations = [
        # Generate affects v2 from current v1 data
        migrations.RunPython(forwards_func),
        # Create view for affects v1
        migrations.CreateModel(
            name='AffectV1',
            fields=[
                ('uuid', models.UUIDField(editable=False, primary_key=True, serialize=False)),
                ('affectedness', models.CharField(max_length=100)),
                ('resolution', models.CharField(max_length=100)),
                ('ps_module', models.CharField(max_length=100)),
                ('ps_component', models.CharField(max_length=255)),
                ('purl', models.TextField(blank=True)),
                ('impact', models.CharField(blank=True, max_length=20)),
                ('not_affected_justification', models.CharField(blank=True, max_length=100)),
                ('resolved_dt', models.DateTimeField(blank=True, null=True)),
                ('meta_attr', psqlextra.fields.hstore_field.HStoreField(default=dict)),
                ('created_dt', models.DateTimeField()),
                ('updated_dt', models.DateTimeField()),
                ('acl_read', django.contrib.postgres.fields.ArrayField(base_field=models.UUIDField(), default=list, size=None)),
                ('acl_write', django.contrib.postgres.fields.ArrayField(base_field=models.UUIDField(), default=list, size=None)),
                ('last_validated_dt', models.DateTimeField(blank=True, default=timezone.now)),
                ('all_tracker_ids', django.contrib.postgres.fields.ArrayField(base_field=models.UUIDField(), blank=True, null=True, size=None)),
                ('all_cvss_score_ids', django.contrib.postgres.fields.ArrayField(base_field=models.UUIDField(), blank=True, null=True, size=None)),
            ],
            options={
                'verbose_name': 'Affect V1',
                'db_table': 'affect_v1',
                'ordering': ['created_dt', 'uuid'],
                'managed': False,
            },
        ),
        migrations.RunSQL(CREATE_AFFECT_V1_VIEW),
    ]
