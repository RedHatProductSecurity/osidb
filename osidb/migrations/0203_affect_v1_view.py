import django.contrib.postgres.fields
from django.db import migrations, models
from django.utils import timezone
import osidb.models.fields
import psqlextra.fields.hstore_field


CREATE_AFFECT_V1_VIEW = """
CREATE OR REPLACE VIEW affect_v1 AS
-- For all v2 affects, a candidate will be chosen to represent the v1 affect
WITH ranked_affects AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY flaw_id, ps_module, ps_component
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
        flaw_id,
        ps_module,
        array_agg(DISTINCT tracker_id) AS all_tracker_ids
    FROM
        osidb_affect
    WHERE
        tracker_id IS NOT NULL
    GROUP BY
        flaw_id, ps_module
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
    ra.cve_id,
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
LEFT JOIN
    grouped_trackers gt ON ra.flaw_id = gt.flaw_id AND ra.ps_module = gt.ps_module
LEFT JOIN
    affect_cvss_ids aci ON ra.uuid = aci.affect_id
WHERE
    ra.rn = 1;
"""


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0202_affect_tracker_data_migration'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tracker',
            name='affects',
        ),
        migrations.AlterField(
            model_name='affect',
            name='tracker',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='affects', to='osidb.tracker'),
        ),
        migrations.CreateModel(
            name='AffectV1',
            fields=[
                ('uuid', models.UUIDField(editable=False, primary_key=True, serialize=False)),
                ('cve_id', osidb.models.fields.CVEIDField(blank=True, null=True, unique=False)),
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
