from django.db import migrations


CREATE_AFFECT_V1_MATERIALIZED_VIEW = """
-- affect_v1 used to be the materialized view itself, but Postgres does not
-- support row level security on materialized views (relkind 'm'), so it can
-- neither inherit RLS from osidb_affect nor define its own policies. The
-- data now lives in affect_v1_mv, and affect_v1 is a thin plain view on top
-- of it reproducing the same acl_read predicate used by the RLS SELECT
-- policies on other ACL-protected tables (see 0246_enable_rls_on_child_acl_tables).
-- affect_v1 is still the old-style materialized view here (from 0214);
-- drop that, not a plain view.
DROP MATERIALIZED VIEW IF EXISTS affect_v1;
DROP MATERIALIZED VIEW IF EXISTS affect_v1_mv;
CREATE MATERIALIZED VIEW affect_v1_mv AS
-- For all v2 affects, a candidate will be chosen to represent the v1 affect
WITH ranked_affects AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY flaw_id, ps_module, ps_component
            ORDER BY
                -- Affects with a PURL that has a subpath (which start with #) take priority
                CASE WHEN purl LIKE '%#%' THEN 1 ELSE 2 END,
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
        ps_component,
        array_agg(DISTINCT tracker_id) AS all_tracker_ids
    FROM
        osidb_affect
    WHERE
        tracker_id IS NOT NULL
    GROUP BY
        flaw_id, ps_module, ps_component
),
-- Group all cvss scores from v2 affects into the v1 affect
affect_cvss_ids AS (
    SELECT
        a.flaw_id,
        a.ps_module,
        a.ps_component,
        array_agg(ac.uuid) AS all_cvss_score_ids
    FROM
        osidb_affectcvss ac
    JOIN
        osidb_affect a ON ac.affect_id = a.uuid
    GROUP BY
        a.flaw_id, a.ps_module, a.ps_component
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
    ra.embargoed,
    ra.last_validated_dt,
    gt.all_tracker_ids,
    aci.all_cvss_score_ids
FROM
    ranked_affects ra
LEFT JOIN
    grouped_trackers gt
        ON ra.flaw_id = gt.flaw_id
        AND ra.ps_module = gt.ps_module
        AND ra.ps_component = gt.ps_component
LEFT JOIN
    affect_cvss_ids aci
        ON ra.flaw_id = aci.flaw_id
        AND ra.ps_module IS NOT DISTINCT FROM aci.ps_module
        AND ra.ps_component IS NOT DISTINCT FROM aci.ps_component
WHERE
    ra.rn = 1;
-- Unique index for the concurrent refresh to work
CREATE UNIQUE INDEX affect_v1_uuid_idx ON affect_v1_mv (uuid);
CREATE INDEX IF NOT EXISTS affect_v1_all_tracker_ids_gin_idx ON affect_v1_mv USING GIN (all_tracker_ids);
CREATE INDEX IF NOT EXISTS affect_v1_flaw_id_idx ON affect_v1_mv (flaw_id);
CREATE INDEX IF NOT EXISTS affect_v1_sorting_idx ON affect_v1_mv (created_dt, uuid);
CREATE VIEW affect_v1 AS
SELECT * FROM affect_v1_mv
WHERE acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[];
"""

RESTORE_PRIOR_AFFECT_V1_MATERIALIZED_VIEW = """
DROP VIEW IF EXISTS affect_v1;
DROP MATERIALIZED VIEW IF EXISTS affect_v1_mv;
CREATE MATERIALIZED VIEW affect_v1 AS
WITH ranked_affects AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY flaw_id, ps_module, ps_component
            ORDER BY
                CASE WHEN purl LIKE '%#%%' THEN 1 ELSE 2 END,
                CASE WHEN affectedness = 'NOTAFFECTED' THEN 2 ELSE 1 END,
                CASE impact
                    WHEN 'CRITICAL'  THEN 4
                    WHEN 'IMPORTANT' THEN 3
                    WHEN 'MODERATE'  THEN 2
                    WHEN 'LOW'       THEN 1
                    ELSE 0
                END DESC,
                created_dt DESC,
                uuid DESC
        ) AS rn
    FROM
        osidb_affect
),
grouped_trackers AS (
    SELECT
        flaw_id, ps_module, ps_component,
        array_agg(DISTINCT tracker_id) AS all_tracker_ids
    FROM osidb_affect
    WHERE tracker_id IS NOT NULL
    GROUP BY flaw_id, ps_module, ps_component
),
affect_cvss_ids AS (
    SELECT
        affect_id,
        array_agg(uuid) AS all_cvss_score_ids
    FROM osidb_affectcvss
    GROUP BY affect_id
)
SELECT
    ra.uuid, ra.flaw_id, ra.affectedness, ra.resolution,
    ra.ps_module, ra.cve_id, ra.ps_update_stream, ra.ps_component,
    ra.impact, ra.purl, ra.not_affected_justification, ra.resolved_dt,
    ra.meta_attr, ra.created_dt, ra.updated_dt,
    ra.acl_read, ra.acl_write,
    ra.last_validated_dt,
    gt.all_tracker_ids,
    aci.all_cvss_score_ids
FROM ranked_affects ra
LEFT JOIN grouped_trackers gt
    ON ra.flaw_id = gt.flaw_id
    AND ra.ps_module = gt.ps_module
    AND ra.ps_component = gt.ps_component
LEFT JOIN affect_cvss_ids aci ON ra.uuid = aci.affect_id
WHERE ra.rn = 1;
CREATE UNIQUE INDEX affect_v1_uuid_idx ON affect_v1 (uuid);
"""


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0262_replace_acl_annotations_with_generated_fields"),
    ]

    operations = [
        migrations.RunSQL(
            sql=CREATE_AFFECT_V1_MATERIALIZED_VIEW,
            reverse_sql=RESTORE_PRIOR_AFFECT_V1_MATERIALIZED_VIEW,
        ),
    ]
