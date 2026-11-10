"""Statement-level maintenance of the Flaw change projection.

Only these trigger entry points are privileged: there is deliberately no callable
function accepting arbitrary Flaw IDs. SQL is compiled into pgtrigger migrations.
"""

# SQL is built exclusively from fixed templates and quoted Django metadata, not
# request values. SQL-generation (rather than cursor execution) is intentional.
# ruff: noqa: S608

import pgtrigger
from pgtrigger import compiler

# Explicit exclusions, not an allowlist: new concrete business fields participate
# automatically. Do not exclude all GeneratedFields (visibility is meaningful),
# all *_dt fields (reported/unembargo dates are meaningful), or all JSON fields.
EXCLUDED_FIELDS = frozenset(
    {
        "acl_read",
        "acl_write",
        "embargoed",
        "created_dt",
        "updated_dt",
        "local_updated_dt",
        "last_validated_dt",
        "last_impact_increase_dt",
        "task_updated_dt",
        "resolved_dt",
        "meta_attr",
        "aegis_meta",
        "assist_meta",
        "classification_meta",
        "search_vector",
    }
)


class WatermarkTriggerSqlV1(compiler.UpsertTriggerSql):
    """Versioned migration SQL: keep this template stable for historical replay."""

    def get_template(self):
        template = super().get_template()
        marker = "$$ LANGUAGE plpgsql;\n\n            DROP TRIGGER"
        if template.count(marker) != 1:
            raise RuntimeError(
                "Unsupported pgtrigger template: cannot apply watermark security hardening"
            )
        # Unlike the generic ignore helper, the trigger itself needs to resolve
        # hidden parents. Installation must use the trusted BYPASSRLS migration
        # role, never the runtime role. FORCE RLS would otherwise silently omit
        # hidden Flaws even with SECURITY DEFINER.
        return """
            DO $owner$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = current_user AND (rolsuper OR rolbypassrls)
                ) THEN
                    RAISE EXCEPTION 'Watermark triggers require a BYPASSRLS migration owner';
                END IF;
            END;
            $owner$;
        """ + template.replace(
            marker,
            """$$ LANGUAGE plpgsql SECURITY DEFINER
                SET search_path = pg_catalog, osidb_admin, public, pg_temp;
            ALTER FUNCTION {pgid}() OWNER TO CURRENT_USER;
            REVOKE ALL ON FUNCTION {pgid}() FROM PUBLIC;

            DROP TRIGGER""",
        )


class WatermarkTrigger(pgtrigger.Trigger):
    def compile(self, model):
        compiled = super().compile(model)
        return compiler.Trigger(
            name=self.name,
            sql=WatermarkTriggerSqlV1(**compiled.sql.kwargs),
        )


def tracked_fields(model, *, exclude=()):
    """Columns physically present on this table, including subclass-only fields."""
    excluded = EXCLUDED_FIELDS | set(exclude)
    return sorted(
        (f for f in model._meta.local_concrete_fields if f.name not in excluded),
        key=lambda f: f.column,
    )


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def _changed_rows(model, operation, exclude):
    if operation == pgtrigger.Insert:
        return "SELECT n.* FROM watermark_new n"
    if operation == pgtrigger.Delete:
        return "SELECT o.* FROM watermark_old o"
    pk = _quote(model._meta.pk.column)
    changed = (
        " OR ".join(
            f"o.{_quote(f.column)} IS DISTINCT FROM n.{_quote(f.column)}"
            for f in tracked_fields(model, exclude=exclude)
        )
        or "FALSE"
    )
    # FULL JOIN also handles raw PK changes; normally IDs are immutable. Preserve
    # both sides of reassignment, not just the child's current parent.
    predicate = f"o.{pk} IS NULL OR n.{pk} IS NULL OR ({changed})"
    return f"""
        SELECT o.* FROM watermark_old o
        FULL JOIN watermark_new n ON o.{pk} = n.{pk}
        WHERE o.{pk} IS NOT NULL AND ({predicate})
        UNION ALL
        SELECT n.* FROM watermark_old o
        FULL JOIN watermark_new n ON o.{pk} = n.{pk}
        WHERE n.{pk} IS NOT NULL AND ({predicate})
    """


def register_watermark_triggers(model, *, parent="flaw", exclude=()):
    """Register independent INSERT/UPDATE/DELETE transition-table triggers.

    ``exclude`` adds explicit model-specific exclusions. ``parent`` describes the
    physical relationship, not a list of business columns. Multi-table children
    must register separately; inherited columns live on the parent's table.
    """
    pk = _quote(model._meta.pk.column)
    parents = {
        "self": f"SELECT c.{pk} AS flaw_id FROM changed c",
        "flaw": "SELECT c.flaw_id FROM changed c",
        "affect_owner": """SELECT c.flaw_id FROM changed c
            UNION ALL SELECT a.flaw_id FROM osidb_affect a
            JOIN links ON links.tracker_id = a.tracker_id""",
        "affect": """SELECT a.flaw_id FROM changed c
                     JOIN osidb_affect a ON a.uuid = c.affect_id""",
        "tracker": f"""SELECT a.flaw_id FROM changed c
                      JOIN osidb_affect a ON a.tracker_id = c.{pk}""",
        "label": f"""SELECT l.flaw_id FROM changed c
                    JOIN osidb_flawlabelv2 l ON l.uuid = c.{pk}""",
    }
    parent_sql = parents[parent]
    for operation in (pgtrigger.Insert, pgtrigger.Update, pgtrigger.Delete):
        suffix = str(operation).lower()
        # Django may populate an isolated app registry more than once in tests.
        # Re-running ready() must not register a second object for the same URI.
        if any(
            registered_model is model and trigger.name == f"watermark_{suffix}"
            for registered_model, trigger in pgtrigger.registered()
        ):
            continue
        link_cte = ""
        if parent == "affect_owner":
            # Affect is the physical Flaw/Tracker association in this schema.
            # Tracker serialization includes its Affect list, so link changes
            # also affect surviving sibling parents of the old/new Trackers.
            # This is relationship resolution, not a business-field allowlist.
            links = "SELECT c.tracker_id FROM changed c"
            if operation == pgtrigger.Update:
                link_changed = f"""o.{pk} IS NULL OR n.{pk} IS NULL
                    OR o.tracker_id IS DISTINCT FROM n.tracker_id
                    OR o.flaw_id IS DISTINCT FROM n.flaw_id"""
                links = f"""
                    SELECT o.tracker_id FROM watermark_old o
                    FULL JOIN watermark_new n ON o.{pk} = n.{pk}
                    WHERE {link_changed}
                    UNION
                    SELECT n.tracker_id FROM watermark_old o
                    FULL JOIN watermark_new n ON o.{pk} = n.{pk}
                    WHERE {link_changed}
                """
            link_cte = f", links AS ({links})"
        # Source mutations have already passed their own RLS. Validate the
        # attachment as defense in depth; the function cannot be repurposed on a
        # caller-controlled table, and PUBLIC cannot CREATE TRIGGER using it.
        guard = f"""
            IF TG_RELID != '{_quote(model._meta.db_table)}'::regclass
               OR TG_LEVEL != 'STATEMENT' OR TG_OP != '{operation}' THEN
                RAISE EXCEPTION 'Invalid watermark trigger attachment';
            END IF;
        """
        # One new row per distinct live parent per statement. No per-parent
        # latest row, FK check, preliminary lock, CVE copy or transaction queue.
        write = """
            INSERT INTO osidb_flawchangeevent (flaw_id, local_updated_dt)
            SELECT f.uuid, statement_timestamp()
            FROM osidb_flaw f JOIN parents p ON p.flaw_id = f.uuid
            ORDER BY f.uuid;
        """
        WatermarkTrigger(
            name=f"watermark_{suffix}",
            when=pgtrigger.After,
            level=pgtrigger.Statement,
            operation=operation,
            referencing=pgtrigger.Referencing(
                old="watermark_old" if operation != pgtrigger.Insert else None,
                new="watermark_new" if operation != pgtrigger.Delete else None,
            ),
            func=guard
            + f"""
                WITH changed AS ({_changed_rows(model, operation, exclude)}){link_cte},
                parents AS (SELECT DISTINCT flaw_id FROM ({parent_sql}) candidates)
                {write}
                RETURN NULL;
            """,
        ).register(model)


def register_all_watermark_triggers():
    from osidb import models

    register_watermark_triggers(models.Flaw, parent="self")
    register_watermark_triggers(models.Affect, parent="affect_owner")
    for model in (
        models.FlawComment,
        models.FlawReference,
        models.FlawAcknowledgment,
        models.FlawCVSS,
        models.FlawLabel,
    ):
        register_watermark_triggers(model)
    register_watermark_triggers(models.AffectCVSS, parent="affect")
    register_watermark_triggers(models.Tracker, parent="tracker")
    # Discover concrete descendants, including future label types. Skip proxies
    # and abstract models so no physical table gets duplicate maintenance.
    from django.apps import apps

    for model in apps.get_models():
        if (
            model is not models.FlawLabel
            and issubclass(model, models.FlawLabel)
            and not model._meta.proxy
        ):
            register_watermark_triggers(model, parent="label")
