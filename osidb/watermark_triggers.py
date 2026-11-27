"""Statement-level maintenance of the Flaw change projection.

Only these trigger entry points are privileged: there is deliberately no callable
function accepting arbitrary Flaw IDs. SQL is compiled into pgtrigger migrations.
"""

# SQL is built exclusively from fixed templates and quoted Django metadata, not
# request values. SQL-generation (rather than cursor execution) is intentional.
# ruff: noqa: S608

import pgtrigger
from pgtrigger import compiler


class WatermarkTriggerSqlV1(compiler.UpsertTriggerSql):
    """Versioned migration SQL: keep this template stable for historical replay."""

    def get_template(self):
        template = super().get_template()
        marker = "$$ LANGUAGE plpgsql;\n\n            DROP TRIGGER"
        if template.count(marker) != 1:
            raise RuntimeError(
                "Unsupported pgtrigger template: cannot apply watermark security hardening"
            )
        return template.replace(
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


def excluded_fields(model):
    """Combine bookkeeping declarations from the model and its owning mixins."""
    return frozenset(
        field
        for base in model.__mro__
        for field in base.__dict__.get("flaw_change_exclude", ())
    )


def tracked_fields(model, *, exclude=()):
    """Columns physically present on this table, including subclass-only fields."""
    excluded = excluded_fields(model) | set(exclude)
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
        # Reapplying the decorator must not register a second object for the URI.
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


def track_flaw_changes(*, parent="flaw", exclude=()):
    """Opt a concrete source table into statement-level Flaw change tracking.

    New business fields participate by default, including generated visibility.
    Each multi-table child opts in separately because it owns a separate table.
    Bookkeeping exclusions belong on the model or the mixin owning those fields.
    """

    def decorate(model):
        model.flaw_change_exclude = (
            *model.__dict__.get("flaw_change_exclude", ()),
            *exclude,
        )
        register_watermark_triggers(model, parent=parent)
        return model

    return decorate
