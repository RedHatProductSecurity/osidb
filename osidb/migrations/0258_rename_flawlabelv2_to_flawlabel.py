"""
Remove V1 label models (FlawLabel, FlawCollaborator) and rename
FlawLabelV2 to FlawLabel as the canonical label model.

Uses a custom state-only rename that avoids Django's model re-rendering
crash when RenameModel is used on polymorphic multi-table inheritance
hierarchies.
"""

import django.db.models.deletion
from django.db import migrations, models


class RenameModelStateOnly(migrations.operations.base.Operation):
    """
    Rename a model in Django's migration state without triggering
    model class re-rendering. This avoids FieldError crashes that occur
    when RenameModel re-renders polymorphic MTI subclasses mid-rename.

    Must be paired with db_table on the model to preserve the physical
    table name (no database_forwards needed).
    """

    reduces_to_sql = False
    reversible = True

    def __init__(self, old_name, new_name, db_table=None):
        self.old_name = old_name
        self.new_name = new_name
        self.db_table = db_table

    def state_forwards(self, app_label, state):
        old_key = (app_label, self.old_name.lower())
        new_key = (app_label, self.new_name.lower())
        old_ref = f"{app_label}.{self.old_name.lower()}"
        new_ref = f"{app_label}.{self.new_name}"

        model_state = state.models.pop(old_key)
        model_state.name = self.new_name
        if self.db_table:
            model_state.options["db_table"] = self.db_table
        state.models[new_key] = model_state

        for ms in state.models.values():
            ms.bases = tuple(
                new_ref
                if isinstance(b, str) and b.lower() == old_ref
                else b
                for b in ms.bases
            )
            for field in ms.fields.values():
                remote = getattr(field, "remote_field", None)
                if remote is None:
                    continue
                ref = getattr(remote, "model", None)
                if isinstance(ref, str) and ref.lower() == old_ref:
                    remote.model = new_ref
                through = getattr(remote, "through", None)
                if isinstance(through, str) and through.lower() == old_ref:
                    remote.through = new_ref

        # Re-key _relations so later operations see the new model key.
        if state._relations is not None:
            if old_key in state._relations:
                state._relations[new_key] = state._relations.pop(old_key)
            for model_relations in state._relations.values():
                if old_key in model_relations:
                    model_relations[new_key] = model_relations.pop(old_key)

        # Invalidate the cached apps registry so the next access rebuilds
        # it from the (now-consistent) state dict.
        state.__dict__.pop("apps", None)

    def state_backwards(self, app_label, state):
        self.new_name, self.old_name = self.old_name, self.new_name
        self.state_forwards(app_label, state)
        self.new_name, self.old_name = self.old_name, self.new_name

    def database_forwards(self, *args, **kwargs):
        pass

    def database_backwards(self, *args, **kwargs):
        pass

    def describe(self):
        return f"Rename model {self.old_name} to {self.new_name} (state only)"

    @property
    def migration_name_fragment(self):
        return f"rename_{self.old_name.lower()}_to_{self.new_name.lower()}"

    def deconstruct(self):
        return (
            self.__class__.__qualname__,
            [],
            {
                "old_name": self.old_name,
                "new_name": self.new_name,
                "db_table": self.db_table,
            },
        )

    def references_model(self, name, app_label):
        return (
            name.lower() == self.old_name.lower()
            or name.lower() == self.new_name.lower()
        )


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0257_bulk_approve_pre_argus_flaws"),
    ]

    operations = [
        # 1. Remove V1 models
        migrations.DeleteModel(name="FlawCollaborator"),
        migrations.DeleteModel(name="FlawLabel"),
        # 2. Rename V2 base model in state only (db_table preserves the table)
        RenameModelStateOnly(
            old_name="FlawLabelV2",
            new_name="FlawLabel",
            db_table="osidb_flawlabelv2",
        ),
        # 3. Update related_name from labels_v2 to labels
        migrations.AlterField(
            model_name="flawlabel",
            name="flaw",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="labels",
                to="osidb.flaw",
            ),
        ),
        # 4. Rename the unique constraint
        migrations.RemoveConstraint(
            model_name="flawlabel",
            name="unique_label_per_flaw_v2",
        ),
        migrations.AddConstraint(
            model_name="flawlabel",
            constraint=models.UniqueConstraint(
                fields=["flaw", "name"],
                name="unique_label_per_flaw",
            ),
        ),
    ]
