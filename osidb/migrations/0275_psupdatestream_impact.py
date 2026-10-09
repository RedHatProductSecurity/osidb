from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0274_remove_flaw_insert_insert_remove_flaw_update_update_and_more"),
    ]

    operations = [
        # Expand step of an expand/contract rename of `minimal_impact` -> `impact`.
        # We intentionally do NOT rename the column: a rename is not
        # backwards-compatible, so a code-only rollback to a release that still
        # references `minimal_impact` would fail against the renamed column.
        # Instead we add the new `impact` column now and leave the old
        # `minimal_impact` column in place (it is always empty, so there is no
        # data to migrate). The dead column is dropped in a later release once
        # no rollback target references it anymore (contract step).
        migrations.AddField(
            model_name="psupdatestream",
            name="impact",
            field=models.CharField(
                blank=True,
                choices=[
                    ("", "Novalue"),
                    ("LOW", "Low"),
                    ("MODERATE", "Moderate"),
                    ("IMPORTANT", "Important"),
                    ("CRITICAL", "Critical"),
                ],
                db_default="",
                max_length=20,
            ),
        ),
        migrations.SeparateDatabaseAndState(
            # Remove `minimal_impact` from Django model state so the new code
            # no longer references it in queries...
            state_operations=[
                migrations.RemoveField(
                    model_name="psupdatestream",
                    name="minimal_impact",
                ),
            ],
            # ...but keep the physical column so a rollback to the previous
            # release (which still selects `minimal_impact`) keeps working.
            # The column is NOT NULL with no DB-level default, so once the new
            # code stops supplying it on INSERT the rows would violate the
            # not-null constraint; give it an empty-string default (a valid
            # choice) so inserts omitting the column keep succeeding.
            database_operations=[
                migrations.RunSQL(
                    sql="ALTER TABLE osidb_psupdatestream ALTER COLUMN minimal_impact SET DEFAULT '';",
                    reverse_sql="ALTER TABLE osidb_psupdatestream ALTER COLUMN minimal_impact DROP DEFAULT;",
                ),
            ],
        ),
    ]
