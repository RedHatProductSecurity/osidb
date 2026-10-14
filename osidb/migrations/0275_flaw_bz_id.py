from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    # AddIndexConcurrently cannot run inside a transaction.
    atomic = False

    dependencies = [
        ("osidb", "0274_remove_flaw_insert_insert_remove_flaw_update_update_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="flaw",
            name="bz_id",
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
        migrations.RunSQL(
            sql="""
                UPDATE osidb_flaw
                   SET bz_id = (meta_attr -> 'bz_id')::bigint,
                       meta_attr = delete(meta_attr, 'bz_id')
                  WHERE meta_attr ? 'bz_id'
                    AND meta_attr -> 'bz_id' ~ '^[0-9]+$'
                    AND (
                        length(meta_attr -> 'bz_id') < 19
                        OR (
                            length(meta_attr -> 'bz_id') = 19
                            AND meta_attr -> 'bz_id' <= '9223372036854775807'
                        )
                    );

                UPDATE osidb_flaw
                   SET meta_attr = delete(meta_attr, 'bz_id')
                  WHERE meta_attr ? 'bz_id'
                    AND meta_attr -> 'bz_id' = '';
            """,
            reverse_sql="""
                UPDATE osidb_flaw
                   SET meta_attr = meta_attr || hstore('bz_id', bz_id::text)
                  WHERE bz_id IS NOT NULL;
            """,
        ),
        AddIndexConcurrently(
            model_name="flaw",
            index=models.Index(
                fields=["bz_id"],
                condition=models.Q(bz_id__isnull=False),
                name="osidb_flaw_bz_id_idx",
            ),
        ),
    ]
