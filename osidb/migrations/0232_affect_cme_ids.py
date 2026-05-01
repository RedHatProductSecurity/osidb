import django.contrib.postgres.fields
from django.db import migrations, models

import osidb.validators


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0231_flaw_osidb_flaw_uuid_0d503b_idx_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='affect',
            name='cme_ids',
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(
                    max_length=20,
                    validators=[osidb.validators.validate_cme_id],
                ),
                blank=True,
                default=list,
                size=None,
            ),
        ),
    ]
