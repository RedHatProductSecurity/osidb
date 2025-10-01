# Needed as django migration renaming operation does not
# changes database constraints name creating conflicts.
# Also this is safe since we recreate policies every collection.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('sla', '0005_replace_sla_with_temporalpolicy'),
    ]

    operations = [
        migrations.DeleteModel(
            name='SLAPolicy',
        ),
    ]
