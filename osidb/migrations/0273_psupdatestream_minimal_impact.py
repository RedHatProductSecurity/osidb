from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0272_relation_audit_indexes'),
    ]

    operations = [
        migrations.AddField(
            model_name='psupdatestream',
            name='minimal_impact',
            field=models.CharField(
                blank=True,
                choices=[
                    ('', 'Novalue'),
                    ('LOW', 'Low'),
                    ('MODERATE', 'Moderate'),
                    ('IMPORTANT', 'Important'),
                    ('CRITICAL', 'Critical'),
                ],
                max_length=20,
            ),
        ),
    ]
