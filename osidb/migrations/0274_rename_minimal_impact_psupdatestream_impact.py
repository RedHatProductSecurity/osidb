from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0273_psupdatestream_minimal_impact'),
    ]

    operations = [
        migrations.RenameField(
            model_name='psupdatestream',
            old_name='minimal_impact',
            new_name='impact',
        ),
    ]
