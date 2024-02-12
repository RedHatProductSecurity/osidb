# Created manually on 2024-02-12 08:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0116_contractpriority'),
    ]

    operations = [
        migrations.RenameField(
            model_name='contractpriority',
            old_name='ps_component',
            new_name='ps_update_stream',
        ),
        migrations.AlterField(
            model_name='contractpriority',
            name='ps_update_stream',
            field=models.CharField(max_length=100),
        ),
        migrations.RemoveField(
            model_name='contractpriority',
            name='ps_module',
        ),
    ]
