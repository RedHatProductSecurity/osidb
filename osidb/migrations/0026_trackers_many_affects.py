# Generated by Django 3.2.9 on 2021-12-20 19:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0025_tracker_ps_update_stream"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="trackerevent",
            name="affect",
        ),
        migrations.AddField(
            model_name="tracker",
            name="affects",
            field=models.ManyToManyField(related_name="trackers", to="osidb.Affect"),
        ),
        migrations.AlterUniqueTogether(
            name="tracker",
            unique_together={("type", "external_system_id")},
        ),
        migrations.RemoveField(
            model_name="tracker",
            name="affect",
        ),
    ]
