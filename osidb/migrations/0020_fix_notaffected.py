# Generated by Django 3.2.9 on 2021-12-04 18:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0019_clean_affect_model"),
    ]

    operations = [
        migrations.AlterField(
            model_name="affect",
            name="affectedness",
            field=models.CharField(
                choices=[
                    ("NONE", "No value"),
                    ("NEW", "Unknown"),
                    ("AFFECTED", "Affected"),
                    ("NOTAFFECTED", "Not affected"),
                ],
                max_length=100,
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="affectevent",
            name="affectedness",
            field=models.CharField(
                choices=[
                    ("NONE", "No value"),
                    ("NEW", "Unknown"),
                    ("AFFECTED", "Affected"),
                    ("NOTAFFECTED", "Not affected"),
                ],
                max_length=100,
                null=True,
            ),
        ),
    ]
