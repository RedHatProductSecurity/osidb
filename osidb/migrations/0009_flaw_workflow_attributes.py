# Generated by Django 3.2.9 on 2021-11-09 09:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0008_auto_20211027_1242"),
    ]

    operations = [
        migrations.AddField(
            model_name="flaw",
            name="osim_state",
            field=models.CharField(
                choices=[
                    ("DRAFT", "Draft"),
                    ("NEW", "New"),
                    ("ANALYSIS", "Analysis"),
                    ("REVIEW", "Review"),
                    ("FIX", "Fix"),
                    ("DONE", "Done"),
                ],
                max_length=10,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="flaw",
            name="osim_workflow",
            field=models.CharField(max_length=20, null=True),
        ),
        migrations.AddField(
            model_name="flawevent",
            name="osim_state",
            field=models.CharField(
                choices=[
                    ("DRAFT", "Draft"),
                    ("NEW", "New"),
                    ("ANALYSIS", "Analysis"),
                    ("REVIEW", "Review"),
                    ("FIX", "Fix"),
                    ("DONE", "Done"),
                ],
                max_length=10,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="flawevent",
            name="osim_workflow",
            field=models.CharField(max_length=20, null=True),
        ),
    ]
