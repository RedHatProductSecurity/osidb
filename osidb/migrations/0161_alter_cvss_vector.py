# Generated by Django 3.2.25 on 2024-08-28 08:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0160_gin_index_for_alert_RBS'),
    ]

    operations = [
        migrations.AlterField(
            model_name='affectcvss',
            name='vector',
            field=models.CharField(max_length=200),
        ),
        migrations.AlterField(
            model_name='flawcvss',
            name='vector',
            field=models.CharField(max_length=200),
        ),
    ]
