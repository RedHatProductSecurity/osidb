# Generated by Django 4.2.17 on 2024-12-19 09:20

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0178_flawlabel'),
    ]

    operations = [
        migrations.CreateModel(
            name='FlawCollaborator',
            fields=[
                ('created_dt', models.DateTimeField(blank=True)),
                ('updated_dt', models.DateTimeField(blank=True)),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('state', models.CharField(choices=[('NEW', 'New'), ('REQ', 'Req'), ('SKIP', 'Skip'), ('DONE', 'Done')], default='NEW', max_length=10)),
                ('contributor', models.CharField(blank=True, max_length=255)),
                ('flaw', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='labels', to='osidb.flaw')),
                ('label', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='osidb.flawlabel', to_field='name')),
            ],
        ),
        migrations.AddConstraint(
            model_name='flawcollaborator',
            constraint=models.UniqueConstraint(fields=('flaw', 'label'), name='unique label per flaw'),
        ),
    ]
