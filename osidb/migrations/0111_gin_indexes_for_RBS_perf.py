# Generated by Django 3.2.23 on 2024-01-09 17:50

import django.contrib.postgres.indexes
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0110_snippet_miscellaneous"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="affect",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_affec_acl_rea_b1208d_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="affectcvss",
            index=models.Index(
                fields=["-updated_dt"], name="osidb_affec_updated_8f7316_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="affectcvss",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_affec_acl_rea_cf0fac_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="flaw",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_flaw_acl_rea_d23b7c_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="flawacknowledgment",
            index=models.Index(
                fields=["-updated_dt"], name="osidb_flawa_updated_727bda_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="flawacknowledgment",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_flawa_acl_rea_0343a9_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="flawcomment",
            index=models.Index(
                fields=["-updated_dt"], name="osidb_flawc_updated_cd6977_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="flawcomment",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_flawc_acl_rea_13cd98_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="flawcvss",
            index=models.Index(
                fields=["-updated_dt"], name="osidb_flawc_updated_546d3e_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="flawcvss",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_flawc_acl_rea_f69fcd_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="flawmeta",
            index=models.Index(
                fields=["-updated_dt"], name="osidb_flawm_updated_3e7bb3_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="flawmeta",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_flawm_acl_rea_51d45b_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="flawreference",
            index=models.Index(
                fields=["-updated_dt"], name="osidb_flawr_updated_dec0b2_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="flawreference",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_flawr_acl_rea_c84e3f_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="package",
            index=models.Index(
                fields=["-updated_dt"], name="osidb_packa_updated_08e3f7_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="package",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_packa_acl_rea_0f4caf_gin"
            ),
        ),
        migrations.AddIndex(
            model_name="tracker",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["acl_read"], name="osidb_track_acl_rea_e22444_gin"
            ),
        ),
    ]
