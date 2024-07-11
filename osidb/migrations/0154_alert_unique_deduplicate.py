"""
Written manually on 2024-07-11

Delete duplicated Alert model instances and add constrain to prevent future duplicates.
"""

from collections import Counter

from django.conf import settings
from django.db import migrations, models

from osidb.core import set_user_acls


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    Alert = apps.get_model("osidb", "Alert")

    # There's currently about 750k Alert objects. Limit the amount of data
    # processed at once in Python by offloading as much work to the database
    # as possible (without using raw SQL).

    # Already known names.
    names = [
        "_validate_acl_identical_to_parent_flaw",
        "_validate_allowed_source",
        "_validate_cve_description_and_requires_cve_description",
        "_validate_cvss_scores_and_nist_cvss_validation",
        "_validate_embargoed_source",
        "_validate_flaw_without_affect",
        "_validate_future_unembargo_date",
        "_validate_historical_affectedness_resolution",
        "_validate_major_incident_combos",
        "_validate_major_incident_state",
        "_validate_no_placeholder",
        "_validate_nonempty_component",
        "_validate_nonempty_components",
        "_validate_nonempty_impact",
        "_validate_nonempty_source",
        "_validate_notaffected_open_tracker",
        "_validate_ooss_open_tracker",
        "_validate_ps_module_new_flaw",
        "_validate_public_source_no_ack",
        "_validate_public_unembargo_date",
        "_validate_reported_date",
        "_validate_summary_and_requires_summary",
        "_validate_tracker_affect",
        "_validate_tracker_bts_match",
        "_validate_tracker_duplicate",
        "_validate_tracker_flaw_accesses",
        "_validate_tracker_ps_update_stream",
        "_validate_wontreport_products",
        "_validate_wontreport_severity",
        "cisa_mi_statement_missing",
        "cisa_mi_summary_missing",
        "cisa_mi_summary_not_reviewed",
        "cvss3_missing",
        "flaw_affects_unknown_component",
        "flaw_historical_affect_status",
        "impact_without_cve_description",
        "impact_without_summary",
        "mi_article_missing",
        "mi_mitigation_missing",
        "mi_statement_missing",
        "mi_summary_missing",
        "mi_summary_not_reviewed",
        "old_flaw_affect_ps_module",
        "private_source_no_ack",
        "public_source_no_ack",
        "request_nist_cvss_validation",
        "rh_nist_cvss_score_diff",
        "rh_nist_cvss_severity_diff",
        "special_consideration_flaw_missing_cve_description",
        "special_consideration_flaw_missing_statement",
        "special_handling_flaw_missing_summary",
        "tracker_no_affect",
        "tracker_no_flaw",
    ]

    # Additional names, if they are in the database. Limits memory usage in Python
    # from tens of MBs to a tiny fraction of that, as compared to a naive
    # `set(Alert.objects.all().values_list("name", flat=True))`.
    names2 = sorted(
        set(Alert.objects.exclude(name__in=names).values_list("name", flat=True))
    )
    names.extend(names2)

    # By searching the duplicates in each name separately, the amount of objects
    # processed at once (number of items in `ids`) is limited to about 100k, as
    # opposed to the total of approx. 750k objects.
    for name in names:
        ids = Alert.objects.filter(name=name).values_list("object_id", "content_type")

        # More efficient than naive approaches https://stackoverflow.com/a/11236042
        # Internally, it uses https://github.com/python/cpython/blob/3.13/Lib/heapq.py#L397
        # which has O(n*log(n)) complexity https://stackoverflow.com/a/42461996.
        counter = Counter(ids)
        dups = [id_pair for id_pair, cnt in counter.items() if cnt > 1]

        # Testing showed that we currently have no duplicates and potential
        # duplicates are limited to only a few flaws for a short duration of time.
        # Therefore, this is to catch the odd-ball duplicate, to prevent it from
        # blocking the migration. Therefore an inefficient but simple way:
        for obj_id, cont_t in dups:
            filter = Alert.objects.filter(
                name=name, object_id=obj_id, content_type=cont_t
            )
            first_uuid = filter.first().uuid
            filter.exclude(uuid=first_uuid).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0153_flaw_syncmanager_link_and_triggers"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
        migrations.AddConstraint(
            model_name="alert",
            constraint=models.UniqueConstraint(
                fields=("name", "object_id", "content_type"),
                name="unique Alert for name and object",
            ),
        ),
    ]
