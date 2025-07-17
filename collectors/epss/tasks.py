"""
EPSS data collector
"""

import csv
import gzip
import io

import requests
from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.exploits.helpers import set_exploit_collector_acls, update_objects_with_flaws
from apps.exploits.models import EPSS
from collectors.framework.models import collector
from osidb.helpers import get_env

logger = get_task_logger(__name__)

# CSV fields:
# cve,epss,percentile
COLUMN_CVE = 0
COLUMN_EPSS = 1
EPSS_URL = get_env(
    "EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)
CHUNK_SIZE = 1000


def download():
    response = requests.get(EPSS_URL, timeout=settings.DEFAULT_REQUEST_TIMEOUT)
    compressed_file = io.BytesIO(response.content)
    return compressed_file


def process_data(compressed_file):
    epss_objects = []
    csv_data = gzip.open(compressed_file).read().decode("utf-8")
    reader = csv.reader(csv_data.split("\n"))
    rows = [r for r in reader if r][2:]  # Remove header and empty lines

    for i, row in enumerate(rows, start=1):
        cve = row[COLUMN_CVE]
        epss = float(row[COLUMN_EPSS])
        epss_objects.append(
            EPSS(
                cve=cve,
                flaw=None,  # Preliminary set to None, make links later
                epss=epss,
            )
        )
        if i % CHUNK_SIZE == 0:
            update_objects_with_flaws(epss_objects)  # Make links to flaws if they exist
            yield epss_objects
            epss_objects = []

    update_objects_with_flaws(epss_objects)  # Make links to flaws if they exist
    yield epss_objects


def process_and_store(data):
    # Do not use store_objects as it cannot handle chunks
    with transaction.atomic():  # Avoid having empty table accessible
        EPSS.objects.all().delete()  # Always load the data again, as it changes in time
        for objects in process_data(data):
            EPSS.objects.bulk_create(objects)


def epss_collector_main():
    set_exploit_collector_acls()
    data = download()
    process_and_store(data)


@collector(
    # Execute once a day
    crontab=crontab(minute=20, hour=1),
)
def epss_collector(collector_obj):
    logger.info(f"Collector {collector_obj.name} is running")

    epss_collector_main()

    # Save time when the collector ran for the last time
    collector_obj.store(updated_until_dt=timezone.now())

    return f"The {collector_obj.name} finished successfully."
