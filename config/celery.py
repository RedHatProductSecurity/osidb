"""
Celery configuration
"""
from celery import Celery, signals
from django.conf import settings

app = Celery("celery")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


@signals.setup_logging.connect
def on_celery_setup_logging(**kwargs):
    pass
