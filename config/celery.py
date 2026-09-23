import logging

from celery import Celery, signals
from django.conf import settings
from kombu import Queue

from osidb.telemetry import OtelSettings, configure_telemetry, safe_instrument

logger = logging.getLogger(__name__)


app = Celery("celery")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
app.conf.task_queues = [
    Queue("high", routing_key="high"),
    # Low priority queue for bulk/periodic collector tasks (Bugzilla, Jira, CVE.org,
    # etc. imports) and housekeeping tasks so they don't starve latency-sensitive
    # tasks (Jira task sync/transition, ACE affect creation) waiting on the "high"
    # queue behind long-running imports.
    Queue("low", routing_key="low"),
    # Legacy queue names for safe migration (tasks route to new names, workers
    # consume from both old and new to avoid task loss during cutover)
    Queue("default", routing_key="default"),
    Queue("collectors", routing_key="collectors"),
]
app.conf.task_default_queue = "high"


@signals.worker_process_init.connect
def on_worker_process_init(**kwargs):
    # CeleryInstrumentor is wired here rather than in _instrument_all()
    # because that helper also runs from gunicorn's post_fork, i.e. in web
    # workers. Folding it in there would make every web worker connect
    # Celery's task signals too (harmless, but broadens instrumentation to
    # processes that only publish tasks, not run them). Keep it scoped to
    # actual Celery workers here instead.
    try:
        if not OtelSettings().enabled:
            return
        configure_telemetry()
        from opentelemetry.instrumentation.celery import CeleryInstrumentor

        safe_instrument(CeleryInstrumentor())
    except Exception:
        logger.exception("Failed to configure telemetry")


@signals.setup_logging.connect
def on_celery_setup_logging(**kwargs):
    pass
