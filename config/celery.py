from celery import Celery, signals
from django.conf import Settings, settings
from kombu import Queue
from pydantic_settings import BaseSettings, SettingsConfigDict


class CelerySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSIDB_CELERY_")

    enable_fifo: bool = False
    fifo_pool_size: int = 2


class FIFORouter:
    """
    A router to send tasks with a specific 'object_id' kwarg to a dedicated
    FIFO queue.

    This router guarantees order of operations for operations on the same
    object, however operations on different objects is not guaranteed.

    E.g. Flaw1 needs to perform update1, update2, update3 and then Flaw2
    performs a single update. update1, update2 and update3 are guaranteed
    to be in FIFO order, however it's possible that Flaw2's update will be
    executed anywhere in between.

    The order is guaranteed by hashing the given object's UUID and assigning it
    to one of the fifo queues in the pool, the assigned queue will always be
    the same for a given object, and since the queue is handled by a single
    worker, tasks for said object will be executed in order.
    """

    def route_for_task(self, task, args=None, kwargs=None):
        settings = CelerySettings()
        if kwargs and "object_id" in kwargs and settings.enable_fifo:
            object_id = str(kwargs["object_id"])
            queue_index = hash(object_id) % settings.fifo_pool_size
            queue_name = f"fifo.{queue_index}"

            return {
                "queue": queue_name,
                "routing_key": queue_name,
            }
        # Return None to use the default routing for all other tasks
        return None


app = Celery("celery")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
app.conf.task_queues = [
    Queue("default", routing_key="default"),
    *[
        Queue(f"fifo.{i}", routing_key=f"fifo.{i}")
        for i in range(CelerySettings().fifo_pool_size)
    ],
]
app.conf.task_default_queue = "default"
app.conf.task_routes = ("config.celery.FIFORouter",)


@signals.setup_logging.connect
def on_celery_setup_logging(**kwargs):
    pass
