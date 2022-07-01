# collector framework

The external data is being collected by **collectors**. To create one start by introducing a new
directory in [collectors](..) with an empty `__init__.py` to make it a Python module,
simple `apps.py` to make it a Django application

```python
"""
example collector
"""

from django.apps import AppConfig


class ExampleCollector(AppConfig):
    """example collector"""

    name = "collectors.example"
```

and `tasks.py` where Celery is going to look for the task definitions

```python
"""
example collector
"""
import logging

from celery.schedules import crontab
from django.utils import timezone

from collectors.framework.models import collector

logger = logging.getLogger(__name__)


@collector(
    # execute this every minute
    crontab=crontab(),
)
# as we set celery task bind=True by default
# we get the task object as the parameter here
# which is our collector
def example_collector(collector_obj):
    """example collector"""
    logger.info(f"Collector {collector_obj.name} is running")
    # fake data to be up-to-date
    collector_obj.store(updated_until_dt=timezone.now())
    # optionally return some result to Celery
    return f"The run of {collector_obj.name} was fun"
```

Then, you need to register your Django application to `INSTALLED_APPS`
in [settings](../../config/settings.py). Compose your OSIDB instance down and start again so the
Celery hosts are up-to-date. Now you should see a new collector status being reported when running

```bash
# provide credentials and optionally set URL and port appropriately
export OSIDB_ACCESS_TOKEN=$(curl -H 'Content-Type: application/json' '-d' '{"username": USERNAME,"password": PASSWORD}' http://localhost:8000/auth/token | jq ."access" -r)
curl -H "Authorization: Bearer $OSIDB_ACCESS_TOKEN" -X GET "https://localhost:8000/collectors/api/v1/status" -w "\n" | jq
```

Now it is completely only up to you and your needs what functionality your collector gets. If you
want to tune it better with the **collector framework** do not forget to look [here](models.py).

When working with the data models with ACLs applied, do not forget to set the collector permissions
appropriately. Default ACL groups can be observed [here](../../config/settings_local.py).

```bash
# set permissions to public read-only access
from django.conf import settings
from osidb.core import set_user_acls
set_user_acls(
    settings.PUBLIC_READ_GROUPS
)
```
