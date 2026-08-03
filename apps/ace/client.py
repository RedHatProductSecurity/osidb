from datetime import datetime, timedelta

import requests
from celery.utils.log import get_task_logger

from osidb.helpers import get_env

logger = get_task_logger(__name__)

AFFECT_AUTOMATION_URL = get_env("AFFECT_AUTOMATION_URL", default="")
AFFECT_AUTOMATION_TOKEN = get_env("AFFECT_AUTOMATION_TOKEN", default="")
AFFECT_AUTOMATION_MAX_CONNECTION_AGE = get_env(
    "AFFECT_AUTOMATION_MAX_CONNECTION_AGE", default="300"
)
AFFECT_AUTOMATION_TIMEOUT = get_env(
    "AFFECT_AUTOMATION_TIMEOUT", default="60", is_int=True
)


class AffectAutomationConnector:
    """
    Connection handler for the Affect Automation microservice.

    Follows the JiraConnector pattern: session reuse with max connection age.
    """

    _base_url = AFFECT_AUTOMATION_URL
    _token = AFFECT_AUTOMATION_TOKEN

    def __init__(self):
        self._session = None
        self._session_timestamp = None

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update(
            {
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        return session

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = self._create_session()
            self._session_timestamp = datetime.now()
        elif AFFECT_AUTOMATION_MAX_CONNECTION_AGE is not None:
            age = datetime.now() - self._session_timestamp
            if age > timedelta(seconds=int(AFFECT_AUTOMATION_MAX_CONNECTION_AGE)):
                self._session = self._create_session()
                self._session_timestamp = datetime.now()
        return self._session


class AffectAutomationQuerier(AffectAutomationConnector):
    """API methods for the Affect Automation microservice."""

    def request_affects(self, flaw_id: str, payload: dict) -> dict:
        url = f"{self._base_url.rstrip('/')}/api/v1/affects/"
        response = self.session.post(
            url, json=payload, timeout=AFFECT_AUTOMATION_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def health_check(self) -> bool:
        url = f"{self._base_url.rstrip('/')}/api/v1/health/"
        try:
            response = self.session.get(url, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
