import pytest
from django.conf import settings

from osidb import telemetry

pytestmark = pytest.mark.unit


class TestInstrumentDjango:
    """
    instrument_django() must register before get_wsgi_application() builds
    WSGIHandler (which reads settings.MIDDLEWARE once, at construction
    time). Covers both preload_app=True (master builds the app before
    fork/post_fork runs) and preload_app=False (worker builds it after
    post_fork), since in both cases wsgi.py calls it ahead of
    get_wsgi_application().
    """

    def teardown_method(self):
        from opentelemetry.instrumentation.django import DjangoInstrumentor

        if DjangoInstrumentor().is_instrumented_by_opentelemetry:
            DjangoInstrumentor().uninstrument()

    def test_disabled_is_noop(self, monkeypatch):
        monkeypatch.setenv("OSIDB_OTEL_ENABLED", "false")
        middleware_before = list(settings.MIDDLEWARE)
        telemetry.instrument_django()
        assert settings.MIDDLEWARE == middleware_before

    def test_enabled_registers_middleware_before_wsgi_app_exists(self, monkeypatch):
        # Simulates wsgi.py: instrument_django() must run, and must have an
        # effect on settings.MIDDLEWARE, before get_wsgi_application() (not
        # called here) would read it.
        monkeypatch.setenv("OSIDB_OTEL_ENABLED", "true")
        telemetry.instrument_django()
        assert any("opentelemetry" in mw for mw in settings.MIDDLEWARE)


class TestPostForkTelemetryFailure:
    def test_post_fork_survives_configure_telemetry_failure(self, monkeypatch):
        import gunicorn_config

        monkeypatch.setattr(
            gunicorn_config,
            "configure_telemetry",
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        )

        class FakeLog:
            def __init__(self):
                self.exceptions = []

            def exception(self, msg, *args):
                self.exceptions.append(msg)

        worker = type("Worker", (), {"log": FakeLog()})()

        # Must not raise, worker startup should continue without telemetry.
        gunicorn_config.post_fork(server=None, worker=worker)

        assert worker.log.exceptions
