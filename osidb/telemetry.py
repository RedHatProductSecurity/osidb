"""
Vendor-neutral OpenTelemetry setup.

No span redaction: traces go to the same RH-approved vendor we already
send logs to, under the same trust relationship, so holding them to a
stricter bar than logs isn't consistent, and it would leave every span
attribute (SQL, URLs, routes) hidden.

Gated on OSIDB_OTEL_ENABLED — completely inert when disabled.
Swap tracing vendors by changing OSIDB_OTEL_EXPORTER_OTLP_ENDPOINT alone.
"""

import logging
import os

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class OtelSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSIDB_OTEL_")

    enabled: bool = False
    exporter_otlp_endpoint: str = ""
    service_name: str = "osidb"


def instrument_django():
    """
    Register Django's OTEL instrumentation.

    DjangoInstrumentor works by inserting itself into settings.MIDDLEWARE,
    which Django only reads once, when WSGIHandler is constructed. That
    construction happens in get_wsgi_application(), which (with
    preload_app=True) runs in the master process before post_fork. So this
    must be called before get_wsgi_application(), not from post_fork like
    the rest of telemetry setup (which needs to run per-worker instead).
    Safe to call before the real TracerProvider exists: OTEL's tracer is a
    lazy proxy that binds to whatever provider is configured later.
    """
    if not OtelSettings().enabled:
        return
    try:
        from opentelemetry.instrumentation.django import DjangoInstrumentor

        instrumentor = DjangoInstrumentor()
    except Exception:
        logger.exception("Failed to instrument DjangoInstrumentor")
        return
    safe_instrument(instrumentor)


def configure_telemetry():
    settings = OtelSettings()
    if not settings.enabled:
        return

    # Conservative default so flipping OSIDB_OTEL_ENABLED=true doesn't spike
    # ingestion volume before we've tuned a real ratio. Auto-instrumentation
    # emits one span per SQL query, so unsampled export gets noisy/expensive
    # fast. Env vars below still take precedence if set per-environment.
    os.environ.setdefault("OTEL_TRACES_SAMPLER", "parentbased_traceidratio")
    os.environ.setdefault("OTEL_TRACES_SAMPLER_ARG", "0.1")

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({"service.name": settings.service_name})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=settings.exporter_otlp_endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    _instrument_all()
    logger.info("OpenTelemetry configured")


def _instrument_all():
    # Django is registered separately, pre-fork, by instrument_django().
    from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor

    for instrumentor_cls in (
        Psycopg2Instrumentor,
        RequestsInstrumentor,
        RedisInstrumentor,
    ):
        safe_instrument(instrumentor_cls())


def safe_instrument(instrumentor):
    # Shared by instrument_django(), _instrument_all() and Celery's
    # on_worker_process_init hook: register an instrumentor once, and never
    # let a broken/incompatible one take the process down.
    name = type(instrumentor).__name__
    try:
        if not instrumentor.is_instrumented_by_opentelemetry:
            instrumentor.instrument()
            logger.info("Instrumented %s", name)
    except Exception:
        logger.exception("Failed to instrument %s", name)
