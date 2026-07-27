"""
Vendor-neutral OpenTelemetry setup with embargo-aware redaction.

Wraps the OTLP exporter with a RedactingExporter that regex-scrubs
sensitive patterns (CVE IDs, UUIDs, quoted string literals) from span
attributes before export. This preserves query/URL structure for
debugging while ensuring embargoed data never reaches third-party
tracing backends (Datadog, Jaeger, Grafana, etc.).

Gated on OSIDB_OTEL_ENABLED — completely inert when disabled.
Swap tracing vendors by changing OTEL_EXPORTER_OTLP_ENDPOINT alone.
"""

import logging
import os
import re

logger = logging.getLogger(__name__)

_configured = False

CVE_RE = re.compile(r"CVE-\d{4}-\d+")
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
QUOTED_STR_RE = re.compile(r"'[^']*'")

SCRUB_ATTR_KEYS = {
    "db.statement",
    "http.target",
    "http.url",
    "url.full",
    "url.path",
    "url.query",
    "http.route",
}


def _scrub(value):
    if not isinstance(value, str):
        return value
    value = CVE_RE.sub("CVE-XXXX-XXXXX", value)
    value = UUID_RE.sub("XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", value)
    value = QUOTED_STR_RE.sub("'?'", value)
    return value


def _scrub_span(span):
    if not span.attributes:
        return span
    scrubbed = {}
    for key, value in span.attributes.items():
        scrubbed[key] = _scrub(value) if key in SCRUB_ATTR_KEYS else value
    span._attributes = scrubbed
    return span


def configure_telemetry():
    global _configured
    if _configured:
        return
    _configured = True

    if os.environ.get("OSIDB_OTEL_ENABLED", "").lower() not in ("1", "true", "yes"):
        return

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter

    class RedactingExporter(SpanExporter):
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def export(self, spans):
            return self._wrapped.export([_scrub_span(s) for s in spans])

        def shutdown(self):
            self._wrapped.shutdown()

        def force_flush(self, timeout_millis=None):
            return self._wrapped.force_flush(timeout_millis)

    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", "osidb"),
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = RedactingExporter(OTLPSpanExporter())
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    _instrument_all()
    logger.info("OpenTelemetry configured")


def _instrument_all():
    instrumentors = [
        ("opentelemetry.instrumentation.django", "DjangoInstrumentor"),
        ("opentelemetry.instrumentation.psycopg2", "Psycopg2Instrumentor"),
        ("opentelemetry.instrumentation.requests", "RequestsInstrumentor"),
        ("opentelemetry.instrumentation.redis", "RedisInstrumentor"),
    ]
    for module_path, class_name in instrumentors:
        try:
            import importlib

            mod = importlib.import_module(module_path)
            instrumentor = getattr(mod, class_name)()
            if not instrumentor.is_instrumented_by_opentelemetry:
                instrumentor.instrument()
                logger.info("Instrumented %s", class_name)
        except Exception:
            logger.exception("Failed to instrument %s", class_name)
