# Datadog APM Setup for OSIDB

This document describes the Datadog APM integration setup for OSIDB.

## Overview

Datadog APM has been integrated into OSIDB to provide distributed tracing and performance monitoring across:
- Django web service (`osidb-service`)
- Celery workers (`celery`, `celery-fifo-1`, `celery-fifo-2`)
- Celery beat scheduler (`celery_beat`)
- Flower monitoring (`flower`)

## Prerequisites

1. **Datadog API Key**: Set in your `.env` file:  <!-- pragma: allowlist secret -->
   ```bash
   DD_API_KEY="your-api-key-here"  # pragma: allowlist secret
   ```

2. **ddtrace installed**: Already included in `pyproject.toml` as `ddtrace>=4.10.4<5.0`

## Configuration

### Environment Variables

The following Datadog environment variables are configured in `docker-compose.yml`:

#### Required (for Datadog Agent):
- `DD_API_KEY`: Your Datadog API key
- `DD_SITE`: Datadog site (default: `datadoghq.com`)

#### APM Configuration (for application containers):
- `DD_AGENT_HOST`: Hostname of Datadog agent (`datadog-agent`)
- `DD_TRACE_AGENT_PORT`: Trace agent port (`8126`)
- `DD_SERVICE`: Service name (varies by container)
- `DD_ENV`: Environment name (default: `local`)
- `DD_VERSION`: Application version (default: `5.11.1`)
- `DD_TRACE_ENABLED`: Enable/disable tracing (default: `true`)
- `DD_LOGS_INJECTION`: Inject trace IDs into logs (default: `true`)
- `DD_TRACE_SAMPLE_RATE`: Sampling rate 0.0-1.0 (default: `1.0`)
- `DD_DJANGO_INSTRUMENT_DATABASES`: Trace database queries (default: `true`)
- `DD_DJANGO_INSTRUMENT_MIDDLEWARE`: Trace middleware (default: `true`)

### Service Names

Each component has its own service name for better trace organization:
- `osidb-service`: Django web application
- `osidb-celery`: Celery workers
- `osidb-celery-beat`: Celery beat scheduler

### Customization

You can override default values by setting them in your `.env` file:

```bash
# Change environment tag
DD_ENV=development

# Reduce sample rate to 50%
DD_TRACE_SAMPLE_RATE=0.5

# Disable tracing temporarily
DD_TRACE_ENABLED=false
```

## How It Works

### Django Middleware

The Datadog TraceMiddleware is added at the top of the middleware stack in `config/settings.py`:

```python
MIDDLEWARE = [
    "ddtrace.contrib.django.TraceMiddleware",  # Datadog APM tracing
    ...
]
```

This middleware provides:
- Request/response tracing with full context
- Automatic span creation for each request
- Integration with Django's request lifecycle
- Better trace correlation across middleware layers

### ddtrace-run Wrapper

All Python processes are started with the `ddtrace-run` wrapper, which automatically instruments:
- Django requests and responses
- Database queries (PostgreSQL)
- Celery tasks
- HTTP requests
- Redis operations

Modified startup commands:
- `ddtrace-run python3 manage.py runserver` (osidb-service)
- `ddtrace-run celery -A config worker` (celery workers)
- `ddtrace-run celery -A config beat` (celery beat)
- `ddtrace-run celery -A config flower` (flower)

**Note**: While `ddtrace-run` auto-instruments Django, the explicit middleware provides better trace context and control.

### Trace Collection Flow

1. Application sends traces to `datadog-agent:8126`
2. Datadog agent buffers and processes traces
3. Agent forwards traces to Datadog backend (`DD_SITE`)

## Verification

After starting the containers:

1. **Check Datadog Agent Status**:
   ```bash
   podman exec -it datadog-agent agent status
   ```

2. **View APM Traces**:
   - Go to https://app.datadoghq.com/apm/traces
   - Filter by service: `osidb-service`, `osidb-celery`, etc.

3. **Check Trace Generation**:
   Make a request to your OSIDB service:
   ```bash
   curl http://localhost:8000/osidb/healthy
   ```
   
   Then check for traces in Datadog UI within 1-2 minutes.

## Troubleshooting

### No traces appearing in Datadog

1. Verify Datadog agent is running:
   ```bash
   podman ps | grep datadog-agent
   ```

2. Check agent logs:
   ```bash
   podman logs datadog-agent
   ```

3. Verify environment variables are set:
   ```bash
   podman exec -it osidb-service env | grep DD_
   ```

4. Check trace agent endpoint:
   ```bash
   podman exec -it osidb-service curl -v http://datadog-agent:8126
   ```

### High overhead

If tracing causes performance issues:

1. Reduce sample rate:
   ```bash
   DD_TRACE_SAMPLE_RATE=0.1  # Sample 10% of traces
   ```

2. Disable database instrumentation:
   ```bash
   DD_DJANGO_INSTRUMENT_DATABASES=false
   ```

### Connection refused to agent

Ensure all containers can reach `datadog-agent`:
```bash
podman exec -it osidb-service ping datadog-agent
```

If not, check that containers are on the same network.

## Production Considerations

For production deployments:

1. **Set appropriate environment**:
   ```bash
   DD_ENV=production
   ```

2. **Use meaningful version tags**:
   ```bash
   DD_VERSION=$(git rev-parse --short HEAD)
   ```

3. **Adjust sample rate** based on traffic:
   ```bash
   DD_TRACE_SAMPLE_RATE=0.1  # For high-volume services
   ```

4. **Enable unified service tagging**:
   Ensure `DD_SERVICE`, `DD_ENV`, and `DD_VERSION` are consistently set.

5. **Configure retention** in Datadog to match your requirements.

## References

- [Datadog Python APM Documentation](https://docs.datadoghq.com/tracing/setup_overview/setup/python/)
- [ddtrace Configuration](https://ddtrace.readthedocs.io/en/stable/configuration.html)
- [Django Integration](https://ddtrace.readthedocs.io/en/stable/integrations.html#django)
- [Celery Integration](https://ddtrace.readthedocs.io/en/stable/integrations.html#celery)
