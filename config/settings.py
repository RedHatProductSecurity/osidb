"""
Django base settings for osidb


"""
import socket
from pathlib import Path

from celery.schedules import crontab
from django.core.management.utils import get_random_secret_key

from osidb.helpers import get_env

DEBUG: bool = get_env("OSIDB_DEBUG", default="False", is_bool=True)

SECRET_KEY = get_random_secret_key()  # pragma: allowlist secret

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

ALLOWED_HOSTS = [
    # Allow local host's IP address and hostname for health probes
    socket.gethostname(),
    socket.gethostbyname(socket.gethostname()),
    ".redhat.com",
]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_LDAP_SERVER_URI = get_env("LDAP_SERVER_URL", default="ldap://testldap:1389")

LOGIN_URL = "/admin/"
BLACKLISTED_HTTP_METHODS = ("patch",)
READONLY_MODE: bool = get_env("OSIDB_READONLY_MODE", default="False", is_bool=True)

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_extensions",
    "django.contrib.postgres",
    "psqlextra",
    "rest_framework",
    "django_filters",
    "osidb",
    "apps.bbsync",
    "apps.exploits",
    "apps.osim",
    "collectors.bzimport",
    "collectors.errata",
    "collectors.framework",
    "collectors.jiraffe",
    "collectors.product_definitions",
    "drf_spectacular",
    "polymorphic",
    "rest_framework_simplejwt",
    "collectors.epss",
    "collectors.exploits_cisa",
    "collectors.exploits_exploitdb",
    "collectors.exploits_metasploit",
    "collectors.nvd",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.gzip.GZipMiddleware",
    "osidb.middleware.PgCommon",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "DEFAULT_AUTHENTICATION_CLASSES": ("osidb.auth.OsidbTokenAuthentication",),
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "osidb.renderers.OsidbRenderer",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 100,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "osidb.exception_handlers.exception_handler",
}

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Celery application definition
CELERY_BROKER_URL = CELERY_RESULT_BACKEND = "redis://redis:6379/"
CELERY_TASK_SOFT_TIME_LIMIT = 3600
CELERY_TASK_IGNORE_RESULT = False
CELERY_TASK_ROUTES = (
    [
        (
            "collector.bzimport.tasks.extract*",
            {"queue": "slow"},
        ),  # slow_* tasks go to 'slow' queue
        ("*", {"queue": "fast"}),  # default other tasks go to 'fast'
    ],
)
CELERY_BEAT_SCHEDULE = {
    "jiraffe_sync": {
        "task": "collectors.jiraffe.tasks.jiraffe_sync",
        "schedule": crontab(minute="*/1"),
    },
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose_celery": {
            "()": "osidb.helpers.TaskFormatter",
            "format": "%(asctime)s [%(levelname)s] %(task_name)s%(task_id)s: %(message)s",
        },
        "verbose": {
            # exact format is not important, this is the minimum information
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
        "celery": {
            "level": "WARNING",
            "class": "logging.StreamHandler",
            "formatter": "verbose_celery",
        },
    },
    "loggers": {
        "django.utils.autoreload": {
            "level": "ERROR",
            "handlers": ["console"],
        },
        "django": {
            "level": "WARNING",
            "handlers": ["console"],
        },
        "celery": {"handlers": ["celery"], "level": "INFO", "propagate": True},
        "osidb": {"level": "WARNING", "handlers": ["console"], "propagate": False},
        "django_auth_ldap": {"level": "WARNING", "handlers": ["console"]},
        # app loggers
        **{
            app_name: {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": True,
            }
            for app_name in [
                "apps.bbsync",
                "apps.exploits",
                "apps.osim",
            ]
        },
        # Collectors loggers
        **{
            collector_name: {
                "level": "WARNING",
                "handlers": ["celery"],
                "propagate": True,
            }
            for collector_name in [
                "collectors.bzimport",
                "collectors.epss",
                "collectors.errata",
                "collectors.example",
                "collectors.exploits_cisa",
                "collectors.exploits_exploitdb",
                "collectors.exploits_metasploit",
                "collectors.framework",
                "collectors.jiraffe",
                "collectors.nvd",
                "collectors.product_definitions",
            ]
        },
    },
}

if DEBUG:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.dummy.DummyCache",
        }
    }

# Settings for the drf-spectacular package
SPECTACULAR_SETTINGS = {
    "TITLE": "OSIDB API",
    "DESCRIPTION": "REST API autogenerated docs for the OSIDB and its components",
    "VERSION": "3.1.3",
    "SWAGGER_UI_SETTINGS": {"supportedSubmitMethods": []},
    "SERVE_AUTHENTICATION": [
        "krb5_auth.auth.KerberosAuthentication",
        "osidb.auth.OsidbTokenAuthentication",
    ],
    "POSTPROCESSING_HOOKS": [
        "drf_spectacular.hooks.postprocess_schema_enums",
        "osidb.hooks.response_metadata_postprocess_hook",
    ],
}

ERRATA_TOOL_SERVER = get_env("ET_URL")
ERRATA_TOOL_XMLRPC_BASE_URL = f"{ERRATA_TOOL_SERVER}/errata/errata_service"

# Execute once a day by default
CISA_COLLECTOR_CRONTAB = crontab(minute=0, hour=1)

# default requests.get timeout aims to be generous but finite
DEFAULT_REQUEST_TIMEOUT = get_env(
    "OSIDB_DEFAULT_REQUEST_TIMEOUT", default="30", is_int=True
)
