"""
index page
"""

import logging

from django.views.generic import TemplateView

from osidb import __version__

logger = logging.getLogger(__name__)


class index(TemplateView):
    """index page view"""

    template_name = "index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["version"] = __version__
        return context
