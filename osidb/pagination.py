from django.conf import settings
from rest_framework.pagination import LimitOffsetPagination


class HardLimitOffsetPagination(LimitOffsetPagination):
    """
    Customisation of LimitOffsetPagination which adds a hard limit that
    cannot be exceeded. If the user requests more records in a page than
    the hard limit, it will be capped to the hard limit.
    """

    limit = settings.REST_FRAMEWORK.get("PAGE_SIZE")
    hard_limit = settings.REST_FRAMEWORK.get("MAX_PAGE_SIZE")

    def get_limit(self, request):
        limit = super().get_limit(request)
        return min(limit, self.hard_limit) if limit else self.limit
