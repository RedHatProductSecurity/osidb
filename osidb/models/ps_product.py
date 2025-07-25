import uuid

from django.db import models

from osidb.helpers import deprecate_field


class PsProduct(models.Model):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # short name of the product, also known as product id from SFM2
    short_name = models.CharField(max_length=50, unique=True)

    # name of the product
    name = models.CharField(max_length=100)

    # team responsible for the product
    team = deprecate_field(models.CharField(max_length=50))

    # the business unit to which the product belongs
    business_unit = models.CharField(max_length=50)

    @property
    def is_community(self) -> bool:
        """
        is community boolean property
        """
        return self.business_unit == "Community"

    @property
    def is_middleware(self) -> bool:
        return self.business_unit == "Core Middleware"
