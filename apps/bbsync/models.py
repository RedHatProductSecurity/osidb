"""
Bugzilla metadata models
"""

from django.contrib.postgres import fields
from django.db import models


class BugzillaProduct(models.Model):
    """
    Bugzilla product model
    """

    # the maximum length in the real data is currently 50
    name = models.CharField(max_length=100, primary_key=True)

    def __str__(self):
        """
        string representaion of the object
        """
        return f"BugzillaProduct({self.name})"


class BugzillaComponent(models.Model):
    """
    Bugzilla component model
    """

    # the maximum length in the real data is currently 64
    name = models.CharField(max_length=100, primary_key=True)
    default_owner = models.CharField(max_length=100)
    default_cc = fields.ArrayField(models.CharField(max_length=100), default=list)

    product = models.ForeignKey(
        BugzillaProduct, on_delete=models.CASCADE, related_name="components"
    )

    def __str__(self):
        """
        string representaion of the object
        """
        return f"BugzillaComponent({self.name})"
