"""
Each model represents a group of keywords collected from
`data/cveorg_keywords.yml` in the `ps-constants` repository.

These keywords determine whether the CVEorg collector should create a flaw.
"""

import uuid

from django.db import models


class Allowlist(models.Model):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keyword = models.CharField(max_length=255, unique=True)


class AllowlistSpecialCase(models.Model):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keyword = models.CharField(max_length=255, unique=True)


class Blocklist(models.Model):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keyword = models.CharField(max_length=255, unique=True)


class BlocklistSpecialCase(models.Model):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    keyword = models.CharField(max_length=255, unique=True)
