import uuid

import pghistory
from django.db import models

from osidb.mixins import ACLMixin, TrackingMixin


class UpstreamProject(TrackingMixin):
    class ContactMethod(models.TextChoices):
        EMAIL = "email"
        GITHUB_ISSUE = "github_issue"
        GITLAB_ISSUE = "gitlab_issue"
        FORGEJO_ISSUE = "forgejo_issue"
        WEBSITE_FORM = "website_form"
        NONE_FOUND = "none_found"
        OTHER = "other"

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    component_name = models.CharField(max_length=255)
    repository_url = models.URLField(blank=True)
    security_contact = models.CharField(max_length=255, blank=True)
    contact_method = models.CharField(
        max_length=20,
        choices=ContactMethod.choices,
        blank=True,
    )
    contact_url = models.URLField(blank=True)
    source = models.CharField(max_length=255, blank=True)
    confidence = models.CharField(max_length=50, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    verified_by = models.CharField(max_length=255, blank=True)
    unsupported = models.BooleanField(default=False)
    stewarded_awareness = models.BooleanField(default=False)
    stewarded_awareness_reason = models.TextField(blank=True)
    stewarded_awareness_marked_by = models.CharField(max_length=255, blank=True)
    stewarded_awareness_marked_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        verbose_name = "Upstream Project"
        verbose_name_plural = "Upstream Projects"

    def __str__(self):
        return self.component_name


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    exclude=["meta_attr"],
    model_name="UpstreamNotificationAudit",
)
class UpstreamNotification(ACLMixin, TrackingMixin):
    class NotificationStatus(models.TextChoices):
        NOT_APPLICABLE = "not_applicable"
        NOT_REQUIRED = "not_required"
        REQUIRED = "required"
        CONTACT_NEEDED = "contact_needed"
        PREPARED = "prepared"
        REVIEWED = "reviewed"
        SENT = "sent"
        DEFERRED = "deferred"
        BLOCKED = "blocked"
        FAILED = "failed"

    class ReportabilityReason(models.TextChoices):
        RED_HAT_IDENTIFIED = "red_hat_identified"
        JOINTLY_IDENTIFIED = "jointly_identified"
        MANUAL_OVERRIDE = "manual_override"

    class NotificationMethod(models.TextChoices):
        EMAIL = "email"
        GITHUB_ISSUE = "github_issue"
        GITLAB_ISSUE = "gitlab_issue"
        FORGEJO_ISSUE = "forgejo_issue"
        WEBSITE_FORM = "website_form"
        OTHER_MANUAL = "other_manual"

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    flaw = models.ForeignKey(
        "osidb.Flaw",
        on_delete=models.CASCADE,
        related_name="upstream_notifications",
    )
    upstream_project = models.ForeignKey(
        UpstreamProject,
        on_delete=models.CASCADE,
        related_name="notifications",
        null=True,
        blank=True,
    )
    status = models.CharField(
        max_length=20,
        choices=NotificationStatus.choices,
        default=NotificationStatus.REQUIRED,
    )
    reportability_reason = models.CharField(
        max_length=30,
        choices=ReportabilityReason.choices,
        blank=True,
    )
    method = models.CharField(
        max_length=20,
        choices=NotificationMethod.choices,
        blank=True,
    )
    timer_started_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        verbose_name = "Upstream Notification"
        verbose_name_plural = "Upstream Notifications"
        indexes = [
            models.Index(fields=["flaw"]),
            models.Index(fields=["status"]),
            models.Index(fields=["timer_started_at"]),
            models.Index(fields=["upstream_project"]),
        ]

    def __str__(self):
        return f"{self.flaw} - {self.upstream_project}"


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    exclude=["meta_attr"],
    model_name="FlawUpstreamMappingAudit",
)
class FlawUpstreamMapping(TrackingMixin):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    flaw = models.ForeignKey(
        "osidb.Flaw",
        on_delete=models.CASCADE,
        related_name="upstream_mappings",
    )
    upstream_project = models.ForeignKey(
        UpstreamProject,
        on_delete=models.CASCADE,
        related_name="flaw_mappings",
    )
    notes = models.TextField(blank=True)

    class Meta:
        verbose_name = "Flaw Upstream Mapping"
        verbose_name_plural = "Flaw Upstream Mappings"

    def __str__(self):
        return f"{self.flaw} -> {self.upstream_project}"
