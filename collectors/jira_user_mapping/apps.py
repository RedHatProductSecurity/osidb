"""
Collector for Jira user mapping data
"""

from django.apps import AppConfig


class JiraUserMappingCollector(AppConfig):
    name = "collectors.jira_user_mapping"
