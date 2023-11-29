import logging
import re
from io import BytesIO
from typing import Dict, List, Tuple, Union

import feedparser
import requests
import yaml
from django.conf import settings
from django.utils import timezone
from feedparser import FeedParserDict
from requests.exceptions import RequestException

from collectors.framework.models import Collector
from osidb.core import set_user_acls
from osidb.models import Snippet

from ..keywords import check_keywords
from .constants import FEEDS_FILE, REQUEST_TIMEOUT
from .utils import find_cves, find_cvss, find_cwes, html_to_text

logger = logging.getLogger(__name__)


###############################################################################
#
#
#       8888888 8888888888 ,o888888o.     8 888888888o.          ,o888888o.
#             8 8888    . 8888     `88.   8 8888    `^888.    . 8888     `88.
#             8 8888   ,8 8888       `8b  8 8888        `88. ,8 8888       `8b
#             8 8888   88 8888        `8b 8 8888         `88 88 8888        `8b
#             8 8888   88 8888         88 8 8888          88 88 8888         88
#             8 8888   88 8888         88 8 8888          88 88 8888         88
#             8 8888   88 8888        ,8P 8 8888         ,88 88 8888        ,8P
#             8 8888   `8 8888       ,8P  8 8888        ,88' `8 8888       ,8P
#             8 8888    ` 8888     ,88'   8 8888    ,o88P'    ` 8888     ,88'
#             8 8888       `8888888P'     8 888888888P'          `8888888P'
#
#
# * TODO: Replace elinks with a Python-native solution if you don't want the
#         added complexity of installing elinks into the container image.
#         A possible approach is to use what's described in OSIDB-1454.
#
# * TODO: Pass new Snippets to Snippet.convert_snippet_to_flaws().
#         See PR 388 for details.
#
# * TODO: Pass only those Snippets for conversion that have "create_flaws": True.
#         The Snippet creation machinery just creates everything, but the
#         "create_flaws": False snippets are just for internal bookkeeping.
#
# * TODO: Eliminate "create_flaws" field from the Snippet contents. The Snippet
#         creation machinery ignores it anyway, so it's not necessary to waste
#         space storing it.
#
# * TODO: Change the structure of Snippet contents based on current practices
#         in other uses of Snippet. E.g. how CVSS is structured.
#
# * TODO: Generate one Snippet per CVE. So if a feed entry contains three CVEs,
#         create three almost identical Snippets, each differing in just the CVE.
#
# * NOTE: These TODOs have been left in in order to not waste time on an
#         approach that turned out to be probably not necessary anymore at the
#         last moment.
#
###############################################################################


class ConfigurationAdapter:
    def get_config(self):
        raise NotImplementedError


class ConfigFile(ConfigurationAdapter):
    def get_config(self):
        with open(FEEDS_FILE) as f:
            feed_data = yaml.safe_load(f)
        return feed_data


class ConfigDict(ConfigurationAdapter):
    def __init__(self, config):
        self.config = config

    def get_config(self):
        return self.config


class FeedCollector(Collector):
    """
    Feed collector
    """

    def __init__(self, configuration_adapter=None):
        """
        Initialize the Collector with a particular configuration adapter.
        If a configuration adapter is not provided, ConfigFile is used.
        """
        if configuration_adapter:
            self.configuration_adapter = configuration_adapter
        else:
            self.configuration_adapter = ConfigFile()
        super().__init__()

    def collect(self) -> str:
        """
        collector run handler

        on every run the configured feed entries are fetched and saved to snippets
        """

        # set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

        logger.info("Fetching new feeds")
        start_dt = timezone.now()

        feed_data = self.configuration_adapter.get_config()

        total, allowed = 0, 0
        for single_feed in feed_data:
            incr_total, incr_allowed = self.collect_feed(single_feed)
            total += incr_total
            allowed += incr_allowed

        self.store(updated_until_dt=start_dt)

        msg = f"{self.name} is updated until {start_dt}."
        msg += f" Total new Feed entries fetched: {total}"
        msg += f" Allowed new Feed entries fetched: {allowed}"

        logger.info("Feed sync finished.")
        return msg

    @staticmethod
    def collect_feed(feed_data: dict) -> Tuple[int, int]:
        """Scrape a particular feed."""

        feed_name = feed_data["name"]
        url = feed_data["url"]
        entry_url_replace = feed_data.get("entry_url_replace", [])
        entry_separate_links = feed_data.get("entry_separate_links")
        skip_entry_title_regex = feed_data.get("skip_entry_title_regex")
        entry_text_in_html = feed_data.get("entry_text_in_html")
        components = feed_data.get("components", [])

        raw_feed_entries = FeedCollector.fetch_new_feed_entries(url, feed_name)

        pruned_raw_feed_entries = FeedCollector.prune_new_raw_feed_entries(
            raw_feed_entries, skip_entry_title_regex
        )

        raw_entries_w_summaries = FeedCollector.get_summaries_for_raw_feed_entries(
            pruned_raw_feed_entries,
            entry_url_replace,
            entry_separate_links,
            entry_text_in_html,
        )

        filtered_raw_entries_w_summaries = (
            FeedCollector.filter_feed_entries_with_summaries(raw_entries_w_summaries)
        )

        content_dicts_for_allowed_snippets = (
            FeedCollector.prepare_data_for_eligible_feed_entries(
                filtered_raw_entries_w_summaries, components
            )
        )

        all_urls = set()
        for entry in raw_feed_entries:
            all_urls.add(entry.link)

        allowed_snippet_urls = set()
        for content in content_dicts_for_allowed_snippets:
            allowed_snippet_urls.add(content["url"])
            new_snippet = Snippet(
                source=feed_name,
                content=content,
            )
            logger.info(
                "Creating allowed Snippet: %s", repr(new_snippet.content["url"])
            )
            logger.debug("new allowed Snippet data: %s", repr(new_snippet.__dict__))
            # Save separately so that log shows the context if it fails.
            new_snippet.save()

        # Prevent reprocessing (or fetching) the same entries in future Collector runs.
        new_blocked_snippet_urls = all_urls - allowed_snippet_urls
        for url in new_blocked_snippet_urls:
            content = {
                "url": url,
                "create_flaws": False,
            }
            new_snippet = Snippet(
                source=feed_name,
                content=content,
            )
            logger.info(
                "Creating blocked Snippet: %s", repr(new_snippet.content["url"])
            )
            logger.debug("new blocked Snippet data: %s", repr(new_snippet.__dict__))
            new_snippet.save()

        return len(all_urls), len(allowed_snippet_urls)

    @staticmethod
    def fetch_new_feed_entries(url: str, feed_name: str) -> List[FeedParserDict]:
        """Find new entries in a feed (those that are not already stored in DB)."""
        try:
            # Use requests to pull feeds because `feedparser.parse` does not have a timeout option.
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except RequestException as exc:
            logger.error("Failed to pull feeds for %s: %s", url, exc)
            return []

        content = BytesIO(response.content)
        feed = feedparser.parse(content)

        if not feed.entries:
            logger.error("No feed entries in feed %s", url)
            return []

        fetched_entry_urls = [entry.link for entry in feed.entries]

        # Note that this limits the query to the fetched URLs, not the other way around.
        # This way, the "in" operator always works with a list of a limited size and
        # the resulting list always has limited size.
        # We can't control how long history a feed provides, hence no time-based filtering.
        known_feed_entries = (
            Snippet.objects.values_list("content__url", flat=True)
            .filter(source=feed_name)
            .filter(content__url__in=fetched_entry_urls)
        )

        new_feed_entries = [
            entry for entry in feed.entries if entry.link not in known_feed_entries
        ]
        return new_feed_entries

    @staticmethod
    def prune_new_raw_feed_entries(
        raw_feed_entries: List[FeedParserDict], skip_entry_title_regex: Union[str, None]
    ) -> List[FeedParserDict]:
        """Throw away feed entries that should be skipped based on special rules."""

        ret = []
        for entry in raw_feed_entries:
            # Ignore all RHSAs
            if "Red Hat Security Advisory" in entry.title:
                continue

            # Per-feed special rules
            if skip_entry_title_regex and re.search(
                skip_entry_title_regex, entry.title
            ):
                continue

            ret.append(entry)
        return ret

    @staticmethod
    def get_summaries_for_raw_feed_entries(
        pruned_raw_feed_entries: List[FeedParserDict],
        entry_url_replace: List[List[str]],
        entry_separate_links: Union[bool, None],
        entry_text_in_html: Union[bool, None],
    ) -> List[Tuple[FeedParserDict, Union[str, None]]]:
        """Get plain text summaries for feed entries."""

        ret = []
        for entry in pruned_raw_feed_entries:
            text = None
            if entry_separate_links:
                text = FeedCollector.get_linked_text(
                    entry.link, entry_url_replace, entry_separate_links
                )
            elif "summary" in entry:
                text = entry.summary.strip()
            else:
                logger.info(
                    "Failed (no summary) to get feed text entry for: %s",
                    entry.link,
                )
            if text and entry_text_in_html:
                try:
                    text = html_to_text(text).strip()
                except Exception:
                    logger.exception(
                        "Failed (html conversion error) to get feed entry text for: %s",
                        entry.link,
                    )
            ret.append((entry, text))
        return ret

    @staticmethod
    def filter_feed_entries_with_summaries(
        raw_entries_w_summaries: List[Tuple[FeedParserDict, Union[str, None]]]
    ) -> List[Tuple[FeedParserDict, Union[str, None]]]:
        """Throw away feed entries that should be skipped based on general blocklist-based filtering."""

        ret = []
        for entry, text in raw_entries_w_summaries:
            text = "" if not text else text
            blocklist, allowlist = check_keywords(entry.title + " " + text)
            if blocklist and not allowlist:
                logger.info(
                    "Skipping feed entry (%s) because of blocklist keywords (%s).",
                    entry.title,
                    "; ".join(blocklist),
                )
                continue
            ret.append((entry, text))
        return ret

    @staticmethod
    def prepare_data_for_eligible_feed_entries(
        filtered_raw_entries_w_summaries: List[Tuple[FeedParserDict, Union[str, None]]],
        components: List[str],
    ) -> List[Dict]:
        """Get data for new entries for a particular feed and return FeedEntry instances."""

        content_dicts_for_snippets = []
        for entry, text in filtered_raw_entries_w_summaries:

            if not text:
                logger.info("Skipping feed entry: %s", entry.link)
                continue

            cves = find_cves(entry.title + text)
            cwes = find_cwes(entry.title + text)
            rh_format_cvss = find_cvss(text)

            content = {
                "cve_ids": cves,
                "title": entry.title,
                "description": text.strip(),
                "cwe_id": cwes,
                "references": [  # For use of a Snippet processor
                    {
                        "url": entry.link,
                        "type": "SOURCE",
                    }
                ],
                "url": entry.link,  # For use of the FeedCollector, for ease of filtering.
                "components": components,
                "create_flaws": True,
            }
            if rh_format_cvss:
                # The reasons for first creating RH-formatted CVSSv3 only to reformat it here are:
                # - The original code and tests used RH formatting.
                # - The non-RH formatting is a new experiment with Snippets that might change (or not),
                #   hence refactoring not worthwhile.
                (
                    snippet_format_cvss_score,
                    snippet_format_cvss_vector,
                ) = rh_format_cvss.split("/", 1)
                content["cvss3"] = {
                    "score": snippet_format_cvss_score,
                    "vector": snippet_format_cvss_vector,
                    # "issuer": unknown!
                }

            content_dicts_for_snippets.append(content)

        return content_dicts_for_snippets

    @staticmethod
    def get_linked_text(
        entry_url: str,
        entry_url_replace: List[List[str]],
        entry_separate_links: Union[bool, None],
    ) -> Union[str, None]:
        """
        Gets summary of a particular feed entry. The method depends on the feed specifics.
        Error-inducing feed entries are skipped without retry.
        """

        text = None
        try:
            if entry_separate_links:
                if entry_url_replace:
                    for pair in entry_url_replace:
                        entry_url = entry_url.replace(pair[0], pair[1])
                try:
                    response = requests.get(entry_url, timeout=REQUEST_TIMEOUT)
                    response.raise_for_status()
                    text = response.text
                except RequestException as exc:
                    logger.error("Error when requesting %s: %s", entry_url, exc)
            else:
                logger.error(
                    "Feed entry URL not configured for fetching via entry_separate_links: %s",
                    entry_url,
                )
        except Exception:
            logger.exception(
                "Failed (download error) to get feed entry text for: %s",
                entry_url,
            )
        return text
