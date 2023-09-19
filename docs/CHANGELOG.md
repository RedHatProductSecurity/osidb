# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Implement collector for ps-constants project (OSIDB-1199)
- Validate summary and requires_summary (OSIDB-1164)
- Validate impact and summary (OSIDB-1164)
- Implement tracker description generation (OSIDB-1173)
- Implement endpoint for suggesting trackers to file (OSIDB-90)
- Add shipped date to erratum model (OSIDB-1197)
- Flaw creation and update triggers a Jira task sync (OSIDB-861)
- Config gunicorn access log file depending on environment (OSIDB-879)
- Link tracker to flaw(s) on create/update (OSIDB-1182)
- Implement FlawCVSS and AffectCVSS APIs with filters (OSIDB-1105)
- Implement package_versions API (OSIDB-1066)
- is_up2date to collector status API (OSIDB-1328)
- Implement flaw filtering based on erratum id in API (OSIDB-1330)
- Implement filters for flaw references in API (OSIDB-1368)
- Reactivate OSIM module unit tests (OSIDB-1320)

### Changed
- Deprecate various cvss fields in Flaw and Affect APIs (OSIDB-1105)

### Fixed
- Fix schema wrongly showing status code for DELETE methods being 204
  whereas the actual returned status code is 200

### Removed
- Remove the Django admin interface (OSIDB-1188)

## [3.4.2] - 2023-08-31
### Changed
- Reduce the total amount of records per page when querying Bugzilla (OSIDB-1232)
- Set AFFECTED as highest precedence resolution when calculating Affect.delegated_resolution (OSIDB-1230)

## [3.4.1] - 2023-08-21
### Changed
- Fix FlawCollector to account for an empty acknowledgment affiliation (OSIDB-1195)

## [3.4.0] - 2023-08-14
### Added
- Implement major_incident_state in Flaw API (OSIDB-266)
- Implement a new FlawAcknowledgment API (OSIDB-1002)
- Implement requires_summary in Flaw API (OSIDB-1005)
- Implement ps_update_stream in Tracker API (OSIDB-1064)
- Implement daily monitoring email for failed tasks / collectors
- Implement nist_cvss_validation in Flaw API (OSIDB-1006)
- Implement additional tracker validations (OSIDB-787)
- Validate NIST RH CVSS feedback loop (OSIDB-334)
- Validate nist_cvss_validation and cvss_scores (OSIDB-1165)
- Implement tracker summary generation (OSIDB-1172)

### Changed
- Change article link validation to be blocking (OSIDB-1060)
- Deprecate the "is_major_incident" field in Flaw (OSIDB-1103)
- Change CORS policy to allow credentials (OSIDB-1115)
- Validate MI and CISA MI separately (OSIDB-1104)
- Fix auto-timestamp issues (OSIDB-1171)

## [3.3.0] - 2023-06-28
### Added
- Implement a new FlawReference API (OSIDB-71)
- Implement adding new flaw comments (OSIDB-81)
- Erratum advisory name to flaw filter (OSIDB-922)
- CORS allow-list functionality (OSIDB-967, OSIDB-965)
- Raw bugzilla summary to Flaw.meta_attr (OSIDB-1016)

### Changed
- Set Jira trackers as public instead of embargoed when private (OSIDB-1013)

## [3.2.2] - 2023-06-19
### Changed
- Account for TRIAGE in the title/summary (OSIDB-999)

## [3.2.1] - 2023-06-12
### Changed
- Fix creation of references on flaw ingestion from Bugzilla

## [3.2.0] - 2023-06-05
### Added
- Introduce flaw ownership through task management system (OSIDB-69)
- Implement task rejection in Taskman (OSIDB-74)
- Implement article validation for Major Incident flaw (OSIDB-655)
- Implement mitigation validation for Major Incident flaw (OSIDB-656)
- Implement statement validation for Major Incident flaw (OSIDB-657)
- Introduce new module for creating trackers in Jira (OSIDB-93)
- Introduce aditional metadata in tasks generated from Taskman (OSIDB-861)

### Changed
- Integrate Jira tracker collector with collector framework (OSIDB-576)
- Make CVSSv3 score mandatory no more (OSIDB-901)
- Make Bugzilla collector aware of migration of old style acks to SRT notes (OSIDB-904)
- Fix BBSync flaw summary composition (OSIDB-902, OSIDB-909)
- Fix Bugzilla import not reflecting some attribute removals (OSIDB-910)
- Make flaw Bugzilla children entities respect flaw visibility (OSIDB-914)

## [3.1.4] - 2023-05-22
### Changed
- Git revision information on each request is fault-tolerant

## [3.1.3] - 2023-05-08
### Added
- Retry mechanism for bzimport collector

## [3.1.2] - 2023-04-27
### Changed
- General performance improvements

## [3.1.1] - 2023-04-17
### Changed
- Fix Jira tracker collection bug (OSIDB-848)

## [3.1.0] - 2023-04-12
### Added
- Introduce mitigation field into Flaw and update SRT notes generator (OSIDB-584)
- Introduce flaw component attribute
- Implement validation for allowed flaw sources (OSIDB-73)
- Implement task management module (Taskman) to keep and update task workflow in Jira (OSIDB-228, OSIDB-684, OSIDB-685, OSIDB-754)
- Expose task management module (Taskman) REST API (OSIDB-811)
- More granular filtering for Flaw, Affect and Tracker API endpoints (OSIDB-667)
- Ordering (ascending/descending) for Flaw, Affect and Tracker API endpoints (OSIDB-668)
- Implement proper NVD CVSS score collector (OSIDB-632)

### Changed
- Rework the mapping from Bugzilla sumary to OSIDB title and vice versa (OSIDB-694)
- Allow updates of flaws with multiple CVE IDs in Bugzilla (OSIDB-382)
- Deprecate "state" and "resolution" in Flaw (OSIDB-73)
- Increase the maximum length of "cwe_id" field in Flaw to 255 (OSIDB-73)
- Make API requests transactional (OSIDB-232)
- Rename REQUIRES_DOC_TEXT to REQUIRES_SUMMARY in FlawMeta (OSIDB-73)
- Minimize mid-air collisions (OSIDB-765)
- API delete methods now returns HTTP 200 status instead of 204
  upon succesful delete

### Removed
- Remove "state" and "resolution" from FlawHistory (OSIDB-73)

## [3.0.0] - 2023-03-21
### Added
- Implement Bugzilla SRT notes builder in Bugzilla Backwards Sync (OSIDB-384)
- Implement validation for flaw without affect (OSIDB-353)
- Implement validation for changes in flaws with high criticicity with open tracker (OSIDB-347)
- Implement validation for components affected by flaws closed as NOTABUG (OSIDB-363)
- Implement validation for invalid components in software collection (OSIDB-356)
- Implement Bugzilla metadata collector
- Implement validation for services related products with WONTREPORT resolution (OSIDB-362)
- Implement validation for combinations of affectedness and resolution (OSIDB-360)
- Implement a new API for getting a list of all supported products (PSINSIGHTS-593)
- Implement CC list builder in Bugzilla backwards sync (OSIDB-386)
- Implement validation for affects with exceptional combination of affectedness and resolution (OSIDB-361)
- Implement validation for affects marked as WONTFIX or NOTAFFECTED with open trackers (OSIDB-364)
- Implement validation for affected special handled modules without summary or statement (OSIDB-328)
- Implement validation for flaws with private source without ACK (OSIDB-339)
- Implement validation for unknown component (OSIDB-355)
- Implement temporary NVD collector (OSIDB-632)
- Implement Exploits report data API endpoint (PSINSIGHTS-764)
- Implement ACL validations (OSIDB-691)
- Implement non-empty impact validation (OSIDB-758)
- Integrate Bugzilla backwards sync into the flaw and affect save (OSIDB-240)
- Introduce Bugzilla API key as a serializer attribute (OSIDB-368)
- Implement non-empty source validation (OSIDB-759)
- Local development instance is now able to switch between stage and production easily via env variables

### Changed
- Change logging of celery and django to filesystem (OSIDB-418)
- Implement validation for CWE ID chain in a Flaw (OSIDB-357)
- Implement validation for embargoed flaws not be able to have public trackers (OSIDB-350)
- Fix Jira tracker created and updated timestamps (OSIDB-14)
- Fix errata created and updated timestamps (OSIDB-453)
- Restrict write operations on placeholder flaws (OSIDB-388)
- Avoid recreating flaws on CVE ID changes whenever possible (OSIDB-392)
- Remove unsused data prestage_eligible_date from schemas (OSIDB-695)
- Revise the allowed API view HTTP methods on models
  restricting flaw deletion and all tracker write methods (OSIDB-748)
- Bugzilla API key is send via Bugzilla-Api-Key HTTP header

### Removed
- Remove deprecated mitigated_by field (OSIDB-753)

## [2.3.4] - 2022-12-15
### Changed
- Make sure the unacked PS update stream is always linked to PS module (OSIDB-637)

## [2.3.3] - 2022-12-13
### Changed
- Link unacked PS update stream to PS module on product definitions sync (OSIDB-629)
- Increase PS component name length from 100 to 255 characters (OSIDB-635)

## [2.3.2] - 2022-11-28
### Changed
- Catch tracker sync exceptions individually (OSIDB-580)

### Added
- Implement complete Bugzilla groups handling in Bugzilla Backwards Sync (OSIDB-387)
- Support (CISA) Major Incident label in tracker description (OSIDB-579)

## [2.3.1] - 2022-10-25
### Changed
- Fix Errata collector saving to handle advisory name change (OSIDB-565)

## [2.3.O] - 2022-10-24
### Changed
- Fix Errata collector design to periodically refresh data (OSIDB-433)
- Flaw mitigated_by field is now deprecated and will be completely removed
  in the next major release (OSIDB-126)
- Fix component matching from tracker description (OSIDB-464)
- Store FlawMeta alerts on FlawMeta instead of on Flaw
- Prevent pgtrigger recreating triggers (OSIDB-429)

### Added
- Helper for manual flaw synchronization (OSIDB-389)
- Usage of django-deprecate-fields package for model field deprecation (OSIDB-126)

## [2.2.2] - 2022-09-20
### Changed
- Fix an issue with FlawSource validation for sources that can be both
  public and private (OSIDB-450)

## [2.2.1] - 2022-09-07
### Changed
- Fix an issue with CVSSv3 validation that was preventing some flaws from
  being synchronized in OSIDB (OSIDB-426, OSIDB-427)

## [2.2.0] - 2022-09-05
### Changed
- Authentication is no longer compulsory for read-only requests against the
  main OSIDB endpoints such as /flaws, /affects and /trackers (OSIDB-313)
- Fix an issue in which the Jiraffe collector was calling Tracker.affect
  instead of Tracker.affects (ManyToMany field) which resulted in some
  failed JIRA tracker synchronizations.
- Treat collector failures due to already running collectors or due to
  waiting for dependencies as celery Retry exceptions.
- OSIDB now uses publicly available images from docker.io (OSIDB-170)
- fix bug that Major Incident can be unset by unrelated BZ flag (OSIDB-416)
- CISA collector to run hourly rather than daily (PSINSIGHTS-635)

### Added
- support for CVE-less flaws (OSIDB-25)
- unified logging across the whole OSIDB
- validate hightouch and hightouch-lite flag value combinations (OSIDB-329)
- validate differences between Red Hat and NVD CVSS score and severity (OSIDB-333)
- validate that embargoed flaws do not have public sources (OSIDB-337)
- validate that flaws from public sources don't contain ack FlawMetas (OSIDB-338)
- `AlertMixin` for the creation of easily-serializable alerts on a per-record
  basis for any model that inherits from said mixin (OSIDB-324)
- validate that an Affect's `ps_module` exists in product definitions (OSIDB-342)
- EPSS data API for Red Hat vulnerabilities (PSINSIGHTS-636)

## [2.1.0] - 2022-08-02
### Changed
- disable krb5 log redirection in stage and production playbooks.
- disable opportunistic_auth when contacting Errata Tool and removed
  the authentication call from the constants file which meant that
  ET authentication would happen every time the code was loaded, generating
  a lot of auth calls and logs.
- change the way that data is synchronized to be more fault-tolerant,
  things like tracker fetching will no longer make the entire flaw
  sync fail.
- fix a bug where only certain metadata were being correctly synchronized
  between BZ and OSIDB which resulted in things like typos in acknowledgments
  persisting in OSIDB despite being removed from BZ.
- fix a bug in which the scheme in next/previous links in paginated
  responses was http:// and not https://.
- fix a bug with the way that the collector framework parsed crontab
  strings.
- fix various bugs with the collector framework instantiation process.
- fix a bug with the way that collector dependencies were being handled.
- fix a bug in which FlawMeta were not being updated correctly due to
  an ACL issue.
- update product exclusion lists.
- fix a bug in which the exploit collectors were not working properly
  due to an ACL issue.
- fix an issue with duplicate affects generating database errors.

### Added
- add various Dockerfile optimizations.
- add API for exploit report processing.
- add a mechanism to reflect CVE changes and/or removals.

### Removed
- remove audit mechanisms and tables from main models.
- remove obsoleted bzload.py script.
- remove outdated service schema.
- remove obsoleted funcspec.
- remove prodsec lib dependency.

## [2.0.3] - 2022-06-16
### Changed
- fix an issue with existing FlawMeta objects not being updated if the
  parent Flaw was itself updated, meaning that FlawMeta could be kept
  as embargoed if the Flaw was unembargoed.

## [2.0.2] - 2022-06-14
### Changed
- fix a change that broke backwards compatibility with IRD, this fix reverts
  the changes to the empty value of enumerations from "" back to "NONE",
  only IRD clients should be affected.

## [2.0.1] - 2022-06-03
### Changed
- fix an issue with objects not being saved to the database due to a bad
  interaction between FlawSaver and TrackerBugConvertor (OSIDB-142)

## [2.0.0] - 2022-06-01
### Added
- add tracker timestamps (OSIDB-62)
- provide erratum ID on API together with advisory ID (OSIDB-128)
- create flaw draft (OSIDB-68)
- API for Insights Vulnerability application (PSINSIGHTS-608)

### Changed
- start using the "Keep a Changelog" format for the CHANGELOG.md
- reviewed and unified the database fields accross all the models (OSIDB-16)
- fix and unify creation and modification timestamps handling (OSIDB-62, OSIDB-82)
- major Bugzilla collection reliability rework (OSIDB-17, OSIDB-130)
- ignore and remove testing Bugzilla bugs (OSIDB-111)
- reflect related entity removal on flaw sync (OSIDB-78)
- improve flaw source handling (OSIDB-61)

### Removed
- remove Flawzilla testing app (OSIDB-18)
- remove old collector APIs (OSIDB-20)

## [1.2.1] - 2022-05-23
### Changed

- ensure API ordering is reproducible - fixes pagination issue (OSIDB-133)

## [1.2.0] - 2022-05-02
### Added
- add /osidb/whoami endpoint to expose currently logged in user information
- add /affects, /trackers endpoints and allow CRUD operations
- add collector for Errata Tool IDs and expose "errata that fix this tracker"
- track OSIDB users' bugzilla and jira usernames

### Changed
- unify metadata across all api responses
- fix Bugzilla flag syncing causing Major Incident update issues (PSDEVOPS-3406)
- fix collector ACLs causing unembargo staleness (PSDEVOPS-3449)
- fix flaw source typos causing minor sync issues (PSDEVOPS-3373)

### Removed
- remove status metadata from responses

## [1.1.2] - 2022-04-06
### Added
- add CPaaS pipeline credential mapping (PSDEVOPS-2569)

### Changed
- update version to 1.1.2
- apply correct update/create dates to flaws, affects, and trackers (PSDEVOPS-3365)
- move DEVELOP.md and TUTORIAL.md to docs directory

## [1.1.1] - 2022-03-29
### Changed
- update version to 1.1.1
- do not pass uuid as groups to set_user_acls

## [1.1.0] - 2022-03-28
### Added
- add update schema step to OSIDB release docs
- add schema extension for custom auth class
- add exploit collectors (PSINSIGHTS-538, PSINSIGHTS-541)
- implement more granular LDAP control groups (PSDEVOPS-2664)
- implement Product Definitions collector
- add tracker QE owner attribute (PSDEVOPS-3219)
- implement read-only mode and enable for prod (PSDEVOPS-3203)

### Changed
- raise OSIDB version to 1.1.0
- update documentation regarding LDAP groups
- increase osidb-service route timeout from 30s to 300s
- update django version to fix known vulnerabilities
- validate peer cert chain and hostname for LDAP connections
- allow bzimport to import testing embargoed data to stage
- provide redis credentials and certificates for osidb-service

## [1.0.0] - 2022-02-23
### Added
- implement kerberos authentication via SPNEGO protocol
- document OSIDB versioning
- add sections about more advanced Flaw queries in tutorial
- implement collector framework API
- implement example collector
- implement collector framework

### Changed
- update version to 1.0.0
- enable krb5_auth in stage
- fix CVSS string storing
- migrate from DRF tokens to JWT for auth (PSDEVOPS-3140)
- load Bugzilla dates as timezone aware
- use osidb-service image for flower instead of dockerhub image
- secure redis instance by enabling TLS (PSDEVOPS-3128)
- secure redis instance with basic authentication (PSDEVOPS-3128)
- enable TLS endpoint verification in ansible playbooks (PSDEVOPS-3110)
- improve flaws endpoint performance for cve_id and change_after params (PSDEVOPS-3209)
- refactor URLs and the landing page
- fix changed_after and changed_before filters
- fix or refactor attribute validations
- fix schema definition
- accommodate flawdb->osidb rename in openshift
- fix OSIDB name on the main page
- modify tracker_ids query param to filter out non relevant affects
- update query parameters description in API schema
- update LDAP groups docs

### Removed
- turn off CWE validation as it is too simple
- deprecate Basic and Session auth for API endpoints (PSDEVOPS-3126)

## [0.0.2] - 2022-01-21
### Changed
- update version to 0.0.2
- enable service accounts in prod

## [0.0.1] - 2022-01-21
### Added
- this is the initial OSIDB version
- see git repo for the older changes

<!-- TODO: Add links to version comparisons -->
