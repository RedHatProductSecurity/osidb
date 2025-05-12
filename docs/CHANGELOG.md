# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Add CISA CVSSIssuer type (OSIDB-4203)
- Ignore modification of non-Red Hat issued CVSS scores through API

## [4.10.1] - 2025-04-30
### Added
- Add feedback form to tracker description (OSIDB-4095)

### Changed
- Adjust ACLs upon workflow advancement in OSIDB and do not wait for Jira sync (OSIDB-4136)

### Fixed
- Postpone Jira task download when there are sync or transition managers pending (OSIDB-4136)
- Consider affect in AFFECTED/DELEGATED state as not resolved (OSIDB-4137)
- Fix missing include_history field on Affect and Flaw API documentation (OSIDB-3960)
- Remove redundant Flaw workflow update (OSIDB-4136)

## [4.10.0] - 2025-03-25
### Fixed
- Make task_key read-only (OSIDB-4080)
- Split Requests/Responses in API schema
- Flaw Jira Tasks changes are now fetched based on history to
  avoid Flaw data reset (OSIDB-4015)

### Changed
- Migrate user ids on history Audit models to user emails or usernames (OSIDB-3988)

## [4.9.1] - 2025-03-10
### Fixed
- Prefix PURL-derived ps_components with path in some cases (OSIDB-4071)

## [4.9.0] - 2025-03-10
### Added
- Extend tracker model with resolved date (OSIDB-4064)
- Extend tracker model with special handling (OSIDB-4065)

### Fixed
- Affect resolved_dt marked correctly as nullable in API schema

## [4.8.0] - 2025-03-03
### Added
- Add not affected justification field to affects (OSIDB-3809)
- Add not affected justification field to trackers (OSIDB-3808)
- Add delegated not affected justification field to affect (OSIDB-3810)
- Add resolved_dt to affect model (OSIDB-4058)
- Map user name or email to flaw audit history entries (OSIDB-3464)

### Changed
- Remove time information when validating embargoed flaws (OSIDB-3862)
- The "Obsolete" tracker resolution is now treated as "Not affected" to allow its use for erroneously filed trackers
- Shift Jira Task collector batch window 1 minute in the past (OSIDB-4068)

### Fixed
- Fix CVSS data parsing in NVD collector (OSIDB-4003)
- Handle delete of last affect when updating flaw collaborators (OSIDB-3986)
- Propagate Jira errors to the user (OSIDB-3939)

### Removed
- Remove flaw impact adjustment from NVD collector (OSIDB-3678)

## [4.7.2] - 2025-01-31
### Changed
- Skip non-migrated Bugzilla tracker sync (OSIDB-3966)

## [4.7.1] - 2025-01-30
### Fixed
- Filter out empty events from history API resutls (OSIDB-3942)
- Make Jira task collector to write only necessary attributes to prevent mid-air collisions (OSIDB-3636)

## [4.7.0] - 2025-01-28
### Added
- Add SLA exclusion policies (OSIDB-3711)
- Implement 'in' operator in SLA conditions (OSIDB-3711)
- Enable async Jira task sync and transition (OSIDB-3693)
- Add collaboration labels on flaw promotion (OSIDB-3804)
- Add basic end-to-end tests for Flaws, Affects and Trackers (OSIDB-3495)
- Allow searching by flaw labels (OSIDB-3816)

### Changed
- Removed `last_validated_dt` from exposed JSON Flaw History data (OSIDB-3814), handled edge-case that would cause failure (OSIDB-3858)
- Trim Jira task summary if flaw's `cve_id` and `title` are too long (OSIDB-3847)
- Validate that a flaw has an impact set and RH CVSSv3 score is non-zero,
  or it does not have an impact set and RH CVSSv3 score is zero (OSIDB-3738)

### Fixed
- Set emtpy SLA dates explicitly (OSIDB-3943)

## [4.6.5] - 2025-01-10
### Changed
- Revert pull request #875 from OSIDB-3814

## [4.6.4] - 2025-01-10
### Changed
- Moved docker-compose images from docker.io to mirror.gcr.io (OSIDB-3653)
- Removed `last_validated_dt` from exposed JSON Flaw History data (OSIDB-3814)

## [4.6.3] - 2025-01-09
### Fixed
- Reduce flaw save operations to avoid outdated timestamps (OSIDB-3837)

## [4.6.2] - 2025-01-08
### Added
- Introduce new field "labels" in Flaw API (OSIDB-3803)

### Changed
- Use keywords from ps-constants in CVEorg collector (OSIDB-3694)
- External references are synced to Jira trackers (OSIDB-3733)
- Make flaw audit history public on embargoed flaws (OSIDB-3463)

### Fixed
- Fix workflow validation with conditional requirements (OSIDB-3524)

## [4.6.1] - 2024-12-06
### Fixed
- Fix not enough general CVE Severity/Severity error fallback (OSIDB-3767)

## [4.6.0] - 2024-12-02
### Added
- Update field `updated_dt` on queryset update (OSIDB-3573)
- Introduce purl to Affect (OSIDB-3409)
- Implement field `embargoed` for advanced search (OSIDB-3549)
- Implement no-week-ending SLA policy support (OSIDB-3500)
- Implement complex logic in workflow state requirements (OSIDB-3524)
- Validate and set ps_component from purl (OSIDB-3410)
- Set Jira Severity and maintain the transition from CVE Severity (OSIDB-3697)

### Changed
- Add history to several other models: AffectCVSS, FlawAcknowledgment, FlawComment,
  FlawCVSS, FlawReference, Snippet and Tracker. (OSIDB-3466)
- Moved metadata creation during tests to root level conftest and
  automatically set envs during VCR recording (OSIDB-3492)
- Exclude component and version from Jira tracker updates (OSIDB-3677)
- Allow moving a flaw to state DONE if it has no trackers but impact is moderate
  or low (OSIDB-3524)
- Set hard limit of paginated results (OSIDB-643)
- Add all references as links when creating Jira trackers (OSIDB-3733)
- Set security level together with embargo status (OSIDB-3598)

### Removed
- Remove UBI handler special treatment (OSIDB-3728)

## [4.5.6] - 2024-11-08
### Fixed
- Properly save updated flaw in NVD collector (OSIDB-3661)

## [4.5.5] - 2024-11-07
### Changed
- Publish internal flaws only when the triage is completed (OSIDB-3669)
- Adjust the NIST flag instead of removing on NIST score deletion
  and relieve the NIST flag validation to account for it (OSIDB-3672)
- Adjust flaw impact if NIST CVSS is changed (OSIDB-3661)

## [4.5.4] - 2024-11-06
### Changed
- Moved envs monkeypatches to root conftest for reusability (OSIDB-3491)

### Fixed
- Fix conversion of CVSS severity to impact (OSIDB-3661)
- Ignore invalid CVSS from OSV collector (OSIDB-3663)

## [4.5.3] - 2024-11-05
### Added
- Implement resolution steps for duplicate tracker validation (OSIDB-3588)

### Changed
- Add upstream references to Jira trackers on creation (OSIDB-3148)
- Change ACL mixin serializer to support internal ACLs (OSIDB-3578)
- Make product definitions collector atomic (OSIDB-3590)
- Validate that the CVSSv3 score is zero for flaws with impact "None" (OSIDB-3581)

## [4.5.2] - 2024-10-24
### Changed
- Reduced count of requests to Jira for task management

## [4.5.1] - 2024-10-23
### Added
- Implement validation of PS module and PS update stream correspondance (OSIDB-3584)

### Changed
- Avoid tracker creation conflicts by async tracker sync (OSIDB-3593)
- Skip flaws with CVE ID in OSV collector (OSIDB-3351)

### Fixed
- Fix Bugzilla flaw summary exceeding (OSIDB-3551)

## [4.5.0] - 2024-10-22
### Added
- Add new flaw reference type "UPSTREAM"

### Changed
- Check title for keywords in CVEorg collector (OSIDB-3545)
- Update delegated resolution mapping so low impact won't fix
  changes to fix deferred (OSIDB-3575)

### Fixed
- ValidationError constraint “unique_external_system_id” during tracker filing (OSIDB-3589)

## [4.4.1] - 2024-10-17
### Added
- Auto-reset CVSS validation flag on NVD CVSS removal (OSIDB-3407)

### Changed
- Restrict tracker file offer by ProdSec support instead of general one (OSIDB-3559)

### Fixed
- Do not add private tracker CC to flaws (OSIDB-3558)

## [4.4.0] - 2024-10-11
### Added
- Introduce moderate tracker streams pre-selection (OSIDB-3346)
- Introduce minor and 0-day incident types (OSIDB-3390)
- Collect CVSSv4 in OSV collector (OSIDB-3487)
- Set Impact for collector flaws based on CVSS severity (OSIDB-3487)

### Changed
- Disable flaw drafts creation for NVD collector (OSIDB-3256)
- Select most relevant CVE, CVSS, CWE, Source for Vulnerability trackers (OSIDB-3348)
- Tracker validations show affect's module/component (OSIDB-3439)

### Fixed
- Rework and complete the tracker stream pre-selection module to fix it
- Exclude unsupported PS modules from tracker file offer (OSIDB-3498)
- Update flaw timestamp after updating NIST CVSS
- Deprecate field "order" in the "comments" endpoint (OSIDB-3547)

## [4.3.4] - 2024-10-03
### Added
- Create custom DjangoQL lookup field for Flaw.components (OSIDB-3479)
- Collect NIST CVSSv4 in NVD collector (OSIDB-2300)

### Changed
- Record last impact increase in trackers (OSIDB-3448)

### Fixed
- Remove duplicate results from advanced search (OSIDB-3482)
- Collect Jira field metadata for only one issuetype for each project (OSIDB-3485)
- parent_uuid field in Alert had wrong type in OpenAPI schema (OSIDB-3451)
- Fix Jira Tracker collector to account for Vulnerability issue type (OSIDB-3489)
- IntegrityError duplicate key during tracker filing (OSIDB-3433)

## [4.3.3] - 2024-09-30
### Added
- Update Vulnerability trackers on components change (OSIDB-3323)
- Enable CVEorg collector in production

### Changed
- Alert users when Bugzilla sync failed (OSIDB-3252)

### Fixed
- Remove infinite recursion when SYNC_FLAWS_TO_BZ is disabled (OSIDB-3430)

## [4.3.2] - 2024-09-19
### Changed
- Update the release documentation (OSIDB-3384)

## [4.3.1] - 2024-09-11
### Added
- Create new API endpoints for DjangoQL (OSIDB-3338)
- Implement Jira collector sync managers (OSIDB-3177)

### Fixed
- Unable to unembargo flaws with trackers (OSIDB-3398)

### Removed
- Remove obsoleted contract priority support (OSIDB-3399)
- Remove obsoleted comliance priority support (OSIDB-3335)

## [4.3.0] - 2024-09-04
### Added
- Add CVEorg collector (OSIDB-2234)
- Allow trackers to have manually set SLAs (OSIDB-3374)

### Changed
- Handle frequent Taskman, Trackers and Collectors exceptions
  instead of internal server error 500 (OSIDB-3280)
- Sync trackers on impact decrease (OSIDB-3350)

### Fixed
- Tracker validations skipping (OSIDB-3336)

## [4.2.0] - 2024-08-30
### Added
- Implement DjangoQL for Flaw filtering (OSIDB-3337)
- Support Vulnerability issuetype for Trackers (OSIDB-2980)
- Set requires_cve_description to REQUESTED when unset and the flaw
  has cve_description (OSIDB-3349)

### Changed
- Extend CVSS vector length (OSIDB-3362)

### Fixed
- Taskman throwing away logs upon JSON decode error (OSIDB-3296)
- Wrong due date when filing new Jira tracker (OSIDB-3376)
- Fix date format error (OSIDB-3364)

## [4.1.7] - 2024-08-22
### Added
- Command for manual syncing Jira metadata (OSIDB-3219)

### Changed
- Saving models only triggers validations once (OSIDB-3108)
- Update ACLs of linked objects to match collector flaw (OSIDB-3253)
- Allow start dates to come from multiple sources in SLA (OSIDB-3221)
- Update public date for collector flaws (OSIDB-3212)
- Tracker collector ignores up-to-date entries (OSIDB-3244)
- Adjust BBSync to work in one-way mode (OSIDB-3251)
- Show only official collectors at the collector status endpoint
- Use OSIDB Bugzilla service account API key for majority of bzsync
  instead of user ones (OSIDB-3261)
- Adjust synchronous bzsync to only work one-way
- Move DEFER from historical to current possible affect resolution (OSIDB-3281)

### Fixed
- Cannot modify CVE of existing flaws (OSIDB-3102)
- Jira metadata collector is not deleting metadata on failure (OSIDB-3219)
- Avoid deadlocks by not triggering nested validations in m2m relationships (OSIDB-3244)
- Manually run validation avoiding duplicated trackers (OSIDB-3234)
- Add delay between Jira metadata fetch calls to prevent rate limiting (OSIDB-3298)

### Removed
- Stop syncing Bugzilla SRT notes to Bugzilla flaw bugs

## [4.1.6] - 2024-08-02
### Fixed
- Cannot fill trackers concurrently (OSIDB-3230)

## [4.1.5] - 2024-08-01
### Removed
- Remove message throttling in the API

## [4.1.4] - 2024-07-31
### Added
- Implement message throttling in the API (OSIDB-894)
- Added contract priority description in trackers (OSIDB-3165)

### Changed
- special_handling_flaw_missing_cve_description Alert to
  special_consideration_flaw_missing_cve_description (OSIDB-2955)
- special_handling_flaw_missing_statement Alert to
  special_consideration_flaw_missing_statement (OSIDB-2955)
- Allow setting empty impact value on flaw (OSIDB-3128)
- Temporarily move has trackers workflow requirement (OSIDB-3098)
- Handle Bugzilla errors in API request as 422 instead of
  500 internal server error (OSIDB-3126)
- Handle DB deadlock errors triggered by concurrent API requests
  as 409 instead of 500 internal server error (OSIDB-3048)
- Propagate Jira errors to the user (OSIDB-3184)

### Fixed
- Fix duplicate comment issue leading in internal server error (OSIDB-3086)
- Handle flaw comments with&without bzimport or bifurcated history (OSIDB-3030)
- Alerts constrained unique so that bzimport doesn't block user requests (OSIDB-3048)
- Duplicate Alerts created concurrently in multiple threads handled correctly (OSIDB-3048)
- Make task collector ignore outdated issues (OSIDB-3085)
- Allow Flaw API to properly unassign owner in Jira (OSIDB-3145)
- Remove sync from Bugzilla from the async sync to Bugzilla (OSIDB-3199)
- Do not save to backend systems in JiraTaskSaver (OSIDB-3087)

## [4.1.3] - 2024-07-25
### Changed
- UnackedHandler only recommends active unacked streams (OSIDB-3160)

## [4.1.2] - 2024-07-03
### Added
- Extend flaw-task linking to primarily use the CVE ID

### Fixed
- Fix Jira task collector (OSIDB-3064)
- Fix OSIDB-Bugzilla mid-air collision issues (OSIDB-3083)
- Null version of PsUpdateStream is not sent to Jira when creating a tracker (OSIDB-3078)

## [4.1.1] - 2024-06-28
### Added
- Prefetch Alerts related models for each API endpoint (OSIDB-3053)

### Fixed
- Keep vulnerability-draft BZ component when rejecting flaw draft (OSIDB-3023)
- Fix external sync order in serializers (OSIDB-3029)
- Make Taskman service validate Jira token (OSIDB-2203)

## [4.1.0] - 2024-06-25
### Added
- Implement a way to switch off each collector (OSIDB-2884)
- Generate Jira tracker "components" field (OSIDB-2988)
- Rudimentary API request logging (OSIDB-2514)
- Add query param to force creation of Jira task for old flaws on update (OSIDB-2882)
- Add collector for Jira tasks manually edited (OSIDB-1930)

### Changed
- Update the SLA policy

### Fixed
- Workflow state of flaws without task automatically changes to 'NEW' (OSIDB-2989)
- Fixed Flaw CC list builder to generate CCs in Bugzilla format
  for both Bugzilla and Jira tracked PS modules (OSIDB-2985)
- Flaw comments create action respects is_private (OSIDB-3003)

## [4.0.0] - 2024-06-17
### Added
- Add new OSV option into FlawSource
- Allow searching by CVE similarity (OSIDB-2482)
- Add CC lists to Jira trackers and to Bugzilla trackers (OSIDB-2191)
- Enable flaw draft creation in BZ (OSIDB-2261)
- Add support for UAT (OSIDB-2447)
- Added API for Alerts (OSIDB-325)
- Add bulk PUT for Affects (OSIDB-2407)
- Add Bugzilla token to promote API (OSIDB-2262)
- Enable creation of Jira tasks for collector flaws (OSIDB-2649)
- Add temporary JIRA stage http forwarder passing in params and headers (OSIDB-2734)
- Add link between trackers to flaws without CVE (OSIDB-2848)
- Support Bugzilla tracker creation/linking for non-Bugzilla flaws (OSIDB-2845)
- Add bulk-enabling parameter "sync_to_bz" to POST for Trackers (OSIDB-2609)
- Add bulk POST, DELETE for Affects (OSIDB-2722)
- Add audit history to Flaws and Affects (OSIDB-2269)
- Implement search on emptiness for several fields (OSIDB-2815)
- Add major_incident_start_dt field (OSIDB-2728)
- Add empty value to workflow_state (OSIDB-2881)

### Changed
- Make workflows API RESTful (OSIDB-1716)
- Collect errata not linked to any flaws (OSIDB-1527)
- Minor change to enable perf tests to run in CI (OSIDB-2447)
- Allow editing flaws without affects in NEW state (OSIDB-2452)
- Fixed read replica to perform HTTP requests as atomic transactions (OSIDB-2585)
- Fixed Bugzilla sync not working when Jira task sync is enabled (OSIDB-2628)
- Ignore SLA if update stream specifies it's not applicable (OSIDB-2612)
- Allow filtering by empty or null CVE IDs (OSIDB-2625)
- Redesign of flaw comments to make them independent of Bugzilla (OSIDB-2760)
- Allow filling trackers for flaws without bz_id (OSIDB-2819)
- Split BBSync enablement switch into flaw and tracker ones (OSIDB-2820)
- Set "Target Release" field in Jira trackers (OSIDB-2727)
- Tracker resolution is now readonly (OSIDB-2746)
- Enable tracker suggestions for affects with new affectedness (OSIDB-2843)
- Correct endpoint for tracker filing schema (OSIDB-2847)
- Renamed Flaw "description" to "comment_zero" and "summary" to "cve_description" (OSIDB-2740)
- Update the workflow check of filed trackers (OSIDB-2799)
- Improve affect validation error messages (OSIDB-2893)

### Fixed
- Fix incorrect ACLs for flaw drafts (OSIDB-2263)
- Fix workflow rejection endpoint (OSIDB-2456)
- Fix FlawReference article count validation (OSIDB-2651)
- Fix not being able to set CVE ID to an empty string through the API (OSIDB-2702)
- Comments not properly updating when syncing from Bugzilla (OSIDB-1385)
- Account for empty string in target release of PS update stream (OSIDB-2909)
- CVSS "comment" field accepts null (OSIDB-2907)

### Removed
- Remove "type" field from Affect (OSIDB-2743)
- Remove "type" field from Flaw (OSIDB-2735)
- Remove "state" field from Flaw (OSIDB-2736)
- Remove "resolution" field from Flaw (OSIDB-2737)
- Remove several cvss fields from Flaw (OSIDB-2749)
- Remove several cvss fields from Affect (OSIDB-2749)
- Remove "type" field from FlawComment (OSIDB-2745)
- Remove FlawMeta (OSIDB-2744)
- Remove "is_major_incident" field from Flaw (OSIDB-2741)
- Remove "meta_attr" field from FlawReference (OSIDB-2854)
- Remove "meta_attr" field from FlawAcknowledgment (OSIDB-2854)
- Remove "component" field from Flaw (OSIDB-2839)
- Remove "meta_attr" field from FlawComment (OSIDB-2747)

## [3.7.3] - 2024-05-28
### Fixed
- Fix erratum-tracker linking (OSIDB-2752)

## [3.7.2] - 2024-05-17
### Fixed
- Fix JiraTrackerConvertor linking of multi-CVE flaws (OSIDB-2708)

## [3.7.1] - 2024-05-16
### Changed
- Move flaw-affect-tracker linking to the tracker sync (OSIDB-1012, OSIDB-2587)

## [3.7.0] - 2024-04-17
### Added
- Implement flaw unembargo mechanism (OSIDB-1177)
- Make ps_product property available in affect API
- Add Fedramp stream preselection handler (OSIDB-1876)
- Introduce CVSS v4 (OSIDB-528)
- Change tests to have default urls strings where it can't be blank (OSIDB-1679)
- Add label compliance-priority to jira trackers based on ps-constants compliance_priority.yml (OSIDB-2062)
- Expose alerts on API for every model alert supported model,
  mainly Flaw, Affect, Tracker (OSIDB-2065)
- Add support for additional_fields in Jira BTS (OSIDB-696)
- Add scripts/restore_pg.sh script for restoring sql dump

### Changed
- Ignore hosts on VCR recording (OSIDB-1678)
- Included workflow fields in OpenAPI document for filtering (OSIDB-2083)
- Set migrated/duplicated delegated resolution to be ignored (OSIDB-1406)
- Update valid affectedness-resolution combinations (OSIDB-2143)
- Change Flaw API filter to allow a list of workflow_state (OSIDB-2208)
- SLA for compliance priority brought to parity with SFM2 (OSIDB-2257)
- Migrate data with outdated workflow_state values to the current ones (OSIDB-1718)
- Flaw CVSS score and Affect CVSS score are now readonly (OSIDB-2347)

### Fixed
- Fix Jira sync when bugzilla token is present (OSIDB-2171)
- Fix Bugzilla summary for first flaw creation (OSIDB-2190)
- Fix Jira tracker security level not being set based on embargo (OSIDB-2082)
- Removed writing operations in workflows when READ_ONLY is enabled (OSIDB-2336)
- Fix Flaw API allowing to sort by all fields (OSIDB-2367)
- Fix FlawCVSS and AffectCVSS "cvss_version" on API to show version enum

## [3.6.2] - 2024-02-02
### Fixed
- Fix issue with tracker updates through Affect objects (OSIDB-2059)
- Ensure invalid fields passed to include_fields filter are ignored (OSIDB-2048)

## [3.6.1] - 2024-02-01
### Fixed
- Fix issue with Flaw updates through collector (OSIDB-2050)

## [3.6.0] - 2024-01-31
### Added
- Implement writable tracker API (OSIDB-1180)
- Command for manual sync of Flaws now also accepts CVEs (OSIDB-1544)
- Add new SOURCE option into FlawReferenceType (OSIDB-1556)
- Add new NVD option into FlawSource
- Implement SLA definition parsing and timestamp computation (OSIDB-1428)
- Implement tracker SLA start date setting (OSIDB-1393)
- Implement tracker SLA end date setting (OSIDB-96)
- Properly link Jira trackers to flaws on creation and update (OSIDB-1426)
- Add OSV collector (OSIDB-677)
- Added GIN indexes for Row Based Security performance on models
- Added MAX_CONNS to django db conf to enable better concurrency
- Workflow fields added into Flaw endpoints (OSIDB-1819)
- Implement after-flaw-update tracker update mechanism (OSIDB-97)
- Add label verification-requested to jira trackers with NEW affects (OSIDB-1185)
- Implement after-affect-update tracker update mechanism (OSIDB-97)
- Keep jira tracker labels added by people or other tools (OSIDB-1440)
- Add label contract-priority to jira trackers based on ps-constants contract_priority.yml (OSIDB-1709)

### Fixed
- Fix incorrect type bool of is_up2date field in
  /collectors/api/v1/status endpoint
- fix schema to reflect Erratum shipped_dt to be nullable
- Ensured serializer db calls are read_only
- Expose git commit id via OPENSHIFT_BUILD_COMMIT env var
- Fix Jira metadata collector to get all pages from a query (OSIDB-1124)

### Changed
- Renamed OSIM module to Workflows (OSIDB-1395)
- Change settings to allow regex in CORS policy in stage environment (OSIDB-1737)
- Enhanced prefetches on Flaw, Affect, and Tracker api querysets
- Change default pg configs 
- Adjust CONN_MAX_AGE and CONN_MAX_CONNS to maintain a minimal pool of idle db conns (OSIDB-1620)
- Tracker status field is read-only (OSIDB-1780)
- Change Bugzilla collector and Flaw model to allow multiple components in bz_summary (OSIDB-1420)

### Removed
- Remove daily monitoring email for failed tasks / collectors (OSIDB-1215)
- Remove not used taskman APIs and services that has been intregated in OSIM (OSIDB-1321)

## [3.5.2] - 2023-12-06
### Added
- Limit Celery worker to maximum amount of tasks (OSIDB-1540)
- Add Celery worker concurrency
- Maximum Bugzilla and Jira connection age (OSIDB-1592, OSIDB-1593)

### Fixed
- Made Querier objects independent on Collector objects (OSIDB-1592, OSIDB-1593)

## [3.5.1] - 2023-10-23
### Fixed
- fix PS contact model (OSIDB-1445)
- Improve EPSS collector memory consumption

## [3.5.0] - 2023-10-09
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
- Update CORS policy to allow bugzilla-api-key request header (OSIDB-1425)
- Change workflows to reflect current IR workflow (OSIDB-1319)

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
