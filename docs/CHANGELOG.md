# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2022-08-01
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

### Removed
- remove audit mechanisms and tables from main models.

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
