# OSIDB

Open Security Issue Database - test

## Table of Contents

* [Introduction](#introduction)
* [Technologies](#technologies)
* [Structure](#structure)
* [Setup](#setup)
* [Usage](#usage)
* [Contributing](#contributing)
* [Status](#status)

## Introduction

OSIDB projects aims to create an easy-to-use open-source
[PSIRT](https://www.first.org/standards/frameworks/psirts/) tooling framework
designed for collecting, storing, processing, and providing security
vulnerability data across software offering portfolio.

* Incorporate an enterprise-ready solution and start tracking security
  vulnerabilities in your organization's offerings or utilize an outstanding
  tooling support to tune your existing product security workflow.
* Create and manage the records on [CVE](https://cve.mitre.org/)s
  and potential security issues throughout your portfolio. Set their impact,
  source, [CWE](https://cwe.mitre.org/), [CVSS](https://www.first.org/cvss/)
  score, description, and more together with information on what products and
  components are being affected.
* Comply with security embargo and manage the access to the sensitive data with
  fine-grained granularity.
* Automate your security data intake with autonomous data collectors.
* Adjust the service to your special needs by custom apps.
* And more...

## Technologies

OSIDB project is build on [Django](https://www.djangoproject.com/) framework.
[PostgreSQL](https://www.postgresql.org/) provide the underlying database.
[Celery](https://docs.celeryq.dev/) with [Redis](https://redis.io/)
is used for asynchronous workloads execution.
[Gunicorn](https://gunicorn.org/) serves as the WSGI HTTP server.
Authentication is performed by [Kerberos](https://web.mit.edu/kerberos/)
and the authorization by [LDAP](https://ldap.com/).
[Bugzilla](https://www.bugzilla.org/) and [Jira](https://jira.atlassian.com/)
are currently supported as the data sources. OSIDB runs as a set cooperating containers.
The deployment is done by [Podman](https://podman.io/) and
[Podman Compose](https://github.com/containers/podman-compose).

## Structure

[osidb](osidb/) contains the core of the service.
Data models, validations, serializers, API, and other vital parts are defined there.
You can find more details [here](osidb/README.md).
Additional functionality is implemented by specialized [apps](apps/).

* [bbsync](apps/bbsync/) Bugzilla Backwards Synchronization
* [exploits](apps/exploits/)
* [workflows](apps/workflows/) - Open Security Issue Manager

Various data sources are being collected by [collectors](collectors/).
They are build on [collector framework](collectors/framework/).

## Setup

Use [Makefile](Makefile) as the local service entrypoint. Run

    make help

to see all available options. Run

    make start-local

to start the service. When running for the first time it gives you hints on
what needs to be set to start successfully. The details of the service setup
can be found [here](docs/developer/DEVELOP.md).

## Usage

Once you have done setting up your OSIDB instance you can start using it.
Follow the [tutorial](docs/user/TUTORIAL.md) and numerous examples in there
to get familiar with how to authenticate to and query the service REST API.

All the user facing documentation can be found [here](docs/user/).

## Contributing

OSIDB project is an open initiative and we welcome any help.
If you are interested in joining us please start by reading
[contributing](docs/developer/CONTRIBUTING.md) guidelines.

All the developer facing documentation can be found [here](docs/developer).

## Status

OSIDB service is still under heavy development and new features, improvements,
and bug fixes are being continuously delivered. Everything is potentially a
subject to change. However, the breaking changes are being considered carefully
as the project is already in a general availability stage and is being actively
used in production environments. The changes are tracked in
[CHANGELOG](docs/CHANGELOG.md).
