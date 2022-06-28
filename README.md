# OSIDB
[![pipeline status](https://git.prodsec.redhat.com/devops/osidb/badges/master/pipeline.svg)](https://git.prodsec.redhat.com/devops/osidb/-/commits/master)
[![coverage report](https://git.prodsec.redhat.com/devops/osidb/badges/master/coverage.svg)](https://git.prodsec.redhat.com/devops/osidb/-/commits/master)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

### data services
[osidb](osidb/README.md) - flaw service and database

### collectors
* [bzimport](collectors/bzimport/README.md) - sync Bugzilla data to osidb

### apps
* [osim](apps/osim/README.md) - Open Security Issue Manager

## More information
* Read [docs](docs/)
* Learn how to contribute and [develop](docs/DEVELOP.md)
* REST API [Tutorial](docs/TUTORIAL.md)
* [CHANGELOG](docs/CHANGELOG.md)

## Kerberos authentication

In order for kerberos authentication to work properly, you may need to install
our custom krb5.conf settings.

You can find the relevant file [here](etc/krb/osidb), download it and install
it in your `/etc/krb5.conf.d/` directory, the file only sets the
`dns_canonicalize_hostname` setting to `fallback` which is a mostly harmless change
since it behaves as both `true` and `false`, so it shouldn't impact any other
kerberos-enabled services. The file also adds entries for all of OSIDB hostnames
to map to the correct kerberos realm.

### But, why?

Using kerberos comes with "challenges" (pun intended), especially within Red Hat
where we have two active realms ([IPA.].REDHAT.COM) but only one of them (IPA)
is being used for generating new SPNs. This means that in order for kerberos
clients (e.g. curl) to use the correct realm, it must either fetch a TXT record
from our CNAME or our canonical hostname, depending on each client's individual
krb5.conf, we can control the TXT record for our CNAME but not the one for the
canonical hostname, and having a `domain_realm` mapping in a file that clients
can easily install helps in dealing with this particular challenge.

As for the `dns_canonicalize_hostname` setting, this is (hopefully) a temporary
measure while we resolve some DNS issues with the OCP PSI team.

## Authentication for implementors
If implementing an application and/or service that interfaces with the
OSIDB REST API, please avoid misusing JWTs as this can lead to
security issues, here are some tips on handling JWTs:

- Assume that one access token = one request, this will simplify
  your application's workflow, as using the same token for multiple
  requests will require checking for an invalid token error, then
  requesting a new access token and finally retrying the original request.

- Avoid storing the tokens in anything other than memory, this applies
  especially to SPAs / JavaScript clients, storing the tokens in something
  like local / session storage can lead to XSS, storing them in a cookie is
  feasible but the cookie must be httpOnly, secure and SameSite=strict
  otherwise they can be susceptible to CSRF attacks, but this is out of our
  scope as service providers so we cannot recommend it.
