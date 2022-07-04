# Kerberos authentication

In order for kerberos authentication to work properly, you may need to install
our custom krb5.conf settings.

You can find the relevant file [here](../../etc/krb/osidb), download it and install
it in your `/etc/krb5.conf.d/` directory, the file only sets the
`dns_canonicalize_hostname` setting to `fallback` which is a mostly harmless change
since it behaves as both `true` and `false`, so it shouldn't impact any other
kerberos-enabled services. The file also adds entries for all of OSIDB hostnames
to map to the correct kerberos realm.

## But, why?

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
