# Kerberos authentication

In order for kerberos authentication to work properly, you may need to change your
existing `krb5.conf` so that the `dns_canonicalize_hostname` setting is set to 
`fallback` which is a mostly harmless change since it behaves as both `true` and `false`,
so it shouldn't impact any other kerberos-enabled services. If your kerberos distribution
and/or version does not support the `fallback` value then you may set this to `false`
instead, however this could affect the behavior of other kerberos-enabled services.

## But, why?

Using kerberos comes with "challenges" (pun intended), especially within Red Hat
where we have multiple active realms but only one of them is being used for
generating new SPNs. This means that in order for kerberos clients (e.g. curl)
to use the correct realm, it must either fetch a TXT record from our CNAME or our
canonical hostname, depending on each client's individual krb5.conf, we can
control the TXT record for our CNAME but not the one for the canonical hostname,
and having a `domain_realm` mapping in a file that clients can easily install
helps in dealing with this particular challenge.
