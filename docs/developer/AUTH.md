# Authentication for implementors
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
