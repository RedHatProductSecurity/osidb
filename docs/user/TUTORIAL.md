# Using the OSIDB REST API with cURL and Python

OSIDB exposes a REST API from which any number of clients can connect, from cURL to a custom-made frontend application to serve as web client, in this tutorial we will go through the basics of using the API under different environments.

To know which endpoints are available and which operations can be performed on each endpoint, please check the [OpenAPI specification](https://git.prodsec.redhat.com/devops/osidb/-/blob/master/openapi.yml) for OSIDB.

> Note: In this tutorial we will use a local instance of OSIDB as a target for all of our commands, however all of these should work on our [staging server](https://osidb-stage.prodsec.redhat.com/)

## Authentication and authorization

The first step towards communicating with the API and retrieving useful data from it is Authentication,
OSIDB uses a multi-tier authentication system:

  - Clients must first perform Kerberos / GSSAPI authentication using the SPNEGO protocol
  - After kerberos authentication, client will be sent JSON Web Tokens for further authentication

### Kerberos setup

Please refer to our [README](AUTH.md#kerberos-authentication), you may not
be able to authenticate if you don't follow the instructions laid in the linked
document.

### Getting an auth token

The first step is to hit the endpoint that will generate a JSON Web Token for us so that we can request data from private endpoints.

With cURL

> Note: auth with curl is not currently working due to some kerberos configuration missing on our side

```bash
$ curl -H 'Content-Type: application/json' \
       --negotiate -u : \
       https://osidb-stage.prodsec.redhat.com/auth/token \

{"refresh": ..., "access": ...}
```

With python

```python
import kerberos
import requests

HOSTNAME = "osidb-stage.prodsec.redhat.com"
rc, ctx = kerberos.authGSSClientInit(f"HTTP@{HOSTNAME}")
kerberos.authGSSClientStep(ctx, "")
token = kerberos.authGSSClientResponse(ctx)

TOKEN_URL = f"https://{HOSTNAME}/auth/token"

headers = {"Authorization": f"Negotiate {token}"}
response = requests.get(TOKEN_URL, headers=headers)
assert response.ok

body = response.json()
token = body['access']
refresh = body['refresh']
print(token)
```

### Using our token for authorization

First, let's try to get the API's status by hitting the `osidb/api/v1/status` endpoint.

With cURL

```bash
$ curl http://localhost:8000/osidb/api/v1/status
```

With python

```python
import requests

response = requests.get("http://localhost:8000/osidb/api/v1/status")
```

For both, you should get a 403 status code along with the message "You do not have permission to perform this action". This is because the endpoint we tried to hit requires authentication, we just conveniently forgot to pass the token we received earlier along with the request, let's try that again by passing the access token we got in the previous step:

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>"\
       http://localhost:8000/osidb/api/v1/status
```

With python

```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
response = requests.get("http://localhost:8000/osidb/api/v1/status", headers=headers)
assert response.ok
```

Now you should get a proper response!

### Refreshing your token

You may have noticed that when requesting a token the server sent back not one
but two tokens, we made the concious choice to use the one labeled as "access"
to authorize requests against the server. This is because OSIDB uses
JSON Web Tokens (JWTs) for authentication, meaning you get a token for access
and a refresh token from which you can generate new access tokens.

Ideally, access tokens are meant to be used only once (single request) as they
have a very short lifetime (5 minutes), but in practice you can use them for
as many requests as you can during its lifetime although we recommend avoiding
this as it can lead to requests being rejected.

Instead what you should do after performing a request with your access token
is requesting a new access token by using your refresh token, refresh tokens
have a longer lifetime (24 hours) and you can get as many new access tokens
from it as you want as long as the refresh token is still valid, let's try it:

With cURL

```bash
$ curl -X POST http://localhost:8000/auth/token/refresh \
       -H 'Content-Type: application/json' \
       -d '{"refresh": <refresh_token>}'

{"access": ...}
```

With python

```python
import requests

REFRESH_URL = "http://localhost:8000/auth/token/refresh"
response = requests.get(REFRESH_URL, json={"refresh": refresh})
assert response.ok
token = response.json()["access"]
```

You will notice that when refreshing, the server only returns a new access
token and no new refresh token is provided. This is normal and clients are
expected to re-authenticate once their refresh token expires.

### Verifying tokens

If you're unsure whether any of your tokens, whether access or refresh, is
still valid or not, OSIDB exposes a token-verification endpoint which will
return either an HTTP 200 response with empty body if the token is valid
or an HTTP 401 response with a body explaining that the token is invalid
or expired.

With cURL

```bash
$ curl -X POST http://localhost:8000/auth/token/verify \
       -H 'Content-Type: application/json' \
       -d '{"token": <access_token | refresh_token>}'

```

With python


```python
import requests

VERIFY_URL = "http://localhost:8000/auth/token/verify"
response = requests.get(VERIFY_URL, json={"token": refresh})
assert response.ok
```

## Fetching flaws

Since we don't know exactly what flaws are within OSIDB, let's start by fetching **all** flaws, and then we can pick and choose one and do more with it.

> Note: while in theory this endpoint returns every flaw in the OSIDB instance, in practice the results are paginated, meaning that you will receive **some** results and then links to the next/previous chunk/batch.

### Fetching all flaws

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws
```

With python

```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers)
assert response.ok
```

Now that we have fetched some flaws, we can pick one from the results we got and grab its `uuid` attribute, with this attribute we can then request data for that specific flaw or even delete it.

### Fetching details for a specific flaw

> Note: in this section we will use a made up uuid, you should use a uuid from the dataset you retrieved in the previous section, otherwise the following examples will not work.

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws/2fe16efb-11cb-4cd2-b31b-d769ba821073
```

With python

```python
import requests

flaw_id = "2fe16efb-11cb-4cd2-b31b-d769ba821073"
headers = {"Authorization": "Bearer <access_token>"}
response = requests.get(f"http://localhost:8000/osidb/api/v1/flaws/{flaw_id}", headers=headers)
assert response.ok
```

This should return all the details for the flaw with the uuid we requested.

You can also get a flaw's details by using its CVE number instead of its uuid, this method might prove more robust across different OSIDB instances

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws/CVE-2005-0001
```

With python

```python
import requests

flaw_id = "CVE-2005-0001"
headers = {"Authorization": "Bearer <access_token>"}
response = requests.get(f"http://localhost:8000/osidb/api/v1/flaws/{flaw_id}", headers=headers)
assert response.ok
```

## Searching for flaws

We can also search flaws by different criterion, by passing query parameters, you can find valid query parameters by looking up the [OpenAPI specification](https://git.prodsec.redhat.com/devops/osidb/-/blob/master/openapi.yml) for the specific endpoint you want to query.

### Searching by specific fields

First, let's try to find all the flaws that were changed after any given day, this may or may not return some results, depending on the day you choose and on the instance from which you're requesting the data.

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws?changed_after=2021-11-18
```

With python

```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
params = {"changed_after": "2021-11-18"}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

Both of these should return any flaws that have changed since the date passed-in as a query parameter.

> Note: you can combine as many parameters as you want, with curl you "chain" parameters with an ampersand (`&`) e.g. `?changed_after=2021-11-18&changed_before=2021-11-19`, that last example would return any flaws that were last modified on 2021-11-18. For python, you simply add an extra `key: value` pair to the params dictionary

### Full text search

You can also perform a full text search, which will search for any flaw that contains a given keyword in any of its fields.

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws?search=openjdk
```

With python


```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
params = {"search": "openjdk"}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

### Filtering the fields returned by a flaw

Ok we managed to search for flaws, but that seems like a lot of information to consume, maybe we don't need all of that and we just need just a few fields, or maybe there are some fields that we're sure we won't need.

In this section we'll go through filtering some fields when retrieving flaws, for this there are three parameters that can help us with this ordeal:

- `include_fields` -- think of this as an allowlist, only the fields passed to this parameter will be returned for all flaws retrieved.

- `exclude_fields` -- this is the opposite of `include_fields`, can be thought of a denylist, all fields except the ones passed to this parameter will be returned for all flaws retrieved.

- `include_meta_attrs` is a special one, by default the `meta_attr` field is not returned, by adding this parameter you can get all values (`?include_meta_attr=*`) or specific keys through a comma-separated list of keys (note that this field can contain whatever, so if some keys are not returned it means they don't exist for the given flaws).

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws?include_fields=cve_id,comments
```

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws?exclude_fields=comments
```

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       http://localhost:8000/osidb/api/v1/flaws?include_meta_attr=*
```

With python

```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
params = {"include_fields": ["cve_id", "comments"]}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
params = {"exclude_fields": ["comments"]}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
params = {"include_meta_attr": ["*"]}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

### Filtering the fields of the related models returned by a flaw

Now when we know how to perform basic filtering on the flaw fields we can jump into more advanced filtering. The previous filtering
methods were filtering only the fields that exists directly on the Flaw model. However Flaw also has some related models like Affects
or Affects Trackers and we would like to filter also on these related models.

For this purpose, we will use the same three query parameters as we used in the previous section, however we will use the dot-notation to
specify fields on realated models to filter.

- `include_fields`/`exclude_fields` -- to filter fields on related models of a flaw all you have to do is write the name of the field
which represents the related model you want to filter on and the name of the field on the related model separated by a dot, eg. `?include_fields=affects.ps_module` (include only `ps_module` field of all the Affects) or `exclude_fields=affects.trackers.external_system_id` (exclude `external_system_id` field of all the Trackers of all the Affects).

- `include_meta_attr` -- related models of a Flaw also have a `meta_attr` field hidden by default as well. To specify which keys of these
`meta_attr` fields you would like to retrieve just simply write a name of the field which represents the related model whose `meta_attr`
you would like to show and the name of the `meta_attr` key you would like to show separated by a dot, eg. `?include_meta_attr=affects.component` (to retrieve key `component` from affects `meta_attr` field) or `?include_meta_attr=affects.trackers.bz_id` (to retrieve key `bz_id` from trackers `meta_attr` field). `*` wildcard for retrieving all the keys on related models is supported as well, eg, `include_meta_attr=affects.*,affects.trackers.*` (to get all keys from the affects `meta_attr` and all the keys from affects trackers `meta_attr`)

Currently supported Flaw related models for advanced filtering: Affects, Trackers

With cURL

```bash
$ curl -H "Authorization: Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847" \
       http://localhost:8000/osidb/api/v1/flaws?include_fields=affects.ps_module
```

```bash
$ curl -H "Authorization: Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847" \
       http://localhost:8000/osidb/api/v1/flaws?exclude_fields=affects.trackers.external_system_id
```

```bash
$ curl -H "Authorization: Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847" \
       http://localhost:8000/osidb/api/v1/flaws?include_meta_attr=affects.*,affects.trackers.bz_id
```

With python

```python
import requests

headers = {"Authorization": "Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847"}
params = {"include_fields": ["affects.ps_module"]}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

```python
import requests

headers = {"Authorization": "Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847"}
params = {"exclude_fields": ["affects.trackers.external_system_id"]}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

```python
import requests

headers = {"Authorization": "Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847"}
params = {"include_meta_attr": ["affects.*", "affects.trackers.*"]}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

### Filtering the flaws related only to specific trackers

Sometimes user can be interested in Trackers and its related Flaws (through Affects). To be able to filter only Flaws, that are connected
to a specific tracker(s), you can use query parameter `tracker_ids` which expects ID or comma-separated list of IDs (BZ IDs for Bugzilla trackers or Jira IDs for Jira trackers). In addition only only Affects that are related to specified tracker(s) will be shown.

With cURL

```bash
$ curl -H "Authorization: Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847" \
       http://localhost:8000/osidb/api/v1/flaws?tracker_ids=AAH-1284,2038382
```

With python

```python
import requests

headers = {"Authorization": "Token 835b5dd8b69d2a6f79adaf3f29e926e138b6c847"}
params = {"tracker_ids": ["AAH-1284", "2038382"]}
response = requests.get("http://localhost:8000/osidb/api/v1/flaws", headers=headers, params=params)
assert response.ok
```

## Creating a flaw

Creating a new flaw is as easy as hitting the same endpoint for retrieving all flaws, but instead of sending a GET request, we send a POST request along with the data for the fields required to create a Flaw.

Let's try it!

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       -H "Content-Type: application/json" \
       -X POST
       -d '{
              "type": "VULNERABILITY",
              "cve_id": "CVE-2161-0013",
              "state": "NEW",
              "resolution": "ERRATA",
              "impact": "MODERATE",
              "title": "Retrieve the water chip",
              "description": "We need the water chip to survive, explore the wasteland and find a replacement",
       }'
       http://localhost:8000/osidb/api/v1/flaws
```

With python

```python
import requests

headers = {
    "Authorization": "Bearer <access_token>",
    "Content-Type": "application/json",
}
data = {
    "type": "VULNERABILITY",
    "cve_id": "CVE-2161-0013",
    "state": "NEW",
    "resolution": "ERRATA",
    "impact": "MODERATE",
    "title": "Retrieve the water chip",
    "description": "We need the water chip to survive, explore the wasteland and find a replacement",
}
response = requests.post("http://localhost:8000/osidb/api/v1/flaws", headers=headers, json=data)
assert response.ok
```

With this, we now have added a brand new Flaw into OSIDB, but we introduced some data that is not 100% correct and need to change it.

## Updating a Flaw

We need to change some data for the Flaw that we just created. To do this, we simply need to hit the detail endpoint with either the UUID (which you should've gotten in the response to the create operation) or the CVE id of the flaw, let's do this.

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       -H "Content-Type: application/json" \
       -X PUT
       -d '{
              "type": "VULNERABILITY",
              "cve_id": "CVE-2161-0013",
              "state": "NEW",
              "resolution": "ERRATA",
              "impact": "CRITICAL",     # from MODERATE to CRITICAL
              "title": "Retrieve the water chip",
              "description": "We need the water chip to survive, explore the wasteland and find a replacement",
       }'
       http://localhost:8000/osidb/api/v1/flaws/CVE-2161-0013
```

With python

```python
import requests

headers = {
    "Authorization": "Bearer <access_token>",
    "Content-Type": "application/json",
}
data = {
    "type": "VULNERABILITY",
    "cve_id": "CVE-2161-0013",
    "state": "NEW",
    "resolution": "ERRATA",
    "impact": "CRITICAL",           # from MODERATE to CRITICAL
    "title": "Retrieve the water chip",
    "description": "We need the water chip to survive, explore the wasteland and find a replacement",
}
response = requests.put("http://localhost:8000/osidb/api/v1/flaws/CVE-2161-0013", headers=headers, json=data)
assert response.ok
```

That seems to have worked! We successfully updated our Flaw, however this was just a test Flaw, no need to pollute the database with dummy data.

## Deleting a Flaw

Since the Flaw we created is just some dummy Flaw in order to test OSIDB's REST API, let's remove it to avoid polluting the database, doing this is as easy as any of the previous operations.

> Note: Deleting has no constraints as of now, but in the future it's highly likely that this won't work in production unless under very strict and specific circumstances to avoid data loss

With cURL

```bash
$ curl -H "Authorization: Bearer <access_token>" \
       -X DELETE
       http://localhost:8000/osidb/api/v1/flaws/CVE-2161-0013
```

With python

```python
import requests

headers = {"Authorization": "Bearer <access_token>"}
response = requests.delete("http://localhost:8000/osidb/api/v1/flaws/CVE-2161-0013", headers=headers)
assert response.ok
```

And that's it! Now we know all that we need to know to use the OSIDB REST API.
