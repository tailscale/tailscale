# Tailnet

A tailnet is your private network, composed of all the devices on it and their configuration.
Learn more about [tailnets](https://tailscale.com/kb/1136/).

When specifying a tailnet in the API, you can:

- Provide a dash (`-`) to reference the default tailnet of the access token being used to make the API call.
  This is the best option for most users.
  Your API calls would start:

  ```sh
  curl "https://api.tailscale.com/api/v2/tailnet/-/..."
  ```

- Provide the **organization** name found on the **[General Settings](https://login.tailscale.com/admin/settings/general)**
  page of the Tailscale admin console (not to be confused with the "tailnet name" found in the DNS tab).

  For example, if your organization name is `alice@gmail.com`, your API calls would start:

  ```sh
  curl "https://api.tailscale.com/api/v2/tailnet/alice@gmail.com/..."
  ```

# API

**[Tailnet](#tailnet)**

- [**Policy File**](#policy-file)
  - Get policy file: [`GET /api/v2/tailnet/{tailnet}/acl`](#get-policy-file)
  - Update policy file: [`POST /api/v2/tailnet/{tailnet}/acl`](#update-policy-file)
  - Preview rule matches: [`POST /api/v2/tailnet/{tailnet}/acl/preview`](#preview-policy-file-rule-matches)
  - Validate and test policy file: [`POST /api/v2/tailnet/{tailnet}/acl/validate`](#validate-and-test-policy-file)
- [**Devices**](#devices)
  - List tailnet devices: [`GET /api/v2/tailnet/{tailnet}/devices`](#list-tailnet-devices)
- [**Keys**](#tailnet-keys)
  - List tailnet keys: [`GET /api/v2/tailnet/{tailnet}/keys`](#list-tailnet-keys)
  - Create an auth key: [`POST /api/v2/tailnet/{tailnet}/keys`](#create-auth-key)
  - Get a key: [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](#get-key)
  - Delete a key: [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](#delete-key)
- [**DNS**](#dns)
  - [**Nameservers**](#nameservers)
    - Get nameservers: [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](#get-nameservers)
    - Set nameservers: [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](#set-nameservers)
  - [**Preferences**](#preferences)
    - Get DNS preferences: [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](#get-dns-preferences)
    - Set DNS preferences: [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](#set-dns-preferences)
  - [**Search Paths**](#search-paths)
    - Get search paths: [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths`](#get-search-paths)
    - Set search paths: [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](#set-search-paths)
  - [**Split DNS**](#split-dns)
    - Get split DNS: [`GET /api/v2/tailnet/{tailnet}/dns/split-dns`](#get-split-dns)
    - Update split DNS: [`PATCH /api/v2/tailnet/{tailnet}/dns/split-dns`](#update-split-dns)
    - Set split DNS: [`PUT /api/v2/tailnet/{tailnet}/dns/split-dns`](#set-split-dns)
- [**User invites**](#tailnet-user-invites)
  - List user invites: [`GET /api/v2/tailnet/{tailnet}/user-invites`](#list-user-invites)
  - Create user invites: [`POST /api/v2/tailnet/{tailnet}/user-invites`](#create-user-invites)

## Policy File

The tailnet policy file contains access control lists and related configuration.
The policy file is expressed using "[HuJSON](https://github.com/tailscale/hujson#readme)"
(human JSON, a superset of JSON that allows comments and trailing commas).
Most policy file API methods can also return regular JSON for compatibility with other tools.
Learn more about [network access controls](https://tailscale.com/kb/1018/).

## Get Policy File

```http
GET /api/v2/tailnet/{tailnet}/acl
```

Retrieves the current policy file for the given tailnet; this includes the ACL along with the rules and tests that have been defined.

This method can return the policy file as JSON or HuJSON, depending on the `Accept` header.
The response also includes an `ETag` header, which can be optionally included when [updating the policy file](#update-policy-file) to avoid missed updates.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `Accept` (optional in request header)

Response is encoded as JSON if `application/json` is requested, otherwise HuJSON will be returned.

#### `details` (optional in query string)

Request a detailed description of the tailnet policy file by providing `details=1` in the URL query string.
If using this, do not supply an `Accept` parameter in the header.

The response will contain a JSON object with the fields:

- **tailnet policy file:** a base64-encoded string representation of the huJSON format
- **warnings:** array of strings for syntactically valid but nonsensical entries
- **errors:** an array of strings for parsing failures

### Request example (response in HuJSON format)

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl" \
  -u "tskey-api-xxxxx:"
```

### Response in HuJSON format

On success, returns a 200 status code and the tailnet policy file in HuJSON format.
No errors or warnings are returned.

```jsonc
...
Content-Type: application/hujson
Etag: "e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c"
...

// Example/default ACLs for unrestricted connections.
{
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": ["user1@example.com", "user2@example.com"],
  },

  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100",
  },

  // Access control lists.
  "acls": [
    // Match absolutely everything.
    // Comment this section out if you want to define specific restrictions.
    {"action": "accept", "src": ["*"], "dst": ["*:*"]},
  ],
}

```

### Request example (response in JSON format)

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl" \
  -u "tskey-api-xxxxx:"
  -H "Accept: application/json"
```

### Response in JSON format

On success, returns a 200 status code and the tailnet policy file in JSON format.
No errors or warnings are returned.

```jsonc
...
Content-Type: application/json
Etag: "e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c"
...
{
   "acls" : [
      {
         "action" : "accept",
         "ports" : [
            "*:*"
         ],
         "users" : [
            "*"
         ]
      }
   ],
   "groups" : {
      "group:example" : [
         "user1@example.com",
         "user2@example.com"
      ]
   },
   "hosts" : {
      "example-host-1" : "100.100.100.100"
   }
}
```

### Request example (with details)

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl?details=1" \
  -u "tskey-api-xxxxx:"
```

### Response (with details)

On success, returns a 200 status code and the tailnet policy file in a base64-encoded string representation of the huJSON format.
In addition, errors and warnings are returned.

```sh
{
  "acl": "Ly8gUG9raW5nIGFyb3VuZCBpbiB0aGUgQVBJIGRvY3MsIGhvcGluZyB5b3UnZCBmaW5kIHNvbWV0aGluZyBnb29kLCBlaD8KLy8gV2UgbGlrZSB5b3VyIHN0eWxlISAgR28gZ3JhYiB5b3Vyc2VsZiBhIFRhaWxzY2FsZSB0LXNoaXJ0IGlmIHRoZXJlIGFyZQovLyBzdGlsbCBzb21lIGF2YWlsYWJsZS4gQnV0IHNoaGguLi4gZG9uJ3QgdGVsbCBhbnlvbmUhCi8vCi8vICAgICAgICAgICAgIGh0dHBzOi8vc3dhZy5jb20vZ2lmdC82a29mNGs1Z3B1ZW95ZDB2NXd6MHJkYmMKewoJLy8gRGVjbGFyZSBzdGF0aWMgZ3JvdXBzIG9mIHVzZXJzIGJleW9uZCB0aG9zZSBpbiB0aGUgaWRlbnRpdHkgc2VydmljZS4KCSJncm91cHMiOiB7CgkJImdyb3VwOmV4YW1wbGUiOiBbInVzZXIxQGV4YW1wbGUuY29tIiwgInVzZXIyQGV4YW1wbGUuY29tIl0sCgl9LAoKCS8vIERlY2xhcmUgY29udmVuaWVudCBob3N0bmFtZSBhbGlhc2VzIHRvIHVzZSBpbiBwbGFjZSBvZiBJUCBhZGRyZXNzZXMuCgkiaG9zdHMiOiB7CgkJImV4YW1wbGUtaG9zdC0xIjogIjEwMC4xMDAuMTAwLjEwMCIsCgl9LAoKCS8vIEFjY2VzcyBjb250cm9sIGxpc3RzLgoJImFjbHMiOiBbCgkJLy8gTWF0Y2ggYWJzb2x1dGVseSBldmVyeXRoaW5nLgoJCS8vIENvbW1lbnQgdGhpcyBzZWN0aW9uIG91dCBpZiB5b3Ugd2FudCB0byBkZWZpbmUgc3BlY2lmaWMgcmVzdHJpY3Rpb25zLgoJCXsiYWN0aW9uIjogImFjY2VwdCIsICJ1c2VycyI6IFsiKiJdLCAicG9ydHMiOiBbIio6KiJdfSwKCV0sCn0K",
  "warnings": [
    "\"group:example\": user not found: \"user1@example.com\"",
    "\"group:example\": user not found: \"user2@example.com\""
  ],
  "errors": null
}
```

## Update policy file

```http
POST /api/v2/tailnet/{tailnet}/acl`
```

Sets the ACL for the given tailnet.
HuJSON and JSON are both accepted inputs.
An `If-Match` header can be set to avoid missed updates.

On success, returns the updated ACL in JSON or HuJSON according to the `Accept` header.
Otherwise, errors are returned for incorrectly defined ACLs, ACLs with failing tests on attempted updates, and mismatched `If-Match` header and ETag.

### Parameters

#### tailnet (required in URL path)

The tailnet organization name.

#### `If-Match` (optional in request header)

This is a safety mechanism to avoid overwriting other users' updates to the tailnet policy file.

- Set the `If-Match` value to that of the ETag header returned in a `GET` request to `/api/v2/tailnet/{tailnet}/acl`.
  Tailscale compares the ETag value in your request to that of the current tailnet file and only replaces the file if there's a match.
  (A mismatch indicates that another update has been made to the file.)
  For example: `-H "If-Match: \"e0b2816b418\""`
- Alternately, set the `If-Match` value to `ts-default` to ensure that the policy file is replaced
  _only if the current policy file is still the untouched default_ created automatically for each tailnet.
  For example: `-H "If-Match: \"ts-default\""`

#### `Accept` (optional in request header)

Sets the return type of the updated tailnet policy file.
Response is encoded as JSON if `application/json` is requested, otherwise HuJSON will be returned.

#### Tailnet policy file entries (required in `POST` body)

Define the policy file in the `POST` body.
Include the entire policy file.
Note that the supplied object fully replaces your existing tailnet policy file.

The `POST` body should be formatted as JSON or HuJSON.
Learn about the [ACL policy properties you can include in the request](https://tailscale.com/kb/1018/#tailscale-policy-syntax).

### Request example

```sh
POST /api/v2/tailnet/example.com/acl
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  -H "If-Match: \"e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c\""
  --data-binary '// Example/default ACLs for unrestricted connections.
{
  // Declare tests to check functionality of ACL rules. User must be a valid user with registered machines.
  "tests": [
    // {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "acls": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "action": "accept", "users": ["*"], "ports": ["*:*"] },
  ]
}'
```

### Response

A successful response returns an HTTP status of '200' and the modified tailnet policy file in JSON or HuJSON format, depending on the request header.

```jsonc
// Example/default ACLs for unrestricted connections.
{
  // Declare tests to check functionality of ACL rules. User must be a valid user with registered machines.
  "tests": [
    // {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": ["user1@example.com", "user2@example.com"]
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100"
  },
  // Access control lists.
  "acls": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "action": "accept", "users": ["*"], "ports": ["*:*"] }
  ]
}
```

### Response: failed test error

```
{
    "message": "test(s) failed",
    "data": [
        {
            "user": "user1@example.com",
            "errors": [
                "address \"user2@example.com:400\": want: Accept, got: Drop"
            ]
        }
    ]
}
```

## Preview policy file rule matches

```http
POST /api/v2/tailnet/{tailnet}/acl/preview
```

When given a user or IP port to match against, returns the tailnet policy rules that
apply to that resource without saving the policy file to the server.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `type` (required in query string)

Specify for which type of resource (user or IP port) matching rules are to be fetched.
Read about [previewing changes in the admin console](https://tailscale.com/kb/1018/#previewing-changes).

- `user`: Specify `user` if the `previewFor` value is a user's email.
  Note that `user` remains in the API for compatibility purposes, but has been replaced by `src` in policy files.
- `ipport`: Specify `ipport` if the `previewFor` value is an IP address and port.
  Note that `ipport` remains in the API for compatibility purposes, but has been replaced by `dst` in policy files.

#### `previewFor` (required in query string)

- If `type=user`, provide the email of a valid user with registered machines.
- If `type=ipport`, provide an IP address + port: `10.0.0.1:80`.

The supplied policy file is queried with this parameter to determine which rules match.

#### Tailnet policy file (required in `POST` body)

Provide the tailnet policy file in the `POST` body in JSON or HuJSON format.
Learn about [tailnet policy file entries](https://tailscale.com/kb/1018).

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl/preview?previewFor=user1@example.com&type=user" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '// Example/default ACLs for unrestricted connections.
{
  // Declare tests to check functionality of ACL rules. User must be a valid user with registered machines.
  "tests": [
    // {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "acls": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "action": "accept", "users": ["*"], "ports": ["*:*"] },
  ]
}'
```

### Response

A successful response returns an HTTP status of '200' and a list of rules that apply to the resource supplied as a list of matches as JSON objects.
Each match object includes:

- `users`: array of strings indicating source entities affected by the rule
- `ports`: array of strings representing destinations that can be accessed
- `lineNumber`: integer indicating the rule's location in the policy file

The response also echoes the `type` and `previewFor` values supplied in the request.

```jsonc
{
  "matches": [
    {
      "users": ["*"],
      "ports": ["*:*"],
      "lineNumber": 19
    }
  ],
  "type": "user",
  "previewFor: "user1@example.com"
}
```

## Validate and test policy file

```http
POST /api/v2/tailnet/{tailnet}/acl/validate
```

This method works in one of two modes, neither of which modifies your current tailnet policy file:

- **Run ACL tests:** When the **request body contains ACL tests as a JSON array**,
  Tailscale runs ACL tests against the tailnet's current policy file.
  Learn more about [ACL tests](https://tailscale.com/kb/1018/#tests).
- **Validate a new policy file:** When the **request body is a JSON object**,
  Tailscale interprets the body as a hypothetical new tailnet policy file with new ACLs, including any new rules and tests.
  It validates that the policy file is parsable and runs tests to validate the existing rules.

In either case, this method does not modify the tailnet policy file in any way.

### Parameters for "Run ACL tests" mode

#### `tailnet` (required in URL path)

The tailnet organization name.

#### ACL tests (required in `POST` body)

The `POST` body should be a JSON formatted array of ACL Tests.
Learn more about [tailnet policy file tests](https://tailscale.com/kb/1018/#tests).

### Request example to run ACL tests

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '
  [
    {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]}
  ]'
```

### Parameters for "Validate a new policy file" mode

#### `tailnet` (required in URL path)

The tailnet organization name.

#### Entire tailnet policy file (required in `POST` body)

The `POST` body should be a JSON object with a JSON or HuJSON representation of a tailnet policy file.

### Request example to validate a policy file

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '
  {
    "acls": [
     { "action": "accept", "src": ["100.105.106.107"], "dst": ["1.2.3.4:*"] },
    ],
    "tests", [
      {"src": "100.105.106.107", "allow": ["1.2.3.4:80"]}
    ],
  }'
```

### Response

The HTTP status code will be '200' if the request was well formed and there were no server errors, even in the case of failing tests or an invalid ACL.
Look at the response body to determine whether there was a problem within your ACL or tests:

- If the tests are valid, an empty body or a JSON object with no `message` is returned.
- If there's a problem, the response body will be a JSON object with a non-empty `message` property and optionally additional details in `data`:

  ```jsonc
  {
    "message": "test(s) failed",
    "data": [
      {
        "user": "user1@example.com",
        "errors": ["address \"2.2.2.2:22\": want: Drop, got: Accept"]
      }
    ]
  }
  ```

If your tailnet has [user and group provisioning](https://tailscale.com/kb/1180/sso-okta-scim/) turned on, we will also warn you about
any groups that are used in the policy file that are not being synced from SCIM. Explicitly defined groups will not trigger this warning.

```jsonc
{
  "message": "warning(s) found",
  "data": [
    {
      "user": "group:unknown@example.com",
      "warnings": [
        "group is not syncing from SCIM and will be ignored by rules in the policy file"
      ]
    }
  ]
}
```

## Devices

## List tailnet devices

```http
GET /api/v2/tailnet/{tailnet}/devices
```

Lists the devices in a tailnet.
Optionally use the `fields` query parameter to explicitly indicate which fields are returned.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `fields` (optional in query string)

Controls whether the response returns **all** fields or only a predefined subset of fields.
Currently, there are two supported options:

- **`all`:** return all fields in the response
- **`default`:** return all fields **except**:
  - `enabledRoutes`
  - `advertisedRoutes`
  - `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

If the `fields` parameter is not supplied, then the default (limited fields) option is used.

### Request example for default set of fields

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/devices" \
  -u "tskey-api-xxxxx:"
```

### Request example for all fields

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/devices?fields=all" \
  -u "tskey-api-xxxxx:"
```

### Response

On success, returns a 200 status code and a JSON array of the tailnet devices and their details.

## Tailnet keys

These methods operate primarily on auth keys, and in some cases on [API access tokens](#authentication).

- Auth keys: Pre-authentication keys (or "auth keys") let you register new devices on a tailnet without needing to sign in via a web browser.
  Auth keys are identifiable by the prefix `tskey-auth-`. Learn more about [auth keys](https://tailscale.com/kb/1085/).

- API access tokens: used to [authenticate API requests](#authentication).

If you authenticate with a user-owned API access token, all the methods on tailnet keys operate on _keys owned by that user_.
If you authenticate with an access token derived from an OAuth client, then these methods operate on _keys owned by the tailnet_.
Learn more about [OAuth clients](https://tailscale.com/kb/1215).

The `POST /api/v2/tailnet/{tailnet}/keys` method is used to create auth keys only.
The remaining three methods operate on auth keys and API access tokens.

### Attributes

```jsonc
{
  // capabilities (JSON object) is a mapping of resources to permissible
  // actions.
  "capabilities": {

    // devices (JSON object) specifies the key's permissions over devices.
    "devices": {

      // create (JSON object) specifies the key's permissions when
      // creating devices.
      "create": {

        // reusable (boolean) for auth keys only; reusable auth keys
        // can be used multiple times to register different devices.
        // Learn more about reusable auth keys at
        // https://tailscale.com/kb/1085/#types-of-auth-keys
        "reusable": false,

        // ephemeral (boolean) for auth keys only; ephemeral keys are
        // used to connect and then clean up short-lived devices.
        // Learn about ephemeral nodes at https://tailscale.com/kb/1111/.
        "ephemeral": false,

        // preauthorized (boolean) for auth keys only; these are also
        // referred to as "pre-approved" keys. 'true' means that devices
        // registered with this key won't require additional approval from a
        // tailnet admin.
        // Learn about device approval at https://tailscale.com/kb/1099/.
        "preauthorized": false,

        // tags (string) are the tags that will be set on devices registered
        // with this key.
        // Learn about tags at https://tailscale.com/kb/1068/.
        "tags": [
          "tag:example"
            ]
          }
        }
  }

  // expirySeconds (int) is the duration in seconds a new key is valid.
  "expirySeconds": 86400

  // description (string) is an optional short phrase that describes what
  // this key is used for. It can be a maximum of 50 alphanumeric characters.
  // Hyphens and underscores are also allowed.
  "description": "short description of key purpose"
}
```

## List tailnet keys

```http
GET /api/v2/tailnet/{tailnet}/keys
```

Returns a list of active auth keys and API access tokens. The set of keys returned depends on the access token used to make the request:

- If the API call is made with a user-owned API access token, this returns only the keys owned by that user.
- If the API call is made with an access token derived from an OAuth client, this returns all keys owned directly by the tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/keys" \
  -u "tskey-api-xxxxx:"
```

### Response

Returns a JSON object with the IDs of all active keys.

```jsonc
{
  "keys": [
    { "id": "XXXX14CNTRL" },
    { "id": "XXXXZ3CNTRL" },
    { "id": "XXXX43CNTRL" },
    { "id": "XXXXgj1CNTRL" }
  ]
}
```

## Create auth key

```http
POST /api/v2/tailnet/{tailnet}/keys
```

Creates a new auth key in the specified tailnet.
The key will be associated with the user who owns the API access token used to make this call,
or, if the call is made with an access token derived from an OAuth client, the key will be owned by the tailnet.

Returns a JSON object with the supplied capabilities in addition to the generated key.
The key should be recorded and kept safe and secure because it wields the capabilities specified in the request.
The identity of the key is embedded in the key itself and can be used to perform operations on the key (e.g., revoking it or retrieving information about it).
The full key can no longer be retrieved after the initial response.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### Tailnet key object (required in `POST` body)

Supply the tailnet key attributes as a JSON object in the `POST` body following the request example below.

At minimum, the request `POST` body must have a `capabilities` object (see below).
With nothing else supplied, such a request generates a single-use key with no tags.

Note the following about required vs. optional values:

- **`capabilities`:** A `capabilities` object is required and must contain `devices`.

- **`devices`:** A `devices` object is required within `capabilities`, but can be an empty JSON object.

- **`tags`:** Whether tags are required or optional depends on the owner of the auth key:

  - When creating an auth key _owned by the tailnet_ (using OAuth), it must have tags.
    The auth tags specified for that new auth key must exactly match the tags that are on the OAuth client used to create that auth key (or they must be tags that are owned by the tags that are on the OAuth client used to create the auth key).
  - When creating an auth key _owned by a user_ (using a user's access token), tags are optional.

- **`expirySeconds`:** Optional in `POST` body.
  Specifies the duration in seconds until the key should expire.
  Defaults to 90 days if not supplied.

- **`description`:** Optional in `POST` body.
  A short string specifying the purpose of the key. Can be a maximum of 50 alphanumeric characters. Hyphens and spaces are also allowed.

### Request example

```jsonc
curl "https://api.tailscale.com/api/v2/tailnet/example.com/keys" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '
{
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": false,
        "preauthorized": false,
        "tags": [ "tag:example" ]
      }
    }
  },
  "expirySeconds": 86400,
  "description": "dev access"
}'
```

### Response

The response is a JSON object that includes the `key` value, which will only be returned once.
Record and safely store the `key` returned.
It holds the capabilities specified in the request and can no longer be retrieved by the server.

```jsonc
{
  "id": "k123456CNTRL",
  "key": "tskey-auth-k123456CNTRL-abcdefghijklmnopqrstuvwxyz",
  "created": "2021-12-09T23:22:39Z",
  "expires": "2022-03-09T23:22:39Z",
  "revoked": "2022-03-12T23:22:39Z",
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": false,
        "preauthorized": false,
        "tags": ["tag:example"]
      }
    }
  },
  "description": "dev access"
}
```

## Get key

```http
GET /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Returns a JSON object with information about a specific key, such as its creation and expiration dates and its capabilities.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `keyId` (required in URL path)

The ID of the key.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL" \
  -u "tskey-api-xxxxx:"
```

### Response

The response is a JSON object with information about the key supplied.

```jsonc
{
  "id": "abc123456CNTRL",
  "created": "2022-05-05T18:55:44Z",
  "expires": "2022-08-03T18:55:44Z",
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": true,
        "preauthorized": false,
        "tags": ["tag:bar", "tag:foo"]
      }
    }
  },
  "description": "dev access"
}
```

Response for a revoked (deleted) or expired key will have an `invalid` field set to `true`:

```jsonc
{
  "id": "abc123456CNTRL",
  "created": "2022-05-05T18:55:44Z",
  "expires": "2022-08-03T18:55:44Z",
  "revoked": "2023-04-01T20:50:00Z",
  "invalid": true
}
```

## Delete key

```http
DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Deletes a specific key.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `keyId` (required in URL path)

The ID of the key. The key ID can be found in the [admin console](https://login.tailscale.com/admin/settings/keys).

### Request example

```sh
curl -X DELETE 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-api-xxxxx:"
```

### Response

This returns status 200 upon success.

## DNS

The tailnet DNS methods are provided for fetching and modifying various DNS settings for a tailnet.
These include nameservers, DNS preferences, and search paths.
Learn more about [DNS in Tailscale](https://tailscale.com/kb/1054/).

## Nameservers

## Get nameservers

```http
GET /api/v2/tailnet/{tailnet}/dns/nameservers
```

Lists the global DNS nameservers for a tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers" \
  -u "tskey-api-xxxxx:"
```

### Response

```jsonc
{
  "dns": ["8.8.8.8"]
}
```

## Set nameservers

```http
POST /api/v2/tailnet/{tailnet}/dns/nameservers
```

Replaces the list of global DNS nameservers for the given tailnet with the list supplied in the request.
Note that changing the list of DNS nameservers may also affect the status of MagicDNS (if MagicDNS is on; learn about [MagicDNS](https://tailscale.com/kb/1081).
If all nameservers have been removed, MagicDNS will be automatically disabled (until explicitly turned back on by the user).

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `dns` (required in `POST` body)

The new list of DNS nameservers in JSON.

```jsonc
{
  "dns": ["8.8.8.8"]
}
```

### Request example: adding DNS nameservers with MagicDNS on

Adding DNS nameservers with the MagicDNS on:

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{"dns": ["8.8.8.8"]}'
```

### Response example: adding DNS nameservers, MagicDNS on

The response is a JSON object containing the new list of nameservers and the status of MagicDNS.

```jsonc
{
  "dns": ["8.8.8.8"],
  "magicDNS": true
}
```

### Request example: removing all DNS nameservers, MagicDNS on

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{"dns": []}'
```

### Response example: removing all DNS nameservers with MagicDNS on

The response is a JSON object containing the new list of nameservers and the status of MagicDNS.

```jsonc
{
  "dns": [],
  "magicDNS": false
}
```

## Preferences

## Get DNS preferences

```http
GET /api/v2/tailnet/{tailnet}/dns/preferences`
```

Retrieves the DNS preferences that are currently set for the given tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences" \
  -u "tskey-api-xxxxx:"
```

### Response

```jsonc
{
  "magicDNS": false
}
```

## Set DNS preferences

```http
POST /api/v2/tailnet/{tailnet}/dns/preferences
```

Set the DNS preferences for a tailnet; specifically, the MagicDNS setting.
Note that MagicDNS is dependent on DNS servers.
Learn about [MagicDNS](https://tailscale.com/kb/1081).

If there is at least one DNS server, then MagicDNS can be enabled.
Otherwise, it returns an error.

Note that removing all nameservers will turn off MagicDNS.
To reenable it, nameservers must be added back, and MagicDNS must be explicitly turned on.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### DNS preference (required in `POST` body)

The DNS preferences in JSON. Currently, MagicDNS is the only setting available:

- **`magicDNS`:** Automatically registers DNS names for devices in your tailnet.

```jsonc
{
  "magicDNS": true
}
```

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{"magicDNS": true}'
```

### Response

If there are no DNS servers, this returns an error message:

```jsonc
{
  "message": "need at least one nameserver to enable MagicDNS"
}
```

If there are DNS servers, this returns the MagicDNS status:

```jsonc
{
  "magicDNS": true
}
```

## Search Paths

## Get search paths

```http
GET /api/v2/tailnet/{tailnet}/dns/searchpaths
```

Retrieves the list of search paths, also referred to as _search domains_, that is currently set for the given tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths" \
  -u "tskey-api-xxxxx:"
```

### Response

```jsonc
{
  "searchPaths": ["user1.example.com"]
}
```

## Set search paths

```http
POST /api/v2/tailnet/{tailnet}/dns/searchpaths
```

Replaces the list of search paths with the list supplied by the user and returns an error otherwise.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `searchPaths` (required in `POST` body)

Specify a list of search paths in a JSON object:

```jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"]
}
```

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{"searchPaths": ["user1.example.com", "user2.example.com"]}'
```

### Response

The response is a JSON object containing the new list of search paths.

```jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"]
}
```

## Split DNS

## Get split DNS

```http
GET /api/v2/tailnet/{tailnet}/dns/split-dns
```

Retrieves the split DNS settings, which is a map from domains to lists of nameservers, that is currently set for the given tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/split-dns" \
  -u "tskey-api-xxxxx:"
```

### Response

```jsonc
{
  "example.com": ["1.1.1.1", "1.2.3.4"],
  "other.com": ["2.2.2.2"]
}
```

## Update split DNS

```http
PATCH /api/v2/tailnet/{tailnet}/dns/split-dns
```

Performs partial updates of the split DNS settings for a given tailnet. Only domains specified in the request map will be modified. Setting the value of a mapping to "null" clears the nameservers for that domain.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `PATCH` body format

Specify mappings from domain name to a list of nameservers in a JSON object:

```jsonc
{
  "example.com": ["1.1.1.1", "1.2.3.4"],
  "other.com": ["2.2.2.2"]
}
```

### Request example: updating split DNS settings for multiple domains

```sh
curl -X PATCH "https://api.tailscale.com/api/v2/tailnet/example.com/dns/split-dns" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{"example.com": ["1.1.1.1", "1.2.3.4"], "other.com": ["2.2.2.2"]}'
```

### Response: updating split DNS settings for multiple domains

The response is a JSON object containing the updated map of split DNS settings.

```jsonc
{
  "example.com": ["1.1.1.1", "1.2.3.4"],
  "other.com": ["2.2.2.2"],
  <existing unmodified key / value pairs>
}
```

### Request example: unsetting nameservers for a domain

```sh
curl -X PATCH "https://api.tailscale.com/api/v2/tailnet/example.com/dns/split-dns" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{"example.com": null}'
```

### Response: unsetting nameservers for a domain

The response is a JSON object containing the updated map of split DNS settings.

```jsonc
{
  <existing unmodified key / value pairs without example.com>
}
```

## Set split DNS

```http
PUT /api/v2/tailnet/{tailnet}/dns/split-dns
```

Replaces the split DNS settings for a given tailnet. Setting the value of a mapping to "null" clears the nameservers for that domain. Sending an empty object clears nameservers for all domains.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `PUT` body format

Specify mappings from domain name to a list of nameservers in a JSON object:

```jsonc
{
  "example.com": ["1.2.3.4"],
  "other.com": ["2.2.2.2"]
}
```

### Request example: setting multiple domains

```sh
curl -X PUT "https://api.tailscale.com/api/v2/tailnet/example.com/dns/split-dns" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{"example.com": ["1.2.3.4"], "other.com": ["2.2.2.2"]}'
```

### Response: unsetting nameservers for a domain

The response is a JSON object containing the updated map of split DNS settings.

```jsonc
{
  "example.com": ["1.2.3.4"],
  "other.com": ["2.2.2.2"]
}
```

### Request example: unsetting all domains

```sh
curl -X PUT "https://api.tailscale.com/api/v2/tailnet/example.com/dns/split-dns" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '{}'
```

### Response: unsetting nameservers for a domain

The response is a JSON object containing the updated map of split DNS settings.

```jsonc
{}
```

## Tailnet user invites

The tailnet user invite methods let you create and list [invites](https://tailscale.com/kb/1371/invite-users).

## List user invites

```http
GET /api/v2/tailnet/{tailnet}/user-invites
```

List all user invites that haven't been accepted.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

```sh
curl -X GET "https://api.tailscale.com/api/v2/tailnet/example.com/user-invites" \
-u "tskey-api-xxxxx:"
```

### Response

```jsonc
[
  {
    "id": "29214",
    "role": "member",
    "tailnetId": 12345,
    "inviterId": 34567,
    "email": "user@example.com",
    "lastEmailSentAt": "2024-05-09T16:13:16.084568545Z",
    "inviteUrl": "https://login.tailscale.com/uinv/<code>"
  },
  {
    "id": "29215",
    "role": "admin",
    "tailnetId": 12345,
    "inviterId": 34567,
    "inviteUrl": "https://login.tailscale.com/uinv/<code>"
  }
]
```

## Create user invites

```http
POST /api/v2/tailnet/{tailnet}/user-invites
```

Create new user invites to join the tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### List of invite requests (required in `POST` body)

Each invite request is an object with the following optional fields:

- **`role`:** (Optional) Specify a [user role](https://tailscale.com/kb/1138/user-roles) to assign the invited user. Defaults to the `"member"` role. Valid options are:
  - `"member"`: Assign the Member role.
  - `"admin"`: Assign the Admin role.
  - `"it-admin"`: Assign the IT admin role.
  - `"network-admin"`: Assign the Network admin role.
  - `"billing-admin"`: Assign the Billing admin role.
  - `"auditor"`: Assign the Auditor role.
- **`email`:** (Optional) Specify the email to send the created invite. If not set, the endpoint generates and returns an invite URL (but doesn't send it out).

### Request example

```sh
curl -X POST "https://api.tailscale.com/api/v2/tailnet/example.com/user-invites" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '[{"role": "admin", "email":"user@example.com"}]'
```

### Response

```jsonc
[
  {
    "id": "29214",
    "role": "admin",
    "tailnetId": 12345,
    "inviterId": 34567,
    "email": "user@example.com",
    "lastEmailSentAt": "2024-05-09T16:23:26.91778771Z",
    "inviteUrl": "https://login.tailscale.com/uinv/<code>"
  }
]
```
