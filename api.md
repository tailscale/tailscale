# Tailscale API

The Tailscale API is a (mostly) RESTful API. Typically, POST bodies should be JSON encoded and responses will be JSON encoded.

# Authentication
Currently based on {some authentication method}. Visit the [admin console](https://login.tailscale.com/admin) and navigate to the `Settings` page. Generate an API Key and keep it safe. Provide the key as the user key in basic auth when making calls to Tailscale API endpoints (leave the password blank).

# APIs

* **[Devices](#device)**
  - [GET device](#device-get)
  - [DELETE device](#device-delete)
  - Routes
    - [GET device routes](#device-routes-get)
    - [POST device routes](#device-routes-post)
  - Authorize machine
    - [POST device authorized](#device-authorized-post)
  - Tags
    - [POST device tags](#device-tags-post)
  - Key
    - [POST device key](#device-key-post)
* **[Tailnets](#tailnet)**
  - ACLs
    - [GET tailnet ACL](#tailnet-acl-get)
    - [POST tailnet ACL](#tailnet-acl-post)
    - [POST tailnet ACL preview](#tailnet-acl-preview-post)
	- [POST tailnet ACL validate](#tailnet-acl-validate-post)
  - [Devices](#tailnet-devices)
    - [GET tailnet devices](#tailnet-devices-get)
  - [Keys](#tailnet-keys)
    - [GET tailnet keys](#tailnet-keys-get)
    - [POST tailnet key](#tailnet-keys-post)
    - [GET tailnet key](#tailnet-keys-key-get)
    - [DELETE tailnet key](#tailnet-keys-key-delete)
  - [DNS](#tailnet-dns)
    - [GET tailnet DNS nameservers](#tailnet-dns-nameservers-get)
    - [POST tailnet DNS nameservers](#tailnet-dns-nameservers-post)
    - [GET tailnet DNS preferences](#tailnet-dns-preferences-get)
    - [POST tailnet DNS preferences](#tailnet-dns-preferences-post)
    - [GET tailnet DNS searchpaths](#tailnet-dns-searchpaths-get)
    - [POST tailnet DNS searchpaths](#tailnet-dns-searchpaths-post)

## Device
<!-- TODO: description about what devices are -->
Each Tailscale-connected device has a globally-unique identifier number which we refer as the "deviceID" or sometimes, just "id".
You can use the deviceID to specify operations on a specific device, like retrieving its subnet routes.

To find the deviceID of a particular device, you can use the ["GET /devices"](#getdevices) API call and generate a list of devices on your network.
Find the device you're looking for and get the "id" field.
This is your deviceID.

<a name=device-get></a>

#### `GET /api/v2/device/:deviceid` - lists the details for a device
Returns the details for the specified device.
Supply the device of interest in the path using its ID.
Use the `fields` query parameter to explicitly indicate which fields are returned.


##### Parameters
##### Query Parameters
`fields` - Controls which fields will be included in the returned response.
Currently, supported options are:
* `all`: returns all fields in the response.
* `default`: return all fields except:
  * `enabledRoutes`
  * `advertisedRoutes`
  * `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

Use commas to separate multiple options.
If more than one option is indicated, then the union is used.
For example, for `fields=default,all`, all fields are returned.
If the `fields` parameter is not provided, then the default option is used.

##### Example
```
GET /api/v2/device/12345
curl 'https://api.tailscale.com/api/v2/device/12345?fields=all' \
  -u "tskey-yourapikey123:"
```

Response
```
{
  "addresses":[
    "100.105.58.116"
  ],
  "id":"12345",
  "user":"user1@example.com",
  "name":"user1-device.example.com",
  "hostname":"User1-Device",
  "clientVersion":"date.20201107",
  "updateAvailable":false,
  "os":"macOS",
  "created":"2020-11-20T20:56:49Z",
  "lastSeen":"2020-11-20T16:15:55-05:00",
  "keyExpiryDisabled":false,
  "expires":"2021-05-19T20:56:49Z",
  "authorized":true,
  "isExternal":false,
  "machineKey":"mkey:user1-machine-key",
  "nodeKey":"nodekey:user1-node-key",
  "blocksIncomingConnections":false,
  "enabledRoutes":[

  ],
  "advertisedRoutes":[

  ],
  "clientConnectivity": {
    "endpoints":[
      "209.195.87.231:59128",
      "192.168.0.173:59128"
    ],
    "derp":"",
    "mappingVariesByDestIP":false,
    "latency":{
      "Dallas":{
        "latencyMs":60.463043
      },
      "New York City":{
        "preferred":true,
        "latencyMs":31.323811
      },
      "San Francisco":{
        "latencyMs":81.313389
      }
    },
    "clientSupports":{
      "hairPinning":false,
      "ipv6":false,
      "pcp":false,
      "pmp":false,
      "udp":true,
      "upnp":false
    }
  }
}
```

<a name=device-delete></a>

#### `DELETE /api/v2/device/:deviceID` - deletes the device from its tailnet
Deletes the provided device from its tailnet.
The device must belong to the user's tailnet.
Deleting shared/external devices is not supported.
Supply the device of interest in the path using its ID.


##### Parameters
No parameters.

##### Example
```
DELETE /api/v2/device/12345
curl -X DELETE 'https://api.tailscale.com/api/v2/device/12345' \
  -u "tskey-yourapikey123:" -v
```

Response

If successful, the response should be empty:
```
< HTTP/1.1 200 OK
...
* Connection #0 to host left intact
* Closing connection 0
```

If the device is not owned by your tailnet:
```
< HTTP/1.1 501 Not Implemented
...
{"message":"cannot delete devices outside of your tailnet"}
```


<a name=device-routes-get></a>

#### `GET /api/v2/device/:deviceID/routes` - fetch subnet routes that are advertised and enabled for a device

Retrieves the list of subnet routes that a device is advertising, as well as those that are enabled for it. Enabled routes are not necessarily advertised (e.g. for pre-enabling), and likewise, advertised routes are not necessarily enabled.

##### Parameters

No parameters.

##### Example

```
curl 'https://api.tailscale.com/api/v2/device/11055/routes' \
-u "tskey-yourapikey123:"
```

Response
```
{
   "advertisedRoutes" : [
      "10.0.1.0/24",
      "1.2.0.0/16",
      "2.0.0.0/24"
   ],
   "enabledRoutes" : []
}
```

<a name=device-routes-post></a>

#### `POST /api/v2/device/:deviceID/routes` - set the subnet routes that are enabled for a device

Sets which subnet routes are enabled to be routed by a device by replacing the existing list of subnet routes with the supplied parameters. Routes can be enabled without a device advertising them (e.g. for preauth). Returns a list of enabled subnet routes and a list of advertised subnet routes for a device.

##### Parameters

###### POST Body
`routes` - The new list of enabled subnet routes in JSON.
```
{
  "routes": ["10.0.1.0/24", "1.2.0.0/16", "2.0.0.0/24"]
}
```

##### Example

```
curl 'https://api.tailscale.com/api/v2/device/11055/routes' \
-u "tskey-yourapikey123:" \
--data-binary '{"routes": ["10.0.1.0/24", "1.2.0.0/16", "2.0.0.0/24"]}'
```

Response

```
{
   "advertisedRoutes" : [
      "10.0.1.0/24",
      "1.2.0.0/16",
      "2.0.0.0/24"
   ],
   "enabledRoutes" : [
      "10.0.1.0/24",
      "1.2.0.0/16",
      "2.0.0.0/24"
   ]
}
```

<a name=device-authorized-post></a>

#### `POST /api/v2/device/:deviceID/authorized` - authorize a device

Marks a device as authorized, for Tailnets where device authorization is required.

##### Parameters

###### POST Body
`authorized` - whether the device is authorized; only `true` is currently supported.
```
{
  "authorized": true
}
```

##### Example

```
curl 'https://api.tailscale.com/api/v2/device/11055/authorized' \
-u "tskey-yourapikey123:" \
--data-binary '{"authorized": true}'
```

The response is 2xx on success. The response body is currently an empty JSON
object.

<a name=device-tags-post></a>

#### `POST /api/v2/device/:deviceID/tags` - update tags on a device

Updates the tags set on a device.

##### Parameters

###### POST Body

`tags` - The new list of tags for the device.

```
{
  "tags": ["tag:foo", "tag:bar"]
}
```

##### Example

```
curl 'https://api.tailscale.com/api/v2/device/11055/tags' \
-u "tskey-yourapikey123:" \
--data-binary '{"tags": ["tag:foo", "tag:bar"]}'
```

The response is 2xx on success. The response body is currently an empty JSON
object.

<a name=device-key-post></a>

#### `POST /api/v2/device/:deviceID/key` - update device key

Allows for updating properties on the device key.

##### Parameters

###### POST Body

`keyExpiryDisabled`

- Provide `true` to disable the device's key expiry. The original key expiry time is still maintained. Upon re-enabling, the key will expire at that original time.
- Provide `false` to enable the device's key expiry. Sets the key to expire at the original expiry time prior to disabling. The key may already have expired. In that case, the device must be re-authenticated.
- Empty value will not change the key expiry.

```
{
  "keyExpiryDisabled": true
}
```

##### Example

```
curl 'https://api.tailscale.com/api/v2/device/11055/key' \
-u "tskey-yourapikey123:" \
--data-binary '{"keyExpiryDisabled": true}'
```

The response is 2xx on success. The response body is currently an empty JSON
object.

## Tailnet

A tailnet is your private network, composed of all the devices on it and their configuration. For more information on tailnets, see [our user-facing documentation](https://tailscale.com/kb/1136/tailnet/).

When making API requests, your tailnet is identified by the organization name. You can find it on the [Settings page](https://login.tailscale.com/admin/settings) of the admin console.

For example, if `alice@example.com` belongs to the `example.com` tailnet, they would use the following format for API calls:

```
GET /api/v2/tailnet/example.com/...
curl https://api.tailscale.com/api/v2/tailnet/example.com/...
```


For solo plans, the tailnet is the email you signed up with.
So `alice@gmail.com` has the tailnet `alice@gmail.com` since `@gmail.com` is a shared email host.
Her API calls would have the following format:
```
GET /api/v2/tailnet/alice@gmail.com/...
curl https://api.tailscale.com/api/v2/tailnet/alice@gmail.com/...
```

Alternatively, you can specify the value "-" to refer to the default tailnet of
the authenticated user making the API call.  For example:
```
GET /api/v2/tailnet/-/...
curl https://api.tailscale.com/api/v2/tailnet/-/...
```

Tailnets are a top-level resource. ACL is an example of a resource that is tied to a top-level tailnet.

### ACL

<a name=tailnet-acl-get></a>

#### `GET /api/v2/tailnet/:tailnet/acl` - fetch ACL for a tailnet

Retrieves the ACL that is currently set for the given tailnet. Supply the tailnet of interest in the path. This endpoint can send back either the HuJSON of the ACL or a parsed JSON, depending on the `Accept` header.

##### Parameters

###### Headers
`Accept` - Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

##### Returns
Returns the ACL HuJSON by default. Returns a parsed JSON of the ACL (sans comments) if the `Accept` type is explicitly set to `application/json`. An `ETag` header is also sent in the response, which can be optionally used in POST requests to avoid missed updates.
<!-- TODO (chungdaniel): define error types and a set of docs for them -->

##### Example

###### Requesting a HuJSON response:
```
GET /api/v2/tailnet/example.com/acl
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl' \
  -u "tskey-yourapikey123:" \
  -H "Accept: application/hujson" \
  -v
```

Response
```
...
Content-Type: application/hujson
Etag: "e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c"
...

// Example/default ACLs for unrestricted connections.
{
    "tests": [],
    // Declare static groups of users beyond those in the identity service.
    "groups": {
        "group:example": [
            "user1@example.com",
            "user2@example.com"
        ],
    },
    // Declare convenient hostname aliases to use in place of IP addresses.
    "hosts": {
        "example-host-1": "100.100.100.100",
    },
    // Access control lists.
    "acls": [
        // Match absolutely everything. Comment out this section if you want
        // to define specific ACL restrictions.
        {
            "Action": "accept",
            "Users": [
                "*"
            ],
            "Ports": [
                "*:*"
            ]
        },
    ]
}
```

###### Requesting a JSON response:
```
GET /api/v2/tailnet/example.com/acl
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl' \
  -u "tskey-yourapikey123:" \
  -H "Accept: application/json" \
  -v
```

Response
```
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

<a name=tailnet-acl-post></a>

#### `POST /api/v2/tailnet/:tailnet/acl` - set ACL for a tailnet

Sets the ACL for the given domain.
HuJSON and JSON are both accepted inputs.
An `If-Match` header can be set to avoid missed updates.

Returns the updated ACL in JSON or HuJSON according to the `Accept` header on success. Otherwise, errors are returned for incorrectly defined ACLs, ACLs with failing tests on attempted updates, and mismatched `If-Match` header and ETag.

##### Parameters

###### Headers
`If-Match` - A request header. Set this value to the ETag header provided in an `ACL GET` request to avoid missed updates.

A special value `ts-default` will ensure that ACL will be set only if current ACL is the default one (created automatically for each tailnet).

`Accept` - Sets the return type of the updated ACL. Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

###### POST Body

The POST body should be a JSON or [HuJSON](https://github.com/tailscale/hujson#hujson---human-json) formatted JSON object.
An ACL policy may contain the following top-level properties:

* `groups` - Static groups of users which can be used for ACL rules.
* `hosts` - Hostname aliases to use in place of IP addresses or subnets.
* `acls` - Access control lists.
* `tagOwners` - Defines who is allowed to use which tags.
* `tests` - Run on ACL updates to check correct functionality of defined ACLs.
* `autoApprovers` - Defines which users can advertise routes or exit nodes without further approval.
* `ssh` - Configures access policy for Tailscale SSH.
* `nodeAttrs` - Defines which devices can use certain features.

See https://tailscale.com/kb/1018/acls for more information on those properties.

##### Example
```
POST /api/v2/tailnet/example.com/acl
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl' \
  -u "tskey-yourapikey123:" \
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

Response:
```
// Example/default ACLs for unrestricted connections.
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
}
```

Failed test error response:
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

<a name=tailnet-acl-preview-post></a>

#### `POST /api/v2/tailnet/:tailnet/acl/preview` - preview rule matches on an ACL for a resource

Determines what rules match for a user on an ACL without saving the ACL to the server.

##### Parameters

###### Query Parameters
`type` - can be 'user' or 'ipport'
`previewFor` - if type=user, a user's email. If type=ipport, a IP address + port like "10.0.0.1:80".
The provided ACL is queried with this parameter to determine which rules match.

###### POST Body
ACL JSON or HuJSON (see https://tailscale.com/kb/1018/acls)

##### Example
```
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl/preview?previewFor=user1@example.com&type=user' \
  -u "tskey-yourapikey123:" \
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

Response:
```
{"matches":[{"users":["*"],"ports":["*:*"],"lineNumber":19}],"user":"user1@example.com"}
```

<a name=tailnet-acl-validate-post></a>

#### `POST /api/v2/tailnet/:tailnet/acl/validate` - run validation tests against the tailnet's active ACL

This endpoint works in one of two modes:

1. with a request body that's a JSON array, the body is interpreted as ACL tests to run against the domain's current ACLs.
2. with a request body that's a JSON object, the body is interpreted as a hypothetical new JSON (HuJSON) body with new ACLs, including any tests.

In either case, this endpoint does not modify the ACL in any way.

##### Parameters

###### POST Body

The POST body should be a JSON formatted array of ACL Tests.

See https://tailscale.com/kb/1018/acls for more information on the format of ACL tests.

##### Example with tests
```
POST /api/v2/tailnet/example.com/acl/validate
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate' \
  -u "tskey-yourapikey123:" \
  --data-binary '
  [
    {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]}
  ]'
```

##### Example with an ACL body
```
POST /api/v2/tailnet/example.com/acl/validate
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate' \
  -u "tskey-yourapikey123:" \
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

Response:

The HTTP status code will be 200 if the request was well formed and there were no server errors, even in the case of failing tests or an invalid ACL. Look at the response body to determine whether there was a problem within your ACL or tests.

If there's a problem, the response body will be a JSON object with a non-empty `message` property and optionally additional details in `data`:

```
{
  "message":"test(s) failed",
  "data":[
           {
             "user":"user1@example.com",
             "errors":["address \"2.2.2.2:22\": want: Drop, got: Accept"]
           }
         ]
}
```

An empty body or a JSON object with no `message` is returned on success.

<a name=tailnet-devices></a>

### Devices

<a name=tailnet-devices-get></a>

#### <a name="getdevices"></a> `GET /api/v2/tailnet/:tailnet/devices` - list the devices for a tailnet
Lists the devices in a tailnet.
Supply the tailnet of interest in the path.
Use the `fields` query parameter to explicitly indicate which fields are returned.


##### Parameters

###### Query Parameters
`fields` - Controls which fields will be included in the returned response.
Currently, supported options are:
* `all`: Returns all fields in the response.
* `default`: return all fields except:
  * `enabledRoutes`
  * `advertisedRoutes`
  * `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

Use commas to separate multiple options.
If more than one option is indicated, then the union is used.
For example, for `fields=default,all`, all fields are returned.
If the `fields` parameter is not provided, then the default option is used.

##### Example

```
GET /api/v2/tailnet/example.com/devices
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/devices' \
  -u "tskey-yourapikey123:"
```

Response
```
{
  "devices":[
    {
      "addresses":[
        "100.68.203.125"
      ],
      "clientVersion":"date.20201107",
      "os":"macOS",
      "name":"user1-device.example.com",
      "created":"2020-11-30T22:20:04Z",
      "lastSeen":"2020-11-30T17:20:04-05:00",
      "hostname":"User1-Device",
      "machineKey":"mkey:user1-node-key",
      "nodeKey":"nodekey:user1-node-key",
      "id":"12345",
      "user":"user1@example.com",
      "expires":"2021-05-29T22:20:04Z",
      "keyExpiryDisabled":false,
      "authorized":false,
      "isExternal":false,
      "updateAvailable":false,
      "blocksIncomingConnections":false,
    },
    {
      "addresses":[
        "100.111.63.90"
      ],
      "clientVersion":"date.20201107",
      "os":"macOS",
      "name":"user2-device.example.com",
      "created":"2020-11-30T22:21:03Z",
      "lastSeen":"2020-11-30T17:21:03-05:00",
      "hostname":"User2-Device",
      "machineKey":"mkey:user2-machine-key",
      "nodeKey":"nodekey:user2-node-key",
      "id":"48810",
      "user":"user2@example.com",
      "expires":"2021-05-29T22:21:03Z",
      "keyExpiryDisabled":false,
      "authorized":false,
      "isExternal":false,
      "updateAvailable":false,
      "blocksIncomingConnections":false,
    }
  ]
}
```

<a name=tailnet-keys></a>

### Keys

<a name=tailnet-keys-get></a>

#### `GET /api/v2/tailnet/:tailnet/keys` - list the keys for a tailnet

Returns a list of active keys for a tailnet
for the user who owns the API key used to perform this query.
Supply the tailnet of interest in the path.

##### Parameters
No parameters.

##### Returns

Returns a JSON object with the IDs of all active keys.
This includes both API keys and also machine authentication keys.
In the future, this may provide more information about each key than just the ID.

##### Example

```
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys' \
  -u "tskey-yourapikey123:"
```

Response:
```
{"keys": [
	{"id": "kYKVU14CNTRL"},
	{"id": "k68VdZ3CNTRL"},
	{"id": "kJ9nq43CNTRL"},
	{"id": "kkThgj1CNTRL"}
]}
```

<a name=tailnet-keys-post></a>

#### `POST /api/v2/tailnet/:tailnet/keys` - create a new key for a tailnet

Create a new key in a tailnet associated
with the user who owns the API key used to perform this request.
Supply the tailnet in the path.

##### Parameters

###### POST Body
`capabilities` - A mapping of resources to permissible actions.

`expirySeconds` - (Optional) How long the key is valid for in seconds.
                  Defaults to 90d.

```
{
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": false,
        "preauthorized": false,
        "tags": [
          "tag:example"
        ]
      }
    }
  },
  "expirySeconds": 1440
}
```

##### Returns

Returns a JSON object with the provided capabilities in addition to the
generated key. The key should be recorded and kept safe and secure as it
wields the capabilities specified in the request. The identity of the key
is embedded in the key itself and can be used to perform operations on
the key (e.g., revoking it or retrieving information about it).
The full key can no longer be retrieved by the server.

##### Example

```
echo '{
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": false,
        "preauthorized": false,
        "tags": [ "tag:example" ]
      }
    }
  }
}' | curl -X POST --data-binary @- https://api.tailscale.com/api/v2/tailnet/example.com/keys \
  -u "tskey-yourapikey123:" \
  -H "Content-Type: application/json" | jsonfmt
```

Response:
```
{
	"id":           "k123456CNTRL",
	"key":          "tskey-k123456CNTRL-abcdefghijklmnopqrstuvwxyz",
	"created":      "2021-12-09T23:22:39Z",
	"expires":      "2022-03-09T23:22:39Z",
	"capabilities": {"devices": {"create": {"reusable": false, "ephemeral": false, "preauthorized": false, "tags": [ "tag:example" ]}}}
}
```

<a name=tailnet-keys-key-get></a>

#### `GET /api/v2/tailnet/:tailnet/keys/:keyid` - get information for a specific key

Returns a JSON object with information about specific key.
Supply the tailnet and key ID of interest in the path.

##### Parameters
No parameters.

##### Returns

Returns a JSON object with information about the key such as
when it was created and when it expires.
It also lists the capabilities associated with the key.

##### Example

```
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-yourapikey123:"
```

Response:
```
{
  "id": "k123456CNTRL",
  "created": "2022-05-05T18:55:44Z",
  "expires": "2022-08-03T18:55:44Z",
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": true,
        "preauthorized": false,
        "tags": [
          "tag:bar",
          "tag:foo"
        ]
      }
    }
  }
}
```

<a name=tailnet-keys-key-delete></a>

#### `DELETE /api/v2/tailnet/:tailnet/keys/:keyid` - delete a specific key

Deletes a specific key.
Supply the tailnet and key ID of interest in the path.

##### Parameters
No parameters.

##### Returns
This reports status 200 upon success.

##### Example

```
curl -X DELETE 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-yourapikey123:"
```

<a name=tailnet-dns></a>

### DNS

<a name=tailnet-dns-nameservers-get></a>

#### `GET /api/v2/tailnet/:tailnet/dns/nameservers` - list the DNS nameservers for a tailnet
Lists the DNS nameservers for a tailnet.
Supply the tailnet of interest in the path.

##### Parameters
No parameters.

##### Example

```
GET /api/v2/tailnet/example.com/dns/nameservers
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:"
```

Response
```
{
  "dns": ["8.8.8.8"],
}
```

<a name=tailnet-dns-nameservers-post></a>

#### `POST /api/v2/tailnet/:tailnet/dns/nameservers` - replaces the list of DNS nameservers for a tailnet
Replaces the list of DNS nameservers for the given tailnet with the list supplied by the user.
Supply the tailnet of interest in the path.
Note that changing the list of DNS nameservers may also affect the status of MagicDNS (if MagicDNS is on).

##### Parameters
###### POST Body
`dns` - The new list of DNS nameservers in JSON.
```
{
  "dns":["8.8.8.8"]
}
```

##### Returns
Returns the new list of nameservers and the status of MagicDNS.

If all nameservers have been removed, MagicDNS will be automatically disabled (until explicitly turned back on by the user).

##### Example
###### Adding DNS nameservers with the MagicDNS on:
```
POST /api/v2/tailnet/example.com/dns/nameservers
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"dns": ["8.8.8.8"]}'
```

Response:
```
{
  "dns":["8.8.8.8"],
  "magicDNS":true,
}
```

###### Removing all DNS nameservers with the MagicDNS on:
```
POST /api/v2/tailnet/example.com/dns/nameservers
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"dns": []}'
```

Response:
```
{
  "dns":[],
  "magicDNS": false,
}
```

<a name=tailnet-dns-preferences-get></a>

#### `GET /api/v2/tailnet/:tailnet/dns/preferences` - retrieves the DNS preferences for a tailnet
Retrieves the DNS preferences that are currently set for the given tailnet.
Supply the tailnet of interest in the path.

##### Parameters
No parameters.

##### Example
```
GET /api/v2/tailnet/example.com/dns/preferences
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences' \
  -u "tskey-yourapikey123:"
```

Response:
```
{
  "magicDNS":false,
}
```

<a name=tailnet-dns-preferences-post></a>

#### `POST /api/v2/tailnet/:tailnet/dns/preferences` - replaces the DNS preferences for a tailnet
Replaces the DNS preferences for a tailnet, specifically, the MagicDNS setting.
Note that MagicDNS is dependent on DNS servers.

If there is at least one DNS server, then MagicDNS can be enabled.
Otherwise, it returns an error.
Note that removing all nameservers will turn off MagicDNS.
To reenable it, nameservers must be added back, and MagicDNS must be explicitly turned on.

##### Parameters
###### POST Body
The DNS preferences in JSON. Currently, MagicDNS is the only setting available.
`magicDNS` -  Automatically registers DNS names for devices in your tailnet.
```
{
  "magicDNS": true
}
```

##### Example
```
POST /api/v2/tailnet/example.com/dns/preferences
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"magicDNS": true}'
```


Response:

If there are no DNS servers, it returns an error message:
```
{
  "message":"need at least one nameserver to enable MagicDNS"
}
```

If there are DNS servers:
```
{
  "magicDNS":true,
}
```

<a name=tailnet-dns-searchpaths-get></a>

#### `GET /api/v2/tailnet/:tailnet/dns/searchpaths` - retrieves the search paths for a tailnet
Retrieves the list of search paths that is currently set for the given tailnet.
Supply the tailnet of interest in the path.


##### Parameters
No parameters.

##### Example
```
GET /api/v2/tailnet/example.com/dns/searchpaths
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:"
```

Response:
```
{
  "searchPaths": ["user1.example.com"],
}
```

<a name=tailnet-dns-searchpaths-post></a>

#### `POST /api/v2/tailnet/:tailnet/dns/searchpaths` - replaces the search paths for a tailnet
Replaces the list of searchpaths with the list supplied by the user and returns an error otherwise.

##### Parameters

###### POST Body
`searchPaths` - A list of searchpaths in JSON.
```
{
  "searchPaths": ["user1.example.com", "user2.example.com"]
}
```

##### Example
```
POST /api/v2/tailnet/example.com/dns/searchpaths
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"searchPaths": ["user1.example.com", "user2.example.com"]}'
```

Response:
```
{
  "searchPaths": ["user1.example.com", "user2.example.com"],
}
```
