# Tailscale API

The Tailscale API is a (mostly) RESTful API. Typically, POST bodies should be JSON encoded and responses will be JSON encoded.

# Authentication
Currently based on {some authentication method}. Visit the [admin panel](https://login.tailscale.com/admin) and navigate to the `Settings` page. Generate an API Key and keep it safe. Provide the key as the user key in basic auth when making calls to Tailscale API endpoints (leave the password blank).

# APIs

* **[Devices](#device)**
  - [GET device](#device-get)
  - [DELETE device](#device-delete)
  - Routes
    - [GET device routes](#device-routes-get)
    - [POST device routes](#device-routes-post)
  - Authorize machine
    - [POST device authorized](#device-authorized-post)
* **[Tailnets](#tailnet)**
  - ACLs
    - [GET tailnet ACL](#tailnet-acl-get)
    - [POST tailnet ACL](#tailnet-acl-post): set ACL for a tailnet
    - [POST tailnet ACL preview](#tailnet-acl-preview-post): preview rule matches on an ACL for a resource
	- [POST tailnet ACL validate](#tailnet-acl-validate-post): run validation tests against the tailnet's existing ACL
  - [Devices](#tailnet-devices)
    - [GET tailnet devices](#tailnet-devices-get)
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

## Tailnet 
A tailnet is the name of your Tailscale network. 
You can find it in the top left corner of the [Admin Panel](https://login.tailscale.com/admin) beside the Tailscale logo.


`alice@example.com` belongs to the `example.com` tailnet and would use the following format for API calls:

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

Tailnets are a top-level resource. ACL is an example of a resource that is tied to a top-level tailnet.

For more information on Tailscale networks/tailnets, click [here](https://tailscale.com/kb/1064/invite-team-members).

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
    "Tests": [],
    // Declare static groups of users beyond those in the identity service.
    "Groups": {
        "group:example": [
            "user1@example.com",
            "user2@example.com"
        ],
    },
    // Declare convenient hostname aliases to use in place of IP addresses.
    "Hosts": {
        "example-host-1": "100.100.100.100",
    },
    // Access control lists.
    "ACLs": [
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

`Accept` - Sets the return type of the updated ACL. Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

###### POST Body

The POST body should be a JSON or [HuJSON](https://github.com/tailscale/hujson#hujson---human-json) formatted JSON object.
An ACL policy may contain the following top-level properties:

* `Groups` - Static groups of users which can be used for ACL rules.
* `Hosts` - Hostname aliases to use in place of IP addresses or subnets.
* `ACLs` - Access control lists.
* `TagOwners` - Defines who is allowed to use which tags.
* `Tests` - Run on ACL updates to check correct functionality of defined ACLs.

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
  "Tests": [
    // {"User": "user1@example.com", "Allow": ["example-host-1:22"], "Deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "Groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "Hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "ACLs": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "Action": "accept", "Users": ["*"], "Ports": ["*:*"] },
  ]
}'
```

Response:
```
// Example/default ACLs for unrestricted connections.
{
  // Declare tests to check functionality of ACL rules. User must be a valid user with registered machines.
  "Tests": [
    // {"User": "user1@example.com", "Allow": ["example-host-1:22"], "Deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "Groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "Hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "ACLs": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "Action": "accept", "Users": ["*"], "Ports": ["*:*"] },
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
  "Tests": [
    // {"User": "user1@example.com", "Allow": ["example-host-1:22"], "Deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "Groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "Hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "ACLs": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "Action": "accept", "Users": ["*"], "Ports": ["*:*"] },
  ]
}'
```

Response:
```
{"matches":[{"users":["*"],"ports":["*:*"],"lineNumber":19}],"user":"user1@example.com"}
```

<a name=tailnet-acl-validate-post></a>

#### `POST /api/v2/tailnet/:tailnet/acl/validate` - run validation tests against the tailnet's active ACL

Runs the provided ACL tests against the tailnet's existing ACL. This endpoint does not modify the ACL in any way.

##### Parameters

###### POST Body

The POST body should be a JSON formatted array of ACL Tests.

See https://tailscale.com/kb/1018/acls for more information on the format of ACL tests.

##### Example
```
POST /api/v2/tailnet/example.com/acl/validate
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate' \
  -u "tskey-yourapikey123:" \
  --data-binary '
{
  [
    {"User": "user1@example.com", "Allow": ["example-host-1:22"], "Deny": ["example-host-2:100"]}
  ]
}'
```

Response:
If all the tests pass, the response will be empty, with an http status code of 200.

Failed test error response:
A 400 http status code and the errors in the response body.  
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
  "searchPaths: ["user1.example.com", "user2.example.com"]
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
