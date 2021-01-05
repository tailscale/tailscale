# Tailscale API

The Tailscale API is a (mostly) RESTful API. Typically, POST bodies should be JSON encoded and responses will be JSON encoded.

# Authentication
Currently based on {some authentication method}. Visit the [admin panel](https://api.tailscale.com/admin) and navigate to the `Keys` page. Generate an API Key and keep it safe. Provide the key as the user key in basic auth when making calls to Tailscale API endpoints.

# APIS

## Device
<!-- TODO: description about what devices are -->

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
curl https://api.tailscale.com/api/v2/device/12345?fields=all \
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

#### `GET /api/v2/device/:deviceID/routes` - fetch subnet routes that are advertised and enabled for a device

Retrieves the list of subnet routes that a device is advertising, as well as those that are enabled for it. Enabled routes are not necessarily advertised (e.g. for pre-enabling), and likewise, advertised routes are not necessarily enabled.

##### Parameters

No parameters.

##### Example

```
curl https://api.tailscale.com/api/v2/device/11055/routes \
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
curl https://api.tailscale.com/api/v2/device/11055/routes \
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

## Domain
<!---
TODO: ctrl+f domain, replace with {workgroup/tailnet/other}
Domain is a top level resource. ACL is an example of a resource that is tied to a top level domain.
--->

### ACL

#### `GET /api/v2/domain/:domain/acl` - fetch ACL for a domain

Retrieves the ACL that is currently set for the given domain. Supply the domain of interest in the path. This endpoint can send back either the HuJSON of the ACL or a parsed JSON, depending on the `Accept` header.

##### Parameters

###### Headers
`Accept` - Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

##### Returns
Returns the ACL HuJSON by default. Returns a parsed JSON of the ACL (sans comments) if the `Accept` type is explicitly set to `application/json`. An `ETag` header is also sent in the response, which can be optionally used in POST requests to avoid missed updates.
<!-- TODO (chungdaniel): define error types and a set of docs for them -->

##### Example

###### Requesting a HuJSON response:
```
GET /api/v2/domain/example.com/acl
curl https://api.tailscale.com/api/v2/domain/example.com/acl \
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
GET /api/v2/domain/example.com/acl
curl https://api.tailscale.com/api/v2/domain/example.com/acl \
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

#### `POST /api/v2/domain/:domain/acl` - set ACL for a domain

Sets the ACL for the given domain. HuJSON and JSON are both accepted inputs. An `If-Match` header can be set to avoid missed updates.

Returns error for invalid ACLs.
Returns error if using an `If-Match` header and the ETag does not match.

##### Parameters

###### Headers
`If-Match` - A request header. Set this value to the ETag header provided in an `ACL GET` request to avoid missed updates.

`Accept` - Sets the return type of the updated ACL. Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

###### POST Body
ACL JSON or HuJSON (see https://tailscale.com/kb/1018/acls)

##### Example
```
POST /api/v2/domain/example.com/acl
curl https://api.tailscale.com/api/v2/domain/example.com/acl \
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

Response
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

#### `POST /api/v2/domain/:domain/acl/preview` - preview rule matches on an ACL for a resource
Determines what rules match for a user on an ACL without saving the ACL to the server.

##### Parameters

###### Query Parameters
`user` - A user's email. The provided ACL is queried with this user to determine which rules match.

###### POST Body
ACL JSON or HuJSON (see https://tailscale.com/kb/1018/acls)

##### Example
```
POST /api/v2/domain/example.com/acl/preiew
curl https://api.tailscale.com/api/v2/domain/example.com/acl?user=user1@example.com \
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

Response
```
{"matches":[{"users":["*"],"ports":["*:*"],"lineNumber":19}],"user":"user1@example.com"}
```

### Devices
#### `GET /api/v2/domain/:domain/devices` - list the devices for a domain
Lists the devices for a domain. 
Supply the domain of interest in the path.
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
GET /api/v2/domain/example.com/devices
curl https://api.tailscale.com/api/v2/domain/example.com/devices \
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


### DNS

#### `GET /api/v2/domain/:domain/dns/nameservers` - list the DNS nameservers for a domain
Lists the DNS nameservers for a domain. 
Supply the domain of interest in the path.

##### Parameters
No parameters.

##### Example 

```
GET /api/v2/domain/example.com/dns/nameservers
curl https://api.tailscale.com/api/v2/domain/example.com/dns/nameservers \
  -u "tskey-yourapikey123:"
```

Response 
```
{
  "dns": ["8.8.8.8"],
}
```

#### `POST /api/v2/domain/:domain/dns/nameservers` - replaces the list of DNS nameservers for a domain
Replaces the list of DNS nameservers for the given domain with the list supplied by the user. 
Supply the domain of interest in the path.
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
POST /api/v2/domain/example.com/dns/nameservers
curl -X POST 'https://api.tailscale.com/api/v2/domain/example.com/dns/nameservers' \
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
POST /api/v2/domain/example.com/dns/nameservers
curl -X POST 'https://api.tailscale.com/api/v2/domain/example.com/dns/nameservers' \
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

#### `GET /api/v2/domain/:domain/dns/preferences` - retrieves the DNS preferences for a domain
Retrieves the DNS preferences that are currently set for the given domain.
Supply the domain of interest in the path.

##### Parameters
No parameters. 

##### Example
```
GET /api/v2/domain/example.com/dns/preferences
curl 'https://api.tailscale.com/api/v2/domain/example.com/dns/preferences' \
  -u "tskey-yourapikey123:" 
```

Response:
```
{
  "magicDNS":false, 
}
```

#### `POST /api/v2/domain/:domain/dns/preferences` - replaces the DNS preferences for a domain 
Replaces the DNS preferences for a domain, specifically, the MagicDNS setting.
Note that MagicDNS is dependent on DNS servers. 

If there is at least one DNS server, then MagicDNS can be enabled. 
Otherwise, it returns an error.
Note that removing all nameservers will turn off MagicDNS. 
To reenable it, nameservers must be added back, and MagicDNS must be explicity turned on.

##### Parameters
###### POST Body
The DNS preferences in JSON. Currently, MagicDNS is the only setting available.
`magicDNS` -  Automatically registers DNS names for devices in your network.
```
{
  "magicDNS": true
}
```

##### Example
```
POST /api/v2/domain/example.com/dns/preferences
curl -X POST 'https://api.tailscale.com/api/v2/domain/example.com/dns/preferences' \
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

#### `GET /api/v2/domain/:domain/dns/searchpaths` - retrieves the search paths for a domain 
Retrieves the list of search paths that is currently set for the given domain. 
Supply the domain of interest in the path.


##### Parameters
No parameters.

##### Example
```
GET /api/v2/domain/example.com/dns/searchpaths
curl 'https://api.tailscale.com/api/v2/domain/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:" 
```

Response:
```
{
  "searchPaths": ["user1.example.com"],
}
```

#### `POST /api/v2/domain/:domain/dns/searchpaths` - replaces the search paths for a domain 
Replaces the list of search paths with the list supplied by the user and returns an error otherwise.

##### Parameters

###### POST Body
`searchPaths` - A list of searchpaths in JSON format.
```
{
  "searchPaths: ["user1.example.com", "user2.example.com"]
}
```

##### Example
```
POST /api/v2/domain/example.com/dns/searchpaths
curl -X POST 'https://api.tailscale.com/api/v2/domain/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"searchPaths": ["user1.example.com", "user2.example.com"]}'
```

Response:
```
{
  "searchPaths": ["user1.example.com", "user2.example.com"],
}
```
