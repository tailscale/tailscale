# Tailscale API

# Introduction

The Tailscale API is a (mostly) RESTful API. Typically, both `POST` bodies and responses are JSON-encoded.

## Endpoint URL
The Tailscale API URL path begins with `https://api.tailscale.com/api/v2/`. 

Examples in this document begin with `api/v2/...`.

## Authentication
TailScale uses several types of keys. The type of key is identified in the key prefix. All keys are structured as follows: `tskey-{key type}-{unique key value}`. The `key type` indicates the type of Tailscale key.
Only two types of keys are relevant for authenticating to the API; these are the **API key**, which functions as an access token when authenticating to the Tailscale API, and the **auth key**, which is used to register devices to a tailnet and discussed later in this document.

### API key 
Provide the API key as the user key in basic authentication when making calls to Tailscale API endpoints (leave the password blank).
<!-- WILL: IS IT THE USER KEY OR BEARER KEY?-->

- **Prefix:** `tskey-api...`

- **Obtain or revoke an API key:** Generate an API key in the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. You can also revoke an API key before its expiry. Recently expired and revoked keys are shown on the **Keys** page.

- **Key expiry:** When generating the key, you can choose the number of days (1 - 90 inclusive) for the automatic key expiry. To continue using an API key after this key expires, you must generate a new key.

- **Provide the API key:** Authenticate to the Tailscale API by passing the API key in the HTTP header of your request.

<!-- JULIA TO MOVE THIS SOMEWHERE BELOW AFTER UNDERSTANDING WHERE

### **Auth key**

Pre-authentication keys ("auth keys” for short) let you register new nodes without needing to sign in via a web browser. Use them to add devices to your tailnet. Auth keys are used for _initial registration_ of a new device to your tailnet (after a device has joined the tailnet, there are additional keys used for subsequent authentication; these include the node key and the machine key). When you generate a new auth key, you can specify that the key should automatically authorize devices for which the auth key is used. Auth keys expire after 90 days max. Recently expired and revoked keys are shown on the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. Learn more [here](https://tailscale.com/kb/1085/auth-keys/).

- **Prefix:** `tskey-auth...`

- **Obtain or revoke an auth key:** Generate an auth key in the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. You can also revoke a key before its expiry.
  
- **Key expiry:** When generating the key, you can choose the number of days (1 - 90 inclusive) for the automatic key expiry. To continue using an auth key after this key expires, you must generate a new key.
-->  

<!--
### **OAuth client**
-->

<!--WILL, ARE THESE GOING TO REPLACE API KEYS? OR WILL BOTH PERSIST? ALSO IN THIS DOC: https://tailscale.com/kb/1215/oauth-clients/, DO THE LISTS MEAN ONE OR ALL ARE REQUIRED FOR EACH ACTION? (I'LL EXPLAIN BETTER IN PERSON) -->
<!--
Use the OAuth client to provide ongoing access to the API with tokens defining scope of permissions. Unlike [API keys](#api-key), which expire and must be regenerated, OAuth clients have no expiry. And unlike API keys, OAuth clients specify permissions.

- **Prefix:** `tskey-client-...`

- **Obtain or revoke an OAuth client:** Generate an OAuth client in the [**OAuth clients**](https://login.tailscale.com/admin/settings/oauth) page of the admin console. You can also revoke an OAuth client in this page. 
-->

## Terminology

In the context of Tailscale, the terms _device_, _machine_, and _node_ are effectively synonymous. They all refer to a specific physical device (computer, mobile phone, virtual machine in the cloud, etc.) in a tailnet. To specify operations on an individual device, the `nodeId` is preferred wherever `:deviceId` appears in an endpoint (a `nodeId` can be retrieved by [fetching a list of tailnet devices](#fetch-a-list-of-tailnet-devices).

<!--WILL, THIS LAST PART IS REPETITIVE, I KNOW. I CAN KEEP IT EITHER IN THE BULLETS ABOVE OR AS THIS PARAGRAPH BELOW, CAN'T DECIDE.-->

## Passing parameters
Required query parameters can be passed in four places within the request:
- URL path
- query string
- HTTP headers
- request body

## Partial matches

<!-- STILL TO DISCUSS JULIA/WILL -->

## Control the fields in a response

For some methods, Tailscale provides the `fields` query parameter to explicitly indicate whether **all** object fields are returned, or only a predefined subset of fields. Details are provided in the description of each method that accepts `fields` parameter.

## Select JSON format for response

Some API calls let you select the format of the JSON returned in the response. Provide your preference as a parameter in the **Accept** header of the request. Two options are supported in these scenarios:

- **JSON:** Standard parsed JSON format.
- **HuJSON:** Human-readable JSON (this is the default if no format is specified). Learn more about HuJSON [here](https://github.com/tailscale/hujson#hujson---human-json).

## Errors
The Tailscale API sends status codes consistent with [standard HTTP conventions](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status). 

Common client error messages (in the 400 range) include:
<!-- WILL, DO WE WANT TO HAVE SOME COMMON ONES AND RECOMMENDED ACTIONS OR NAH-->

For server error messages (in the 500 range), contact [Tailscale support](https://tailscale.com/contact/support/).

## Pagination
The Tailscale API v2 does not currently support pagination. All results are returned at once.

## Versioning
The Tailscale API generally follows [semantic versioning conventions](https://semver.org/), where version numbers are structured as follows: `MAJOR.MINOR.PATCH`. When the API is updated with backwards-incompatible changes, Tailscale releases a new version, incrementing the `MAJOR` numeral in the version number. The `MAJOR` version number is passed in the URL path: `https://api.tailscale.com/api/v2/`.

<!-- WILL, DO WE WANT TO SAY WHAT THE CURRENT VERSION NUMBER IS IN HERE (ALSO, WHAT IS THE CURRENT VERSION NUMBER, 2.X.X?) AND DO WE WANT TO SAY HOW THEY CAN FIND OUT THE CURRENT VERSION NUMBER-->

# APIs

**[Devices](#device)**
- [GET device](#fetch-the-details-for-a-device)
- [DELETE device](#delete-a-device)
- Routes
  - [GET device routes](#fetch-device-routes)
  - [POST device routes](#set-enabled-subnet-routes-for-a-device)
- Authorize machine
  - [POST device authorized](#authorize-a-device)
- Tags
  - [POST device tags](#update-device-tags)
- Key
  - [POST device key](#update-device-key-expiry)

**[Tailnets](#tailnet)**
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

# Device

<!-- WILL WHERE SHOULD I TALK ABOUT WHICH SCOPES ARE REQUIRED FOR WHICH ENDPOINTS ONCE WE INCLUDE OAUTH CONTENT... NEXT TO EACH METHOD, I WOULD THNK? OR HIGHER UP, AT THE ENDPOINT LEVEL?-->

A Tailscale device (synonymous with _machine_ and _node_), is any computer or mobile device that joins a tailnet. <!--WILL, What to add to this desc? -->

Endpoints: 
<!-- 
WILL, 
1. REMINDER THAT YOU WERE PLANNING TO ADD NODE ID TO THE MACHINES PAGE OF THE ADMIN CONSOLE. 
2. CAN I WRITE `:nodeID` INSTEAD OF `:deviceID` FOR THE ENDPOINTS?
-->
- [`GET /api/v2/device/:deviceID`](#fetch-the-details-for-a-device)
- [`DELETE /api/v2/device/:deviceID`](#delete-a-device)
- [`GET /api/v2/device/:deviceID/routes`](#fetch-device-routes)
- [`POST /api/v2/device/:deviceID/routes`](#set-enabled-subnet-routes-for-a-device)
- [`POST /api/v2/device/:deviceID/authorized`](#authorize-a-device)
- [`POST /api/v2/device/:deviceID/tags`](#update-device-tags)
- [`POST /api/v2/device/:deviceID/key`](#update-device-key-expiry)

## Device object

Each Tailscale-connected device has a globally-unique identifier number to which we refer as the `nodeId`. Use the `nodeId` to specify operations on a specific device, such as retrieving its subnet routes. 

To find the `nodeId` for a particular device, you can use the [`GET /api/v2/tailnet/:tailnet/devices`](#fetch-a-list-of-tailnet-devices) API call to generate a list of devices on your network, then find the device you're looking for and get its `"nodeId"` field. This is what you provide in the URL whenever `:deviceID` is included in an endpoint.

(While `nodeId` is the preferred way to identify a unique device, `id` is also still accepted when specifying operations on a particular device. Note that this will be deprecated in the future. Find the `id` of a particular device by [fetching device details](#fetch-the-details-for-a-device).)

### Attributes

``` jsonc
    {
      // "addresses" (array of strings) is a list of Tailscale IP 
      // addresses for the device, formatted as 100.x.y.z ???

      "addresses": [
        "100.96.222.106",
        "fd7a:115c:a1e0:ab12:4843:cd96:6260:d26a"
      ],
      
      // "authorized" (boolean) is 'true' if the device had been 
      // authorized to join the tailnet; otherwise, 'false' 

      "authorized": true,
      
      // "blocksIncomingConnections" (boolean) is 'true' if ???. 
      // Reported starting with Tailscale v1.3.x. This setting is 
      // configured via the device's Tailscale client preferences ??? WHERE??
      
      "blocksIncomingConnections": false,

      // "clientVersion" (string) is the version of ???; 
      // this is empty for external devices 

      "clientVersion": "",

      // "created" (string) is the date on which the device was added 
      // (first added? last added???) to the tailnet; this is empty for external devices. 

      "created": "",

      // "expires" (string) is ???

      "expires": "2023-05-30T04:44:05Z",

      // "hostname" (string) is ??? 

      "hostname": "go",

      // "id" (string) is the legacy identifier for a node (AKA device); you 
      // can provide this value wherever :deviceId is indicated in the endpoint
      // Use it to specify operations on a specific device, such as authorizing
      // it, deleting it from a tailnet, or retrieving its subnet routes.
      // Note that although "id" is still accpeted, "nodeId" is preferred.

      "id": "39381946735751060",

      // "isExternal" (boolean) if 'true', indicates that a device is not 
      // a member of the tailnet, but is shared in; if 'false', the device 
      // is a member of the tailnet

      "isExternal": true,

      // "keyExpieryDisabled" (boolean) is ??? WILL IS THIS A TYPO???
      //

      "keyExpiryDisabled": true,

      // "lastSeen" (string) is ??? 
      // 

      "lastSeen": "2022-12-01T05:23:30Z",

      // "machineKey" (string) is for internal use and is not required for
      // any API operations. Learn about machine keys at: 
      // https://tailscale.com/blog/tailscale-key-management/#machine-keys.
      // This value is empty for external devices.

      "machineKey": "",

      // "name" (string) is ??? 

      "name": "go-test.namename.ts.net",

      // "nodeID" (string) is the preferred identifier for a node (AKA device);  
      // provide this value wherever :deviceId is indicated in the endpoint.
      // Use it to specify operations on a specific device, such as authorizing
      // it, deleting it from a tailnet, or retrieving its subnet routes.
      // Note that although "nodeId" is preferred, "id" is still accpeted. 

      "nodeId": "nWqeZf5CNTRL",

      // "nodeKey" (string) is rarely used; it is required for a few select 
      // operations, such as adding a node to a locked tailnet; 
      // most operations require "nodeId" or "id" rather than "nodeKey".
      // Learn about node keys at: 
      // https://tailscale.com/blog/tailscale-key-management/#node-keys 

      "nodeKey": 
      "nodekey:c123959c82afcbeb716bc9fd72cf46a5d46844fd3e97590b90b021469860d266",

      // "os" (string) is ???

      "os": "linux",

      // "tags" (array of strings) let you assign an identity to a device that
      // is separate from human users, and use it as part of an ACL to restrict 
      // access. Tags are created in the tailnet policy file; a tag is created 
      // by defining an owner. Once a device is tagged, the tag is the owner 
      // of that device. A single node can have multiple tags assigned. 
      // Learn more about tags at https://tailscale.com/kb/1068/acl-tags/. 
      // This value is empty for external devices.

      "tags": [
        "tag:golink"
      ],
      // "tailnetLockError" (string) indicates an issue with the tailnet lock 
      // node-key signature on this device. 
      // This field is only populated when tailnet lock is enabled.

      "tailnetLockError": "",

      // "tailnetLockKey" (string) is the node's tailnet lock key. 
      // A tailnet lock can be enabled at the command line and lets you 
      // control which nodes are signed and verified by trusted nodes in 
      // your tailnet. Learn more at: https://tailscale.com/kb/1226/

      "tailnetLockKey": "",

      // "updateAvailable" (boolean) is ??? 
      // This value is empty for external devices.

      "updateAvailable": false,

      // "user" (string) is the user who originally created the node, 
      // or whose auth key was used to create the node.?? WILL, I GOT THIS FROM THE CODE, BUT DO THEY ACTUALLY MEAN AUTH KEY HERE OR??

      "user": "username@github"
    },

```

### Subnet Routes

Nodes (or devices) within a tailnet can be set up as subnet routers.  A subnet router acts as a gateway, relaying traffic from your Tailscale network onto your physical subnet. Setting up subnet routers exposes routes to other nodes in the tailnet. Learn more about subnet routers [here](https://tailscale.com/kb/1019/).

A device can act as a subnet router if its subnet routes are both advertised and enabled. This is a two-step process, but the steps can occur in any order: 
- The device that intends to act as a subnet router exposes its routes by **advertising** them. This is done in the Tailscale command-line interface.
- The tailnet admin must approve the routes by **enabling** them. This is done in the [**Machines**](https://login.tailscale.com/admin/machines) page of the Tailscale admin console or in this API via the [`POST /api/v2/device/:deviceID/routes`](#set-enabled-subnet-routes-for-a-device) endpoint. 

If a device has advertised routes, they are not exposed to traffic until they are enabled by the tailnet admin. Conversely, if a tailnet admin pre-approves certain routes by enabling them, they are not available for routing until the device in question has advertised them.

The Devices endpoint exposes two methods for dealing with subnet routes:
- [`GET /api/v2/device/:deviceID/routes`](#fetch-device-routes) to fetch lists of advertised and enabled routes for a device
- [`POST /api/v2/device/:deviceID/routes`](#set-enabled-subnet-routes-for-a-device) to set enabled routes for a device

## Fetch the details for a device

``` http
GET /api/v2/device/:deviceid
```

Retrieve the details for the specified device. 

- Supply the device of interest in the path using its ID.
- Use the `fields` query parameter to explicitly indicate whether all fields are returned, or only a predefined subset of fields.

Returns a JSON `device` object listing either all device attributes, or a predefined subset of the attributes.

### Query parameters

#### `fields` (optional)

Controls whether the response returns **all** object fields or only a predefined subset of fields. Currently, there are two supported options:
- **`all`:** return all object fields in the response
- **`default`:** return all object fields **except**:
  - `enabledRoutes`
  - `advertisedRoutes`
  - `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

Use commas to separate multiple options. If more than one option is indicated, then `all` is used. For example, for `fields=default,all`, all fields are returned. If the `fields` parameter is not provided, then the default (limited fields) option is used. 

In the future, we plan to support querying specific fields by name.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/12345?fields=all' \
  -u "tskey-yourapikey123:"
```

### Response
``` jsonc
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

## Delete a device

``` http
DELETE /api/v2/device/:deviceID
``` 

Deletes the provided device from its tailnet. The device must belong to the user's tailnet. Deleting shared/external devices is not supported. Supply the device to delete in the URL path using its ID.

Returns an empty response if successful; otherwise, a '501' response if the device is not owned by the tailnet.

### Query parameters
No parameters.

### Request example
``` sh
curl -X DELETE 'https://api.tailscale.com/api/v2/device/12345' \
  -u "tskey-yourapikey123:" -v
```

### Response

If successful, the response should be empty:

``` http
< HTTP/1.1 200 OK
...
* Connection #0 to host left intact
* Closing connection 0
```

If the device is not owned by your tailnet:

``` http
< HTTP/1.1 501 Not Implemented
...
{"message":"cannot delete devices outside of your tailnet"}
```

## Fetch Device Routes
``` http
GET /api/v2/device/:deviceID/routes
``` 

Fetch a list of subnet routes that are advertised, and a list of subnet routes that are enabled for a device. Subnet routes are introduced [above](#subnet-routes) and discussed further in our [Knowledge Base](https://tailscale.com/kb/1019/subnets/). 

This API call retrieves the list of subnet routes that a device is advertising, as well as those that are enabled for it:
- **Enabled routes:** The subnet routes for this device that have been approved by the tailnet admin. 
- **Advertised routes:** The subnets this device intends to expose.

### Query parameters

No parameters.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/11055/routes' \
-u "tskey-yourapikey123:"
```

### Response
``` jsonc
{
   "advertisedRoutes" : [
      "10.0.1.0/24",
      "1.2.0.0/16",
      "2.0.0.0/24"
   ],
   "enabledRoutes" : []
}
```

## Set enabled subnet routes for a device

``` http
POST /api/v2/device/:deviceID/routes
```

Set the subnet routes that are enabled for a device. Subnet routes are introduced [above](#subnet-routes) and discussed further in our [Knowledge Base](https://tailscale.com/kb/1019/subnets/).

This call sets a device's enabled subnet routes by replacing the existing list of subnet routes with the supplied parameters. Tailscale returns a JSON list with enabled subnet routes and a list of advertised subnet routes for a device.

### Query parameters

#### `routes` (optional)

The new list of enabled subnet routes in JSON. Provide this parameter in the `POST` body, as shown:

``` jsonc
{
  "routes": ["10.0.1.0/24", "1.2.0.0/16", "2.0.0.0/24"]
}
```

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/11055/routes' \
-u "tskey-yourapikey123:" \
--data-binary '{"routes": ["10.0.1.0/24", "1.2.0.0/16", "2.0.0.0/24"]}'
```

### Response

``` jsonc
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

## Authorize a device
``` http
POST /api/v2/device/:deviceID/authorized
```

Authorize a device. This call marks a device as authorized for Tailnets where device authorization is required.

Tailscale returns a successful 2xx response with an empty JSON object in the response body.

### Query parameters

#### `authorized` (optional)
Specify whether the device is authorized. Only `true` is currently supported. Provide this parameter in the `POST` body, as shown:

``` jsonc
{
  "authorized": true
}
```

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/11055/authorized' \
-u "tskey-yourapikey123:" \
--data-binary '{"authorized": true}'
```

### Response
The response is 2xx on success. The response body is currently an empty JSON object.

## Update device tags
``` http
POST /api/v2/device/:deviceID/tags
```
<!-- WILL should this next sentence say that you're updating tags on a node rather than on a device?-->

Update the tags set on a device. Tags let you assign an identity to a device that is separate from human users, and use that identity as part of an ACL to restrict access. Tags are similar to role accounts, but more flexible.
 
Tags are created in the tailnet policy file (also known as the ACL file); a tag is created by defining an owner. Once a device is tagged, the tag is the owner of that device. A single node can have multiple tags assigned.

Consult the policy file for your tailnet in the [admin console](https://login.tailscale.com/admin/acls) for the list of tags that have been created for your tailnet. Learn more about tags [here](https://tailscale.com/kb/1068/acl-tags/).

Tailscale returns a 2xx code if successful, with an empty JSON object in the response body.

### Query parameters

#### `tags` (optional)
The new list of tags for the device. Provide this parameter in the `POST` body as shown:

``` jsonc
{
  "tags": ["tag:foo", "tag:bar"]
}
```

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/11055/tags' \
-u "tskey-yourapikey123:" \
--data-binary '{"tags": ["tag:foo", "tag:bar"]}'
```

### Response
The response is 2xx on success. The response body is currently an empty JSON object.

If the tags provided in the `POST` call do not exist in the tailnet policy file, the response is '400 Bad Request':

``` jsonc
{
  "message": "requested tags [tag:madeup tag:wrongexample] are invalid or not permitted"
}
```

## Update device key expiry
``` http
POST /api/v2/device/:deviceID/key
```

Disable or enable the expiry of the device's key. When a device is added to a tailnet, its key expiry is set in the [General settings](https://login.tailscale.com/admin/settings/general) page of the admin console, with a duration between 1-180 days. If the key is not refreshed and expires, the device can no longer communicate with other devices in the tailnet. 

Use this API call setting `"keyExpiryDisabled": true` to disable key expiry for the device, so that the device can rejoin the tailnet. You then have the option to update the key and call this endpoint again, this time with `"keyExpiryDisabled": false` to re-enable expiry. 
<!-- WILL: BUT STILL, WHICH KEY?? CAN I SAY NODE KEY?-->

### Query parameters

`keyExpiryDisabled` (optional)

Provide this parameter in the `POST` body as shown:

``` jsonc
{
  "keyExpiryDisabled": true
}
```

- Provide `true` to disable the device's key expiry. The original key expiry time is still maintained. Upon re-enabling, the key will expire at that original time.
- Provide `false` to enable the device's key expiry. Sets the key to expire at the original expiry time prior to disabling. The key may already have expired. In that case, the device must be re-authenticated.
- Empty value will not change the key expiry.

Tailscale returns a 2xx code on success, with an empty JSON object in the response body.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/11055/key' \
-u "tskey-yourapikey123:" \
--data-binary '{"keyExpiryDisabled": true}'
```
### Response
The response is 2xx on success. The response body is currently an empty JSON
object.

# Tailnet

A tailnet, previously called a _domain_, is your private network, composed of all the devices on it and their configuration. Learn more about tailnets [here](https://tailscale.com/kb/1136/tailnet/).

<!-- JULIA AND WILL TO FIGURE OUT WHAT HAPPENS IF THE "WRONG" TAILNET NAME IS PROVIDED AND TO SPECIFY EXACTLY WHICH IS THE RIGHT TAILNET NAME-->

<!--JULIA TO ASK WILL ABOUT ORGANIZING THIS ENDPOINT-->

When making API requests, your tailnet is identified by the **organization** name (not to be confused with the **tailnet name**). You can find your **organization name** on the [General](https://login.tailscale.com/admin/settings/general) settings page of the admin console.

For example, if `alice@example.com` belongs to the `example.com` tailnet, they would use the following format for API calls:

``` http
GET /api/v2/tailnet/example.com/...
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/...'
```

For solo plans, the tailnet is the email you signed up with.
So `alice@gmail.com` has the tailnet `alice@gmail.com` because `@gmail.com` is a shared email host.
Their API calls would have the following format:

```
GET /api/v2/tailnet/alice@gmail.com/...
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/alice@gmail.com/...'
```

Alternatively, you can specify the value "`-`" to refer to the default tailnet of the authenticated user making the API call. For example:

``` http
GET /api/v2/tailnet/-/...
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/-/...'
```

Tailnets are a top-level resource. ACL is an example of a resource that is tied to a top-level tailnet. <!--Huh?-->

Endpoints:

- [`GET /api/v2/tailnet/:tailnet/acl`]()
- [`POST /api/v2/tailnet/:tailnet/acl`]()
- [`POST /api/v2/tailnet/:tailnet/acl/preview`]()
- [`POST /api/v2/tailnet/:tailnet/acl/validate`]()
- [`GET /api/v2/tailnet/:tailnet/devices`](#fetch-a-list-of-tailnet-devices)
- [`GET /api/v2/tailnet/:tailnet/keys`]()
- [`POST /api/v2/tailnet/:tailnet/keys`]()
- [`GET /api/v2/tailnet/:tailnet/keys/:keyid`]()
- [`DELETE /api/v2/tailnet/:tailnet/keys/:keyid`]()
- [`GET /api/v2/tailnet/:tailnet/dns/nameservers`]()
- [`POST /api/v2/tailnet/:tailnet/dns/nameservers`]()
- [`GET /api/v2/tailnet/:tailnet/dns/preferences`]()
- [`POST /api/v2/tailnet/:tailnet/dns/preferences`]()
- [`GET /api/v2/tailnet/:tailnet/dns/searchpaths`]()
- [`POST /api/v2/tailnet/:tailnet/dns/searchpaths`]()

## Tailnet object

Desc

### Attributes

## ACL object

<a name=tailnet-acl-get></a>

#### `GET /api/v2/tailnet/:tailnet/acl` - fetch ACL for a tailnet

Retrieves the ACL that is currently set for the given tailnet. Supply the tailnet of interest in the path. This endpoint can send back either the HuJSON of the ACL or a parsed JSON, depending on the `Accept` header.

##### Query parameters

###### Headers
`Accept` - Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

##### Returns
Returns the ACL HuJSON by default. Returns a parsed JSON of the ACL (sans comments) if the `Accept` type is explicitly set to `application/json`. An `ETag` header is also sent in the response, which can be optionally used in POST requests to avoid missed updates.
<!-- TODO (chungdaniel): define error types and a set of docs for them -->

##### Example

###### Requesting a HuJSON response:
``` http
GET /api/v2/tailnet/example.com/acl
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl' \
  -u "tskey-yourapikey123:" \
  -H "Accept: application/hujson" \
  -v
```

Response
``` jsonc
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
``` http
GET /api/v2/tailnet/example.com/acl
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl' \
  -u "tskey-yourapikey123:" \
  -H "Accept: application/json" \
  -v
```

Response
``` jsonc
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

Sets the ACL for the given tailnet. HuJSON and JSON are both accepted inputs. An `If-Match` header can be set to avoid missed updates.

Returns the updated ACL in JSON or HuJSON according to the `Accept` header on success. Otherwise, errors are returned for incorrectly defined ACLs, ACLs with failing tests on attempted updates, and mismatched `If-Match` header and ETag.

### Query parameters in request headers

`If-Match` - A request header. Set this value to the ETag header provided in an `ACL GET` request to avoid missed updates.

A special value `ts-default` will ensure that ACL will be set only if current ACL is the default one (created automatically for each tailnet).

`Accept` - Sets the return type of the updated ACL. Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

### Query parameters in the `POST` body

The POST body should be a JSON or [HuJSON](https://github.com/tailscale/hujson#hujson---human-json) formatted JSON object.
An ACL policy may contain the following top-level properties:

- `groups` - Static groups of users which can be used for ACL rules.
- `hosts` - Hostname aliases to use in place of IP addresses or subnets.
- `acls` - Access control lists.
- `tagOwners` - Defines who is allowed to use which tags.
- `tests` - Run on ACL updates to check correct functionality of defined ACLs.
- `autoApprovers` - Defines which users can advertise routes or exit nodes without further approval.
- `ssh` - Configures access policy for Tailscale SSH.
- `nodeAttrs` - Defines which devices can use certain features.

See https://tailscale.com/kb/1018/acls for more information on those properties.

### Request example

``` sh
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

#### Response

``` jsonc
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
<!-- WHAT IS HAPPENING IN THIS CALL?-->
Determines what rules match for a user on an ACL without saving the ACL to the server.

### Query parameters

#### `type` (optional)
Can be 'user' or 'ipport'. Provide this parameter in the URL path as shown in the request example below.

#### `previewFor` (optional)
- If `type`='user', a user's email. 
- If `type`='ipport', an IP address + port like "10.0.0.1:80".

Provide this parameter in the URL path as shown in the request example below.

The provided ACL is queried with this parameter to determine which rules match. <!-- ??? -->

#### POST body
ACL JSON or HuJSON (see https://tailscale.com/kb/1018/acls)
<!-- REQUEST EXAMPLE DOESN'T SEEM TO INCLUDE THIS?-->

### Request example

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

### Response

``` jsonc
{"matches":[{"users":["*"],"ports":["*:*"],"lineNumber":19}],"user":"user1@example.com"}
```

<a name=tailnet-acl-validate-post></a>

#### `POST /api/v2/tailnet/:tailnet/acl/validate` - run validation tests against the tailnet's active ACL

This endpoint works in one of two modes:

1. with a request body that's a JSON array, the body is interpreted as ACL tests to run against the tailnet's current ACLs.
2. with a request body that's a JSON object, the body is interpreted as a hypothetical new JSON (HuJSON) body with new ACLs, including any tests.

In either case, this endpoint does not modify the ACL in any way.

##### Parameters

###### POST Body

The POST body should be a JSON formatted array of ACL Tests.

See https://tailscale.com/kb/1018/acls for more information on the format of ACL tests.

##### Example with tests

``` http
POST /api/v2/tailnet/example.com/acl/validate
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate' \
  -u "tskey-yourapikey123:" \
  --data-binary '
  [
    {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]}
  ]'
```

##### Example with an ACL body
``` http
POST /api/v2/tailnet/example.com/acl/validate
```

``` sh
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

``` jsonc
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

## Fetch a list of tailnet devices

``` http
GET /api/v2/tailnet/:tailnet/devices
```

Lists the devices in a tailnet. Supply the tailnet of interest in the path. Optionally use the `fields` query parameter to explicitly indicate which fields are returned.

This call is also useful for retrieving a device's `deviceID` (returned as `"id"`). A device ID is used in API requests where you must provide an ID in order to, for example, [fetch device details](#fetch-the-details-for-a-device) or [authorize a device](#authorize-a-device).

### Query parameters

#### `fields` (optional)

Controls whether the response returns **all** fields or only a predefined subset of fields. Currently, there are two supported options:
- **`all`:** return all fields in the response
- **`default`:** return all fields **except**:
  * `enabledRoutes`
  * `advertisedRoutes`
  * `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

Use commas to separate multiple options. If more than one option is indicated, then `all` is used. For example, for `fields=default,all`, all fields are returned. 

If the `fields` parameter is not provided, then the default (limited fields) option is used.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/devices' \
  -u "tskey-yourapikey123:"
```

### Response

``` jsonc
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

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys' \
  -u "tskey-yourapikey123:"
```

Response:

``` jsonc
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

``` jsonc
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

``` jsonc
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

``` jsonc
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

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-yourapikey123:"
```

Response:

``` jsonc
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

``` sh
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

``` http
GET /api/v2/tailnet/example.com/dns/nameservers
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:"
```

Response

``` jsonc
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

``` jsonc
{
  "dns":["8.8.8.8"]
}
```

##### Returns
Returns the new list of nameservers and the status of MagicDNS.

If all nameservers have been removed, MagicDNS will be automatically disabled (until explicitly turned back on by the user).

##### Example
###### Adding DNS nameservers with the MagicDNS on:
``` http
POST /api/v2/tailnet/example.com/dns/nameservers
```

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"dns": ["8.8.8.8"]}'
```

Response:

``` jsonc
{
  "dns":["8.8.8.8"],
  "magicDNS":true,
}
```

###### Removing all DNS nameservers with the MagicDNS on:
``` http
POST /api/v2/tailnet/example.com/dns/nameservers
```

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"dns": []}'
```

Response:

``` jsonc
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

``` http
GET /api/v2/tailnet/example.com/dns/preferences
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences' \
  -u "tskey-yourapikey123:"
```

Response:

``` jsonc
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

``` jsonc
{
  "magicDNS": true
}
```

##### Example
``` http
POST /api/v2/tailnet/example.com/dns/preferences
```

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"magicDNS": true}'
```


Response:

If there are no DNS servers, it returns an error message:

``` jsonc
{
  "message":"need at least one nameserver to enable MagicDNS"
}
```

If there are DNS servers:
``` jsonc
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
``` http
GET /api/v2/tailnet/example.com/dns/searchpaths
```

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:"
```

Response:
``` jsonc
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
``` jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"]
}
```

##### Example
```
POST /api/v2/tailnet/example.com/dns/searchpaths
```

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"searchPaths": ["user1.example.com", "user2.example.com"]}'
```

### Response:

``` jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"],
}
```
