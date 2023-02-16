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
Supply the API key as the **Username** in **Basic** authentication when making calls to Tailscale API endpoints (leave the password blank).

- **Prefix:** `tskey-api...`

- **Obtain or revoke an API key:** Generate an API key in the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. You can also revoke an API key before its expiry. Recently expired and revoked keys are shown on the **Keys** page.

- **Key expiry:** When generating the key, you can choose the number of days (1 - 90 inclusive) for the automatic key expiry. To continue using an API key after this key expires, you must generate a new key.

- **Supply the API key:** Authenticate to the Tailscale API by passing the API key in the HTTP header of your request.

<!-- JULIA CAN REMOVE THIS NOW

### **Auth key**

Pre-authentication keys ("auth keys” for short) let you register new nodes without needing to sign in via a web browser. Use them to add devices to your tailnet. Auth keys are used for _initial registration_ of a new device to your tailnet (after a device has joined the tailnet, there are additional keys used for subsequent authentication; these include the node key and the machine key). When you generate a new auth key, you can specify that the key should automatically authorize devices for which the auth key is used. Auth keys expire after 90 days max. Recently expired and revoked keys are shown on the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. Learn more about [auth keys](https://tailscale.com/kb/1085/).

- **Prefix:** `tskey-auth...`

- **Obtain or revoke an auth key:** Generate an auth key in the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. You can also revoke a key before its expiry.
  
- **Key expiry:** When generating the key, you can choose the number of days (1 - 90 inclusive) for the automatic key expiry. To continue using an auth key after this key expires, you must generate a new key.
-->  

### **OAuth client**

Use the OAuth client to provide ongoing access to the API with tokens defining scope of permissions. Unlike [API keys](#api-key), which expire and must be regenerated, OAuth clients have no expiry. And unlike API keys, OAuth clients specify permissions. Learn more about [OAuth clients](https://tailscale.com/kb/1215/).

- **Prefix:** `tskey-client-...`

- **Obtain or revoke an OAuth client:** Generate or revoke an OAuth client in the [**OAuth clients**](https://login.tailscale.com/admin/settings/oauth) page of the admin console.

## Terminology

In the context of Tailscale, the terms _device_, _machine_, and _node_ are effectively synonymous. They all refer to a specific physical device (computer, mobile phone, virtual machine in the cloud, etc.) in a tailnet. To specify operations on an individual device, the `nodeId` is preferred wherever `{deviceId}` appears in an endpoint (a `nodeId` can be retrieved by [fetching a list of tailnet devices](#fetch-a-list-of-tailnet-devices).

## Providing input parameters
Required input parameters can be passed in one of four places within the request:
- URL path (e.g., `{deviceId}` in `/api/v2/device/{deviceId}`)
- query string (e.g., `?fields=all` in `https://api.tailscale.com/api/v2/device/12345?fields=all`)
- HTTP headers (e.g., `Accept`)
- request body (e.g., a JSON object in the body of a `POST` request)

## Control the fields in a response

For some methods, Tailscale provides the `fields` query parameter to explicitly indicate whether **all** object fields are returned, or only a predefined subset of fields. Details are provided in the description of each method that accepts `fields` parameter.

## Select JSON format for response

Some API calls let you select the format of the JSON returned in the response. Supply your preference as a parameter in the **Accept** header of the request. Two options are supported in these scenarios:

- **JSON:** Standard parsed JSON format.
- **HuJSON:** Human-readable JSON (this is the default if no format is specified). Learn more about [HuJSON](https://github.com/tailscale/hujson#hujson---human-json).

## Errors
The Tailscale API sends status codes consistent with [standard HTTP conventions](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status). In addition to the status code, client error messages may include additional information in the response body.

## Pagination
The Tailscale API v2 does not currently support pagination. All results are returned at once.

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
  - [GET tailnet ACL](JULIA)
  - [POST tailnet ACL](JULIA)
  - [POST tailnet ACL preview](JULIA)
  - [POST tailnet ACL validate](JULIA)
- [Devices](JULIA)
  - [GET tailnet devices](JULIA)
- [Keys](JULIA)
  - [GET tailnet keys](JULIA)
  - [POST tailnet key](JULIA)
  - [GET tailnet key](JULIA)
  - [DELETE tailnet key](JULIA)
- [DNS](JULIA)
  - [GET tailnet DNS nameservers](JULIA)
  - [POST tailnet DNS nameservers](JULIA)
  - [GET tailnet DNS preferences](JULIA)
  - [POST tailnet DNS preferences](JULIA)
  - [GET tailnet DNS search paths](JULIA)
  - [POST tailnet DNS search paths](JULIA)

# Device

<!-- WILL REMINDER TO ADD WHICH SCOPES ARE REQUIRED FOR EACH ENDPOINT AT THE END OF PROJECT; TO DISCUSS NEXT TO EACH METHOD-->

A Tailscale device (sometimes referred to as _node_ or _machine_), is any computer or mobile device that joins a tailnet.

Endpoints: 
- [`GET /api/v2/device/{deviceId}`](#fetch-the-details-for-a-device)
- [`DELETE /api/v2/device/{deviceID}`](#delete-a-device)
- [`GET /api/v2/device/{deviceID}/routes`](#fetch-device-routes)
- [`POST /api/v2/device/{deviceID}/routes`](#set-enabled-subnet-routes-for-a-device)
- [`POST /api/v2/device/{deviceID}/authorized`](#authorize-a-device)
- [`POST /api/v2/device/{deviceID}/tags`](#update-device-tags)
- [`POST /api/v2/device/{deviceID}/key`](#update-device-key-expiry)

## Device object

Each Tailscale-connected device has a globally-unique identifier number to which we refer as the `nodeId`. Use the `nodeId` to specify operations on a specific device, such as retrieving its subnet routes. 

To find the `nodeId` for a particular device in the admin console, navigate to [**Settings** → **General**]() and copy the **organization** name. To retrieve a `nodeId` using the API, make a [`GET /api/v2/tailnet/{tailnet}/devices`](#fetch-a-list-of-tailnet-devices) call to generate a list of devices on your network, then find the device you're looking for and get its `"nodeId"` value. 

(While `nodeId` is the preferred way to identify a unique device, `id` is also still accepted when specifying operations on a particular device. Find the `id` of a particular device by [fetching device details](#fetch-the-details-for-a-device).)

### Attributes

``` jsonc
    {
      // "addresses" (array of strings) is a list of Tailscale IP 
      // addresses for the device, including both ipv4 (formatted as 100.x.y.z)
      // and ipv6 (formatted as fd7a:115c:a1e0:a:b:c:d:e) addresses.
      "addresses": [
        "100.96.222.106",
        "fd7a:115c:a1e0:ab12:4843:cd96:6260:d26a"
      ],

      // "advertisedRoutes" (array of strings) are the subnets this device 
      // intends to expose. 
      // Learn more about subnet routes at https://tailscale.com/kb/1019/.
      "advertisedRoutes" : [
      "10.0.1.0/24",
      "1.2.0.0/16",
      "2.0.0.0/24"
      ],
   
      // "authorized" (boolean) is 'true' if the device has been 
      // authorized to join the tailnet; otherwise, 'false'. Learn
      // more about device authorization at https://tailscale.com/kb/1099/.
      "authorized": true,
      
      // "blocksIncomingConnections" (boolean) is 'true' if the device is not
      // allowed to accept any connections over Tailscale, including pings. 
      // Reported starting with Tailscale v1.3.x. This setting is 
      // configured via the device's Tailscale client preferences.
      // Learn more in the "Allow incoming connections" 
      // section of https://tailscale.com/kb/1072.      
      "blocksIncomingConnections": false,

      // "clientConnectivity" provides a report on your current physical
      // network conditions
      "clientConnectivity": {

        // "endpoints" (array of strings) Client's magicsock UDP IP:port 
        // endpoints (IPv4 or IPv6) 
        "endpoints":[
          "209.195.87.231:59128",
          "192.168.0.173:59128"
        ],

        // "derp" (string) is the IP:port of the designated encrypted relay
        // for packets (DERP) server currently being used; learn about DERP
        // servers here: https://tailscale.com/kb/1232
        "derp":"",

        // "mappingVariesByDestIP" (boolean) is 'true' if the host's network
        // address translation (NAT-enables multiple machines behind a router
        // to share the same public IP address) mappings vary based on the  
        // destination IP         
        "mappingVariesByDestIP":false,

        // "latency" (map) lists DERP server locations and their current
        // latency; "preferred" is 'true' for the node's preferred DERP 
        // server for incoming traffic
        "latency":{
          "Dallas":{
            "latencyMs":60.463043
          },
          "New York City":{
            "preferred":true,
            "latencyMs":31.323811
          },
        },

        // WILL DOES THIS NEED A DESC?
        "clientSupports":{

          // "hairpinning" (boolean) is 'true' if your router can route connections from endpoints on your LAN back to your LAN using those endpoints’ globally-mapped IPv4 addresses/ports
          "hairPinning":false,

          // "ipv6" (boolean) is 'true' if the device OS supports IPv6, 
          // regardless of whether IPv6 internet connectivity is available.
          "ipv6":false,

          // "pcp" (boolean) is 'true' if PCP port-mapping service exists on
          // your router
          "pcp":false,

          // "pmp" (boolean) is 'true' if NAT-PMP port-mapping service exists
          // on your router
          "pmp":false,

          // "udp" (boolean) is 'true' if UDP traffic is enabled on the 
          // current network; if 'false', Tailscale may be unable to make 
          // direct connections, and will rely on our DERP servers
          "udp":true,

          // "upnp" (boolean) is 'true' if UPnP port-mapping service exists
          // on your router
          "upnp":false
        }
      
      // "clientVersion" (string) is the version of the Tailscale client  
      // software; this is empty for external devices. 
      "clientVersion": "",

      // "created" (string) is the date on which the device was added 
      // to the tailnet; this is empty for external devices. 
      "created": "",

      // "enabledRoutes" (array of strings) are the subnet routes for this  
      // device that have been approved by the tailnet admin.       
      // Learn more about subnet routes at https://tailscale.com/kb/1019/.
      "enabledRoutes" : [
      "10.0.1.0/24",
      "1.2.0.0/16",
      "2.0.0.0/24"
      ]
      
      // "expires" (string) is the expiration date of the device's
      // authentication key.
      // Learn more about key expiry at https://tailscale.com/kb/1028.
      "expires": "2023-05-30T04:44:05Z",

      // "hostname" (string) is the machine name in the admin console 
      // Learn more about machine names at https://tailscale.com/kb/1098.
      "hostname": "go",

      // "id" (string) is the legacy identifier for a node (AKA device); you 
      // can provide this value wherever {deviceId} is indicated in the 
      // endpoint. Note that although "id" is still accpeted, "nodeId" is 
      // preferred.
      "id": "39381946735751060",

      // "isExternal" (boolean) if 'true', indicates that a device is not 
      // a member of the tailnet, but is shared in to the tailnet; 
      // if 'false', the device is a member of the tailnet.
      // Learn more about node sharing at https://tailscale.com/kb/1084.
      "isExternal": true,

      // "keyExpiryDisabled" (boolean) is 'true' if the keys for the device
      // will not expire. Learn more at https://tailscale.com/kb/1028.
      "keyExpiryDisabled": true,

      // "lastSeen" (string) is when device was last active on the tailnet.
      "lastSeen": "2022-12-01T05:23:30Z",

      // "machineKey" (string) is for internal use and is not required for
      // any API operations. This value is empty for external devices.
      "machineKey": "",

      // "name" (string) is THE MagicDNS name of the device.
      // Learn more about MagicDNS at https://tailscale.com/kb/1081.
      "name": "go-test.namename.ts.net",

      // "nodeID" (string) is the preferred identifier for a node (AKA device);  
      // provide this value wherever {deviceId} is indicated in the endpoint.
      // Find the node ID value as "ID" in the Tailscale admin console's 
      // Machines tab, in the Machine Details section.
      "nodeId": "nWqeZf5CNTRL",

      // "nodeKey" (string) is mostly for internal use, required for select 
      // operations, such as adding a node to a locked tailnet. 
      // Most operations require "nodeId" or "id" rather than "nodeKey".
      // Learn about tailnet locks at https://tailscale.com/kb/1226.
      "nodeKey": 
      "nodekey:c123959c82afcbeb716bc9fd72cf46a5d46844fd3e97590b90b021469860d266",

      // "os" (string) is the operating system that the device is running.
      "os": "linux",

      // "tags" (array of strings) let you assign an identity to a device that
      // is separate from human users, and use it as part of an ACL to restrict 
      // access. Once a device is tagged, the tag is the owner of that device.
      // A single node can have multiple tags assigned. 
      // Learn more about tags at https://tailscale.com/kb/1068/acl-tags/. 
      // This value is empty for external devices.
      "tags": [
        "tag:golink"
      ],

      // "tailnetLockError" (string) indicates an issue with the tailnet lock 
      // node-key signature on this device. 
      // This field is only populated when tailnet lock is enabled.
      "tailnetLockError": "",

      // "tailnetLockKey" (string) is the node's tailnet lock key. Every node
      // generates a tailnet lock key (so the value will be present) even if 
      // tailnet lock is not enabled.
      // Learn more about tailnet lock at: https://tailscale.com/kb/1226/.
      "tailnetLockKey": "",

      // "updateAvailable" (boolean) is 'true' if a Tailscale client version
      // upgrade is available. This value is empty for external devices.
      "updateAvailable": false,

      // "user" (string) For nodes that are not tagged, this is the user who 
      // originally created the node, or whose auth key was used to create the 
      // node (tag would override the user).
      "user": "username@github"
    },

```

### Subnet Routes

Nodes (or devices) within a tailnet can be set up as subnet routers.  A subnet router acts as a gateway, relaying traffic from your Tailscale network onto your physical subnet. Setting up subnet routers exposes routes to other nodes in the tailnet. Learn more about [subnet routers](https://tailscale.com/kb/1019).

A device can act as a subnet router if its subnet routes are both advertised and enabled. This is a two-step process, but the steps can occur in any order: 
- The device that intends to act as a subnet router exposes its routes by **advertising** them. This is done in the Tailscale command-line interface.
- The tailnet admin must approve the routes by **enabling** them. This is done in the [**Machines**](https://login.tailscale.com/admin/machines) page of the Tailscale admin console or in this API via the [`POST /api/v2/device/{deviceID}/routes`](#set-enabled-subnet-routes-for-a-device) endpoint. 

If a device has advertised routes, they are not exposed to traffic until they are enabled by the tailnet admin. Conversely, if a tailnet admin pre-approves certain routes by enabling them, they are not available for routing until the device in question has advertised them.

The Devices endpoint exposes two methods for dealing with subnet routes:
- [`GET /api/v2/device/{deviceID}/routes`](#fetch-device-routes) to fetch lists of advertised and enabled routes for a device
- [`POST /api/v2/device/{deviceID}/routes`](#set-enabled-subnet-routes-for-a-device) to set enabled routes for a device

## Fetch the details for a device

``` http
GET /api/v2/device/{deviceid}
```

Retrieve the details for the specified device. Returns a JSON `device` object listing either all device attributes, or a predefined subset of the attributes.

### Input parameters

#### `{deviceid}` (required in URL path)

Supply the device of interest in the path using its ID.

#### `fields` (optional in query string)

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
DELETE /api/v2/device/{deviceID}
``` 

Deletes the provided device from its tailnet. The device must belong to the user's tailnet. Deleting shared/external devices is not supported. Supply the device to delete in the URL path using its ID.

Returns an empty response if successful; otherwise, a '501' response if the device is not owned by the tailnet.

### Input parameters

#### `{deviceid}` (required in URL path)
Supply the device of interest in the path using its ID.

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
GET /api/v2/device/{deviceID}/routes
``` 

Fetch a list of subnet routes that are advertised, and a list of subnet routes that are enabled for a device. Subnet routes are introduced [above](#subnet-routes) and discussed further in our [Knowledge Base](https://tailscale.com/kb/1019). 

This API call retrieves the list of subnet routes that a device is advertising, as well as those that are enabled for it:
- **Enabled routes:** The subnet routes for this device that have been approved by the tailnet admin. 
- **Advertised routes:** The subnets this device intends to expose.

### Input parameters

#### `{deviceid}` (required in URL path)
Supply the device of interest in the path using its ID.

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
POST /api/v2/device/{deviceID}/routes
```

Set the subnet routes that are enabled for a device. Subnet routes are introduced [above](#subnet-routes) and discussed further in our [Knowledge Base](https://tailscale.com/kb/1019/subnets/).

This call sets a device's enabled subnet routes by replacing the existing list of subnet routes with the supplied parameters. Tailscale returns a JSON list with enabled subnet routes and a list of advertised subnet routes for a device.

### Input parameters

#### `{deviceid}` (required in URL path)
Supply the device of interest in the path using its ID.

#### `routes` (optional in `POST` body)

The new list of enabled subnet routes in JSON. Provide this parameter as an array of strings in the `POST` body, as shown:

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
POST /api/v2/device/{deviceID}/authorized
```

Authorize a device. This call marks a device as authorized for Tailnets where device authorization is required.

Tailscale returns a successful 2xx response with an empty JSON object in the response body.

### Input parameters

#### `{deviceid}` (required in URL path)
Supply the device of interest in the path using its ID.

#### `authorized` (optional in `POST` body)
Specify whether the device is authorized. Only 'true' is currently supported. Provide this parameter in the `POST` body, as shown:

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
POST /api/v2/device/{deviceID}/tags
```

Update the tags set on a device. Tags let you assign an identity to a device that is separate from human users, and use that identity as part of an ACL to restrict access. Tags are similar to role accounts, but more flexible.
 
Tags are created in the tailnet policy file (also known as the ACL file); a tag is created by defining an owner. Once a device is tagged, the tag is the owner of that device. A single node can have multiple tags assigned.

Consult the policy file for your tailnet in the [admin console](https://login.tailscale.com/admin/acls) for the list of tags that have been created for your tailnet. Learn more about [tags](https://tailscale.com/kb/1068/acl-tags/).

Tailscale returns a 2xx code if successful, with an empty JSON object in the response body.

### Input parameters

#### `{deviceid}` (required in URL path)
Supply the device of interest in the path using its ID.

#### `tags` (optional in `POST` body)
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

## Update device node key expiry
``` http
POST /api/v2/device/{deviceID}/key
```

Disable or enable the expiry of the device's node key. When a device is added to a tailnet, its key expiry is set in the [General settings](https://login.tailscale.com/admin/settings/general) page of the admin console, with a duration between 1-180 days. If the key is not refreshed and expires, the device can no longer communicate with other devices in the tailnet. 

Use this API call setting `"keyExpiryDisabled": true` to disable key expiry for the device, so that the device can rejoin the tailnet. You then have the option to update the key and call this endpoint again, this time with `"keyExpiryDisabled": false` to re-enable expiry. -->

### Input parameters

#### `{deviceid}` (required in URL path)
Supply the device of interest in the path using its ID.

#### `keyExpiryDisabled` (optional in `POST` body)
Provide this parameter as a boolean in the `POST` body as shown:

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

A tailnet is your private network, composed of all the devices on it and their configuration. Learn more about [tailnets](https://tailscale.com/kb/1136/tailnet/).

When making API requests, URLs are structured as `/api/v2/tailnet/{tailnet}/`. 

Where `{tailnet}` is indicated in the URL, you have two options:

- **Simply provide the `{tailnet}` value as a dash (`-`).** This refers to the default tailnet of the authenticated user making the API call and is the best option for most users. Your API call to the tailnet endpoint would start like this:

  ``` sh
  curl 'https://api.tailscale.com/api/v2/tailnet/-/...'
  ```

- Alternately, you can provide the **organization** name found on the **[General Settings](https://login.tailscale.com/admin/settings/general)** page of the Tailscale admin console (not to be confused with the "tailnet name" found in the DNS tab).

  For example, if your organization name is `alice@example.com`, your API call to the tailnet endpoint would start like this:

  ``` sh
  curl 'https://api.tailscale.com/api/v2/tailnet/alice@example.com/...'
  ```

Endpoints:

- [`GET /api/v2/tailnet/{tailnet}/acl`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/acl`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/acl/preview`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/acl/validate`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/devices`](#fetch-a-list-of-tailnet-devices)
- [`GET /api/v2/tailnet/{tailnet}/keys`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/keys`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](JULIA)
- [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](JULIA)

## ACL in the tailnet policy file

Access control lists (ACL) and rules are stored in the tailnet policy file and can be expressed in two formats: plain JSON and HuJSON (human JSON, a superset of JSON that allows comments and trailing commas). Learn more about [network access controls](https://tailscale.com/kb/1018/).

Endpoints:

- [`GET /api/v2/tailnet/{tailnet}/acl`](#fetch-the-tailnet-policy-file) 
- [`POST /api/v2/tailnet/{tailnet}/acl`](#replace-the-tailnet-policy-file)
- [`POST /api/v2/tailnet/{tailnet}/acl/preview`](#preview-rule-matches-on-an-ACL-for-a-resource)
- [`POST /api/v2/tailnet/{tailnet}validate`](#run-validation-tests-against-the-tailnets-active-ACL)

## Fetch the tailnet policy file

``` http
GET /api/v2/tailnet/{tailnet}/acl
```

Retrieves the current policy file for the given tailnet; this includes the ACL along with the rules and tests that have been defined. Supply the tailnet of interest in the path. This endpoint can send back either the HuJSON of the ACL or a parsed JSON, depending on the `Accept` header.

Returns the ACL HuJSON by default. Returns a parsed JSON of the ACL (sans comments) if the `Accept` type is explicitly set to `application/json`. The response also includes an `ETag` header, which can be optionally used in `POST` requests to avoid missed updates.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `Accept` (optional in request header)
Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

- **`application/hujson`:** The response will be parsed human JASON; this is also the default if no value is provided.

- **`application/json`:** The response will be parsed JSON.

#### `details` (optional in query string)

Request a detailed description of the tailnet policy file by providing `details=1` in the URL query string as follows: `api/v2/tailnet/-/acl?details=1`. If using this, do not provide an `Accept` parameter in the header.

Tailscale returns three fields: 
- **tailnet policy file:** a base64-encoded string representation of the huJSON format
- **warnings:** array of strings for syntactically valid but nonsensical entries
- **errors:** an array of strings for parsing failures

### Request example (response in HuJSON format)

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl' \
  -u "tskey-yourapikey123:" \
  -H "Accept: application/hujson" \
  -v
```

### Response in HuJSON format

Successful response returns an HTTP code of '200' and the tailnet policy file in HuJSON format, as per the request header. No errors or warnings are returned.

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

### Request example (response in JSON format)

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl' \
  -u "tskey-yourapikey123:" \
  -H "Accept: application/json" \
  -v
```

### Response in JSON format

Successful response returns an HTTP code of '200' and the tailnet policy file in JSON format, as per the request header. No errors or warnings are returned.

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
### Request example (with details)

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl?details=1' \
  -u "tskey-yourapikey123:" \
  -H 
  -v
```

### Response (with details)

Successful response returns an HTTP code of '200' and the tailnet policy file in a base64-encoded string representation of the huJSON format. In addition, errors and warnings are returned.

``` sh
{
  "acl": "Ly8gRXhhbXBsZS9kZWZhdWx0IEFDTHMgZm9yIHVucmVzdHJpY3RlZCBjb25uZWN0aW9ucy4KewoJLy8gRGVjbGFyZSBzdGF0aWMgZ3JvdXBzIG9mIHVzZXJzIGJleW9uZCB0aG9zZSBpbiB0aGUgaWRlbnRpdHkgc2VydmljZS4KCSJncm91cHMiOiB7CgkJImdyb3VwOmV4YW1wbGUiOiBbInVzZXIxQGV4YW1wbGUuY29tIiwgInVzZXIyQGV4YW1wbGUuY29tIl0sCgl9LAoKCS8vIERlY2xhcmUgY29udmVuaWVudCBob3N0bmFtZSBhbGlhc2VzIHRvIHVzZSBpbiBwbGFjZSBvZiBJUCBhZGRyZXNzZXMuCgkiaG9zdHMiOiB7CgkJImV4YW1wbGUtaG9zdC0xIjogIjEwMC4xMDAuMTAwLjEwMCIsCgl9LAoKCS8vIEFjY2VzcyBjb250cm9sIGxpc3RzLgoJImFjbHMiOiBbCgkJLy8gTWF0Y2ggYWJzb2x1dGVseSBldmVyeXRoaW5nLgoJCS8vIENvbW1lbnQgdGhpcyBzZWN0aW9uIG91dCBpZiB5b3Ugd2FudCB0byBkZWZpbmUgc3BlY2lmaWMgcmVzdHJpY3Rpb25zLgoJCXsiYWN0aW9uIjogImFjY2VwdCIsICJ1c2VycyI6IFsiKiJdLCAicG9ydHMiOiBbIio6KiJdfSwKCV0sCgkic3NoIjogWwoJCS8vIEFsbG93IGFsbCB1c2VycyB0byBTU0ggaW50byB0aGVpciBvd24gZGV2aWNlcyBpbiBjaGVjayBtb2RlLgoJCS8vIENvbW1lbnQgdGhpcyBzZWN0aW9uIG91dCBpZiB5b3Ugd2FudCB0byBkZWZpbmUgc3BlY2lmaWMgcmVzdHJpY3Rpb25zLgoJCXsKCQkJImFjdGlvbiI6ICJjaGVjayIsCgkJCSJzcmMiOiAgICBbImF1dG9ncm91cDptZW1iZXJzIl0sCgkJCSJkc3QiOiAgICBbImF1dG9ncm91cDpzZWxmIl0sCgkJCSJ1c2VycyI6ICBbImF1dG9ncm91cDpub25yb290IiwgInJvb3QiXSwKCQl9LAoJXSwKCSJ0YWdPd25lcnMiOiB7CgkJInRhZzpnb2xpbmsiOiBbImV4YW1wbGUuY29tIl0sCgl9LAp9Cg==",
  "warnings": [
    "\"group:example\": user not found: \"user1@example.com\"",
    "\"group:example\": user not found: \"user2@example.com\""
  ],
  "errors": null
}
```

## Update the policy file for a tailnet

``` http
POST /api/v2/tailnet/{tailnet}/acl`
```

Sets the ACL for the given tailnet. HuJSON and JSON are both accepted inputs. An `If-Match` header can be set to avoid missed updates.

On success, returns the updated ACL in JSON or HuJSON according to the `Accept` header. Otherwise, errors are returned for incorrectly defined ACLs, ACLs with failing tests on attempted updates, and mismatched `If-Match` header and ETag.

### Input parameters

#### {tailnet} (required in URL path)
Supply the tailnet in the path.

#### `If-Match` (optional in request header)
This is a safety mechanism to avoid overwriting other users' updates to the tailnet policy file. 

- Set the `If-Match` value to that of the ETag header returned in a `GET` request to `/api/v2/tailnet/{tailnet}/acl`. Tailscale compares the ETag value in your request to that of the current tailnet file and only replaces the file if there's a match. (A mismatch indicates that another update has been made to the file.) 
  For example: `-H "If-Match: \"e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c\""`
- Alternately, set the `If-Match` value to `ts-default` to ensure that the policy file is replaced _only if the current policy file is still the untouched default_ created automatically for each tailnet.
  For example: `-H "If-Match: \"ts-default\""`

#### `Accept` (optional in request header)
Sets the return type of the updated tailnet policy file. Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

#### Tailnet policy file entries (required in `POST` body)

Define the policy file in the `POST` body. Include the entire policy file. Note that the provided object fully replaces your existing tailnet policy file.

The `POST` body should be a JSON- or [HuJSON](https://github.com/tailscale/hujson#hujson---human-json)-formatted JSON object. Learn about the [ACL policy properties you can include in the request](https://tailscale.com/kb/1018/acls/#tailscale-policy-syntax). 

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

### Response

A successful response returns an HTTP status of '200' and the modified tailnet policy file in JSON or HuJSON format, depending on the request header.

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

## Preview policy file rule matches for a resource

``` http
POST /api/v2/tailnet/{tailnet}/acl/preview
```
When given a user or IP port to match against, returns the tailnet policy rules that apply to that resource without saving the policy file to the server.

### Input parameters 

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `type` (required in query string)

Specify for which type of resource (user or IP port) matching rules are to be fetched. Provide this parameter in the query string as shown in the request example below. Read about [previewing changes in the admin console](https://tailscale.com/kb/1018/acls/#previewing-changes).

- **`user`:** Specify 'user' if the `previewFor` value is a user's email. Note that `user` remains in the API for compatibility purposes, but has been replaced by "source" (`src`) in Tailscale.
- **`ipport`:** Specify 'ipport' if the `previewFor` value is an IP address and port. Note that `ipport` remains in the API for compatibility purposes, but has been replaced by "destination" (`dst`) in Tailscale.

#### `previewFor` (required in query string)

Provide this parameter in the query string as shown in the request example below.

- If `type`='user', provide the email of a valid user with registered machines. 
- If `type`='ipport', provide an IP address + port in this format: "10.0.0.1:80".

The provided policy file is queried with this parameter to determine which rules match.

#### Tailnet policy file (required in `POST` body)

Provide the tailnet policy file in the `POST` body in JSON or HuJSON format. Learn about [tailnet policy file entries](https://tailscale.com/kb/1018).

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

A successful response returns an HTTP status of '200' and a list of rules that apply to the resource provided as a list of matches as JSON objects. Each match object includes: 
- `users` as an array of strings indicating source entities affected by the rule
- `ports` as an array of strings representing destinations that can be accessed
- `lineNumber` as an integer indicating the rule's location in the policy file

The response also echoes the `type` and `previewFor` values provided in the request.

``` jsonc
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

## Validate and test tailnet's policy file

``` http
POST /api/v2/tailnet/{tailnet}/acl/validate
```

This endpoint works in one of two modes, neither of which modifies your current tailnet policy file:

- **Run ACL tests:** When the **request body contains ACL tests as a JSON array**, Tailscale runs ACL tests against the tailnet's current policy file. Learn more about [ACL tests](https://tailscale.com/kb/1018/acls/#tests).
- **Validate a new policy file:** When the **request body is a JSON object**, Tailscale interprets the body as a hypothetical new tailnet policy file with new ACLs, including any new rules and tests. It validates that the policy file is parsable and runs tests to validate the existing rules. 

Learn more about [tailnet policy file tests](https://tailscale.com/kb/1018/acls/ACLS#tests).

In either case, this endpoint does not modify the tailnet policy file in any way.

### Input parameters for "Run ACL tests" mode

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### ACL tests (required in `POST` body)

The `POST` body should be a JSON formatted array of ACL Tests. Learn more about [tailnet policy tests](https://tailscale.com/kb/1018/acls/acls#tests).

### Request example to run ACL tests

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

### Input parameters for "Validate a new policy file" mode

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### Entire tailnet policy file (required in `POST` body)

The `POST` body should be a JSON object with a JSON or HuJSON representation of a tailnet policy file.

### Request example to validate a policy file

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

### Response

The HTTP status code will be '200' if the request was well formed and there were no server errors, even in the case of failing tests or an invalid ACL. Look at the response body to determine whether there was a problem within your ACL or tests:
- If the tests are valid, an empty body or a JSON object with no `message` is returned.
- If there's a problem, the response body will be a JSON object with a non-empty `message` property and optionally additional details in `data`:

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

## Tailnet devices
Refer to the Device resource description [above](#device). This endpoint addresses the devices registered to a tailnet.

Endpoints:

- [`GET /api/v2/tailnet/{tailnet}/devices`](#fetch-a-list-of-tailnet-devices)

## Fetch a list of tailnet devices

``` http
GET /api/v2/tailnet/{tailnet}/devices
```

Lists the devices in a tailnet. Supply the tailnet of interest in the path. Optionally use the `fields` query parameter to explicitly indicate which fields are returned.

This call is also useful for retrieving a device's `deviceID` (returned as `"id"`). A device ID is used in API requests where you must provide an ID in order to, for example, [fetch device details](#fetch-the-details-for-a-device) or [authorize a device](#authorize-a-device).

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `fields` (optional in query string)

Controls whether the response returns **all** fields or only a predefined subset of fields. Currently, there are two supported options:
- **`all`:** return all fields in the response
- **`default`:** return all fields **except**:
  * `enabledRoutes`
  * `advertisedRoutes`
  * `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

Provide this parameter in the query string as shown in the examples below. Use commas to separate multiple options. If more than one option is indicated, then `all` is used. For example, for `fields=default,all`, all fields are returned. 

If the `fields` parameter is not provided, then the default (limited fields) option is used.

### Request example for default set of fields

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/devices' \
  -u "tskey-yourapikey123:"
```

### Response with default set of fields
<!--JULIA CHANGE THE ABOVE ORDER IN THE DEVICE DESCS TO MATCH THE RETURNED ORDER OF PARAMETERS-->
If successful, Tailscale returns an HTTP code of '200' and a JSON list of the tailnet devices and their details, excluding `enabledRoutes`, `advertisedRoutes`, and `clientConnectivity`.

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

### Request example for all fields

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/devices?fields=all' \
  -u "tskey-yourapikey123:"
```

### Response with all fields

If successful, Tailscale returns an HTTP code of '200' and a JSON list of the tailnet devices and their details, including `enabledRoutes`, `advertisedRoutes`, and `clientConnectivity`. <!--WILL to provide standard values to plug in to all private fields, ip addresses, node keys etc.-->

``` jsonc
{
  "devices": [
    {
      "addresses": [
        "100.108.247.11",
        "fd7a:115c:a1e0:ab12:4843:cd96:626c:f70b"
      ],
      "id": "60828930103888201",
      "nodeId": "nmL9cF5CNTRL",
      "user": "example@email.com",
      "name": "danys-macbook-pro-13.taile17db.ts.net",
      "hostname": "Danys-MacBook-Pro-13",
      "clientVersion": "1.34.0-tbb6e746f3-g8d1edab6f",
      "updateAvailable": true,
      "os": "macOS",
      "created": "2022-11-18T16:51:23Z",
      "lastSeen": "2023-02-01T16:49:36Z",
      "keyExpiryDisabled": false,
      "expires": "2023-06-05T23:13:53Z",
      "authorized": true,
      "isExternal": false,
      "machineKey": "mkey:c0043101c25e07ca2bb7f829f5ff9dd5d0cb342a0fa88339d1888d0d571e002a",
      "nodeKey": "nodekey:5dec45b43a8cc1ef103285a1cb38840629ab4f6ee2d9d01f6b2c789888cabf5b",
      "tailnetLockKey": "nlpub:00147d30c323e009e62dda0314dcaa87a6245e361aed34442d34933c6566e68b",
      "blocksIncomingConnections": false,
      "enabledRoutes": [],
      "advertisedRoutes": [],
      "clientConnectivity": {
        "endpoints": [
          "98.42.44.20:41641",
          "[2601:648:8900:37b0:8ca0:d089:4fd:24e1]:41641",
          "10.0.0.152:41641",
          "[2601:648:8900:37b0::f558]:41641",
          "[2601:648:8900:37b0:184c:8fe5:f8a3:ee70]:41641"
        ],
        "derp": "",
        "mappingVariesByDestIP": false,
        "latency": {
          "Los Angeles": {
            "latencyMs": 34.354108000000004
          },
          "San Francisco": {
            "preferred": true,
            "latencyMs": 22.937421
          },
          "Seattle": {
            "latencyMs": 42.493266
          }
        },
        "clientSupports": {
          "hairPinning": false,
          "ipv6": true,
          "pcp": false,
          "pmp": false,
          "udp": true,
          "upnp": false
        }
      }
    },
    {
      "addresses": [
        "100.96.210.106",
        "fd7a:115c:a1e0:ab12:4843:cd96:6260:d26a"
      ],
      "id": "39381946735751060",
      "nodeId": "nZqeZf5CNTRL",
      "user": "example@github",
      "name": "go-test.exampl.ts.net",
      "hostname": "go",
      "clientVersion": "",
      "updateAvailable": false,
      "os": "linux",
      "created": "",
      "lastSeen": "2022-12-01T05:23:30Z",
      "keyExpiryDisabled": true,
      "expires": "2023-05-30T04:44:05Z",
      "authorized": true,
      "isExternal": true,
      "machineKey": "",
      "nodeKey": "nodekey:c368959c82afcbeb716bc9fd72cf46a5d46844fd3e97590b90b021469860d266",
      "blocksIncomingConnections": false,
      "enabledRoutes": [],
      "advertisedRoutes": [],
      "clientConnectivity": {
        "endpoints": [
          "172.17.0.2:41721",
          "24.6.96.6:56325"
        ],
        "derp": "",
        "mappingVariesByDestIP": false,
        "latency": {},
        "clientSupports": {
          "hairPinning": false,
          "ipv6": false,
          "pcp": false,
          "pmp": false,
          "udp": true,
          "upnp": false
        }
      },
      "tags": [
        "tag:golink",
        "tag:server"
      ]
    },
    {
      "addresses": [
        "100.75.209.36",
        "fd7a:115c:a1e0:ab12:4843:cd96:624b:d124"
      ],
      "id": "48375643633226582",
      "nodeId": "ntieaT7CNTRL",
      "user": "example@example.com",
      "name": "go.taile17db.ts.net",
      "hostname": "go",
      "clientVersion": "1.33.0-dev-t",
      "updateAvailable": true,
      "os": "macOS",
      "created": "2022-12-07T23:24:32Z",
      "lastSeen": "2022-12-22T19:59:28Z",
      "keyExpiryDisabled": false,
      "expires": "2023-06-05T23:24:32Z",
      "authorized": true,
      "isExternal": false,
      "machineKey": "mkey:d922f7c6547df1fab2c32d80364e0e4822165ae1a2ef9421af34500d01f61474",
      "nodeKey": "nodekey:56ba5e34ecffbbe2045d2fb132e9e9914753fce8a1585ceb25b616fc178bd123",
      "tailnetLockKey": "nlpub:6d59607bc54a21bded5a674b236450cc080f5e5f9b21f17019c3f5d4df353479",
      "blocksIncomingConnections": false,
      "enabledRoutes": [],
      "advertisedRoutes": [],
      "clientConnectivity": {
        "endpoints": [
          "10.0.1.2:50764",
          "10.0.100.242:50764",
          "24.6.96.6:50764"
        ],
        "derp": "",
        "mappingVariesByDestIP": false,
        "latency": {},
        "clientSupports": {
          "hairPinning": false,
          "ipv6": false,
          "pcp": false,
          "pmp": false,
          "udp": true,
          "upnp": false
        }
      },
      "tags": [
        "tag:golink"
      ]
    }
  ]
}
```

## Tailnet keys

Pre-authentication keys ("auth keys” for short) let you register new nodes without needing to sign in via a web browser. Auth keys are identifiable by the prefix `tskey-auth...`. Use them to add devices to your tailnet. Auth keys are used for _initial registration_ of a new device to your tailnet (after a device has joined the tailnet, there are additional keys used for subsequent authentication; these include the node key and the machine key). 

Generate or revoke an auth key in the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. When you generate a new auth key, you can specify that the key should automatically authorize devices for which the auth key is used. When generating the auth key, you can choose the number of days (1 - 90 inclusive) for the automatic key expiry. To continue using an auth key after this key expires, you must generate a new key.

Recently expired and revoked keys are shown on the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console. Learn more about [auth keys](https://tailscale.com/kb/1085/).

If you authenticate with a user-owned API key, all the methods on tailnet keys operate on _keys owned by that user_. If you authenticate with an access token derived from an OAuth client, then these methods operate on _keys owned by the tailnet_. Learn more about [OAuth clients](https://tailscale.com/kb/1215).

WHEN YOU'RE USING AN ACCESS TOKEN DERIVED FROM AN OUATH CLIENT THEN LPERATES ON KEYS OWNED BY THE TAILNET SO WHEN DO A POST, CREATING A N AUTH KEY OWNED BY THE TAILNET. EXISTYING DOCS APPLY ONLY TO USER-OWNED API KEYS

Endpoints:
- [`GET /api/v2/tailnet/{tailnet}/keys`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/keys`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](JULIA)
- [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](JULIA)

## Fetch the keys for a tailnet
``` http
GET /api/v2/tailnet/{tailnet}/keys
```

Returns a list of active auth and API keys for the tailnet supplied in the URL path, depending on permissions assigned to the caller: 
- If the API call is made  with a user-owned API key, Tailscale returns only the keys owned by the caller.
- If the API call is made with an access token derived from an OAuth client, Tailscale returns all keys owned by the tailnet that the caller's permissions allow. 

Returns a JSON object with the IDs of all active keys. In the future, this method may return more information about each key than just the ID.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

### Query Example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys' \
  -u "tskey-yourapikey123:"
```

### Response

``` jsonc
{"keys": [
	{"id": "kYKVU14CNTRL"},
	{"id": "k68VdZ3CNTRL"},
	{"id": "kJ9nq43CNTRL"},
	{"id": "kkThgj1CNTRL"}
]}
```

## Create a new key for a tailnet
<!-- WHEN CREATE JULIA GO TO TRANSCRIPT!!! "TAGS"-->
``` http
POST /api/v2/tailnet/{tailnet}/keys
```

Create a new key in a tailnet supplied in the URL path. The key will be associated with the user who owns the API key used to make this call, or, if the call is made with an access token derived from an OAuth client, the key will be owned by the tailnet. Supply the tailnet in the path.

Returns a JSON object with the provided capabilities in addition to the
generated key. The key should be recorded and kept safe and secure because it
wields the capabilities specified in the request. The identity of the key
is embedded in the key itself and can be used to perform operations on
the key (e.g., revoking it or retrieving information about it).
The full key can no longer be retrieved by the server.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `capabilities` (required in `POST` body)
<!--capabilities is required and must contain devices; devices is requried but can be an empty JSON object  -->
A mapping of resources to permissible actions; for example:

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
}
```

#### `expirySeconds` (optional in `POST` body)

Duration in seconds of the key's validity. Defaults to 90d. For example:
<!-- JULIA COMBINE BACK BC WEIRD TO HAVE ONLY EXPIERY SECONDS. ALSO DOCUMENT THE STRUCTURE OF A KEY OBJECT JUST LIKE DEVICE-->
``` jsonc
{
  "expirySeconds": 1440
}
```

### Query example

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

### Response

``` jsonc
{
	"id":           "k123456CNTRL",
	"key":          "tskey-k123456CNTRL-abcdefghijklmnopqrstuvwxyz",
	"created":      "2021-12-09T23:22:39Z",
	"expires":      "2022-03-09T23:22:39Z",
	"capabilities": {"devices": {"create": {"reusable": false, "ephemeral": false, "preauthorized": false, "tags": [ "tag:example" ]}}}
}
```

Record and safely store the `"key"` returned. It holds the capabilities specified in the request and can no longer be retrieved by the server.

## Fetch information for a specific key

``` http
GET /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Returns a JSON object with information about specific key. Supply the tailnet and key ID of interest in the path.

Returns a JSON object with information about the key such as when it was created and when it expires. It also lists the capabilities associated with the key.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `{keyId}` (required in URL path)
Supply the key ID in the path.

### Query example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-yourapikey123:"
```

### Response

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

## Delete a specific key

``` http
DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Deletes a specific key. Supply the tailnet and key ID of interest in the path.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `{keyId}` (required in URL path)
Supply the key ID in the path. <!-- WILL DO I SAY THAT THEY CAN FIND THE KEY IN THE ADMIN CONSOLE OR ARE THERE MULTIPLE PLACES-->

### Query example

``` sh
curl -X DELETE 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-yourapikey123:"
```

### Response

Tailscale returns status 200 upon success.

## DNS

The tailnet DNS endpoints are provided for fetching and modifying various DNS settings for a tailnet. These include nameservers, DNS preferences, and searchpaths.

Endpoints:

- [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](JULIA)
- [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths`](JULIA)
- [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](JULIA)

## Fetch the global DNS nameservers for a tailnet
``` http
GET /api/v2/tailnet/{tailnet}/dns/nameservers
```

Lists the global DNS nameservers for a tailnet. Supply the tailnet of interest in the path.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

### Request example

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

## Replace the list of global DNS nameservers for a tailnet

``` http
POST /api/v2/tailnet/{tailnet}/dns/nameservers
```

Replaces the list of DNS nameservers for the given tailnet with the list supplied by the user. Supply the tailnet of interest in the path. Note that changing the list of DNS nameservers may also affect the status of MagicDNS (if MagicDNS is on).

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `dns` (required in `POST` body)

The new list of DNS nameservers in JSON.

``` jsonc
{
  "dns":["8.8.8.8"]
}
```

### Response
Returns the new list of nameservers and the status of MagicDNS.

If all nameservers have been removed, MagicDNS will be automatically disabled (until explicitly turned back on by the user).

### Request example: adding DNS nameservers with MagicDNS on

Adding DNS nameservers with the MagicDNS on:

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"dns": ["8.8.8.8"]}'
```

### Response example: adding DNS nameservers, MagicDNS on

``` jsonc
{
  "dns":["8.8.8.8"],
  "magicDNS":true,
}
```

### Request example: removing all DNS nameservers, MagicDNS on

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"dns": []}'
```

### Response example: removing all DNS nameservers with MagicDNS on

``` jsonc
{
  "dns":[],
  "magicDNS": false,
}
```

## Fetch the DNS preferences for a tailnet

``` http
GET /api/v2/tailnet/{tailnet}/dns/preferences` 
```

Retrieves the DNS preferences that are currently set for the given tailnet.
Supply the tailnet of interest in the path.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences' \
  -u "tskey-yourapikey123:"
```

### Response example

``` jsonc
{
  "magicDNS":false,
}
```

## Replace the DNS preferences for a tailnet

``` http
POST /api/v2/tailnet/{tailnet}/dns/preferences
```

Replaces the DNS preferences for a tailnet; specifically, the MagicDNS setting. Note that MagicDNS is dependent on DNS servers.

If there is at least one DNS server, then MagicDNS can be enabled. Otherwise, it returns an error. 

Note that removing all nameservers will turn off MagicDNS. To reenable it, nameservers must be added back, and MagicDNS must be explicitly turned on.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### DNS preference (required in `POST` body)

The DNS preferences in JSON. Currently, MagicDNS is the only setting available.
`magicDNS` -  Automatically registers DNS names for devices in your tailnet.

``` jsonc
{
  "magicDNS": true
}
```

### Request example

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"magicDNS": true}'
```

### Response example

If there are no DNS servers, Tailscale returns an error message:

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

## Retrieve the search paths for a tailnet

``` http
GET /api/v2/tailnet/{tailnet}/dns/searchpaths
```
<!--WE DO NOT TALK ABOUT SEARCHPATHS IN THE KB DOCS-->
Retrieves the list of search paths that is currently set for the given tailnet. Supply the tailnet of interest in the path.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:"
```

### Response example
``` jsonc
{
  "searchPaths": ["user1.example.com"],
}
```

## Replace the search paths for a tailnet

``` http
POST /api/v2/tailnet/{tailnet}/dns/searchpaths
```

Replaces the list of search paths with the list supplied by the user and returns an error otherwise.

### Input parameters

#### `{tailnet}` (required in URL path)
Supply the tailnet in the path.

#### `searchPaths` (required in `POST` body)

`searchPaths` - A list of search paths in JSON.
``` jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"]
}
```

### Request example

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"searchPaths": ["user1.example.com", "user2.example.com"]}'
```

### Response example

``` jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"],
}
```
