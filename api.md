# Tailscale API

# Introduction

The Tailscale API is a (mostly) RESTful API. Typically, both `POST` bodies and responses are JSON-encoded.

## Endpoint URL

The Tailscale API URL path begins with `https://api.tailscale.com/api/v2/`.

Examples in this document begin with `api/v2/...`.

## Authentication

Requests to the Tailscale API are authenticated with an API access token (sometimes called an API key).
Access tokens can be supplied as the username portion of HTTP Basic authentication (leave the password blank) or as an OAuth Bearer token.

Access tokens for individual users can be created and managed at the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console.
These tokens will have the same permissions as the owning user, and can be set to expire in 1 to 90 days.

Alternatively, an OAuth client can be used to create short-lived access tokens with scoped permission.
Unlike access tokens, OAuth clients don't expire, and so can be used to provide ongoing access to the API by creating access tokens as needed.
OAuth clients and access tokens they create are not tied to any individual Tailscale user.
Learn more about [OAuth clients](https://tailscale.com/kb/1215/).

### Key format

In addition to access tokens and OAuth client credentials, Tailscale uses several other types of keys, which all share a similar format.
All keys are structred as `tskey-{key type}-{key data}`, with `{key type}` identifying the type of key.
Relevant to the Tailscale API are:

- API access token: `tskey-api-{key data}`
- OAuth client secret: `tskey-client-{key data}`
- Auth key: `tskey-auth-{key data}` (used in some [Key API methods](#tailnet-key-object))

## Terminology

In the context of Tailscale, the terms _device_, _machine_, and _node_ are effectively synonymous.
They all refer to a specific physical device (computer, mobile phone, virtual machine in the cloud, etc.) in a tailnet.
To specify operations on an individual device, the `nodeId` is preferred wherever `deviceId` appears in an endpoint
(a `nodeId` can be retrieved by [fetching a list of tailnet devices](#fetch-a-list-of-tailnet-devices).

## Supplying input parameters

Required input parameters can be passed in one of four places within the request:
- URL path (e.g., `{deviceId}` in `/api/v2/device/{deviceId}`)
- query string (e.g., `?fields=all` in `https://api.tailscale.com/api/v2/device/12345?fields=all`)
- HTTP headers (e.g., `Accept`)
- request body (e.g., a JSON object in the body of a `POST` request)

## Control the fields in a response

For some methods, Tailscale provides the `fields` query parameter to explicitly indicate whether **all** object fields are returned, or only a predefined subset of fields.
Details are provided in the description of each method that accepts `fields` parameter.

## Select JSON format for response

Some API calls let you select the format of the JSON returned in the response.
Supply your preference as a parameter in the **Accept** header of the request.
Two options are supported in these scenarios:

- **JSON:** Standard parsed JSON format.
- **HuJSON:** Human-readable JSON (this is the default if no format is specified).
  Learn more about [HuJSON](https://github.com/tailscale/hujson#readme).

## Errors

The Tailscale API sends status codes consistent with [standard HTTP conventions](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status).
In addition to the status code, client error messages may include additional information in the response body.

## Pagination

The Tailscale API v2 does not currently support pagination.
All results are returned at once.

# APIs

**[Device](#device)**
- Get a device: [`GET /api/v2/device/{deviceid}`](#fetch-the-details-for-a-device)
- Delete a device: [`DELETE /api/v2/device/{deviceID`}](#delete-a-device)
- **Routes**
  - Get routes: [`GET /api/v2/device/{deviceID}/routes`](#fetch-device-routes)
  - Set routes: [`POST /api/v2/device/{deviceID}/routes`](#set-enabled-subnet-routes-for-a-device)
- **Authorized**
  - Authorize a device: [`POST /api/v2/device/{deviceID}/authorized`](#authorize-a-device)
- **Tags**
  - Update tags: [`POST /api/v2/device/{deviceID}/tags`](#update-device-tags)
- **Key**
  - Set key expiry: [`POST /api/v2/device/{deviceID}/key`](#update-device-node-key-expiry)

**[Tailnet](#tailnet)**
- [**ACL**](#acl-in-the-tailnet-policy-file)
  - Get policy file: [`GET /api/v2/tailnet/{tailnet}/acl`](#fetch-the-tailnet-policy-file)
  - Update policy file: [`POST /api/v2/tailnet/{tailnet}/acl`](#update-the-policy-file-for-a-tailnet)
  - Preview rule matches: [`POST /api/v2/tailnet/{tailnet}/acl/preview`](#preview-policy-file-rule-matches-for-a-resource)
  - Validate policy file: [`POST /api/v2/tailnet/{tailnet}/acl/validate`](#validate-and-test-tailnets-policy-file)
- [**Devices**](#tailnet-devices)
  - List devices: [`GET /api/v2/tailnet/{tailnet}/devices`](#fetch-a-list-of-tailnet-devices)
- [**Keys**](#tailnet-key-object)
  - Get tailnet keys: [`GET /api/v2/tailnet/{tailnet}/keys`](#fetch-the-keys-for-a-tailnet)
  - Create a key: [`POST /api/v2/tailnet/{tailnet}/keys`](#create-a-new-key-for-a-tailnet)
  - Get key details: [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](#fetch-information-for-a-specific-tailnet-key)
  - Delete a key: [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](#delete-a-specific-tailnet-key)
- [**DNS**](#dns)
  - **Nameservers**
    - Get nameservers: [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](#fetch-the-global-dns-nameservers-for-a-tailnet)
    - Set nameservers: [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](#replace-the-list-of-global-dns-nameservers-for-a-tailnet)
  - **Preferences**
    - Get DNS preferences: [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](#fetch-the-dns-preferences-for-a-tailnet)
    - Set DNS preferences: [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](#replace-the-dns-preferences-for-a-tailnet)
  - **Search paths**
    - Get search paths: [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths](#fetch-the-search-paths-for-a-tailnet)
    - Set search paths: [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](#replace-the-search-paths-for-a-tailnet)

# Device

A Tailscale device (sometimes referred to as _node_ or _machine_), is any computer or mobile device that joins a tailnet.

Endpoints:
- Get a device: [`GET /api/v2/device/{deviceid}`](#fetch-the-details-for-a-device)
- Delete a device: [`DELETE /api/v2/device/{deviceID`}](#delete-a-device)
- **Routes**
  - Get routes: [`GET /api/v2/device/{deviceID}/routes`](#fetch-device-routes)
  - Set routes: [`POST /api/v2/device/{deviceID}/routes`](#set-enabled-subnet-routes-for-a-device)
- **Authorized**
  - Authorize a device: [`POST /api/v2/device/{deviceID}/authorized`](#authorize-a-device)
- **Tags**
  - Update tags: [`POST /api/v2/device/{deviceID}/tags`](#update-device-tags)
- **Key**
  - Set key expiry: [`POST /api/v2/device/{deviceID}/key`](#update-device-node-key-expiry)

## Device object

Each Tailscale-connected device has a globally-unique identifier number to which we refer as the `nodeId`.
Use the `nodeId` to specify operations on a specific device, such as retrieving its subnet routes.

To find the `nodeId` for a particular device in the admin console, navigate to [**Settings** → **General**](https://login.tailscale.com/admin/settings/general) and copy the **organization** name.
To retrieve a `nodeId` using the API, make a [`GET /api/v2/tailnet/{tailnet}/devices`](#fetch-a-list-of-tailnet-devices) call to generate a list of devices on your network, then find the device you're looking for and get its `"nodeId"` value.

(While `nodeId` is the preferred way to identify a unique device, `id` is also still accepted when specifying operations on a particular device.
Find the `id` of a particular device by [fetching device details](#fetch-the-details-for-a-device).)

### Attributes

``` jsonc
{
  // addresses (array of strings) is a list of Tailscale IP
  // addresses for the device, including both ipv4 (formatted as 100.x.y.z)
  // and ipv6 (formatted as fd7a:115c:a1e0:a:b:c:d:e) addresses.
  "addresses": [
    "100.96.XXX.XXX",
    "a1b2:c3d4:f6g6:h7i8:j9e5:a1b2:c3d4:e5f6"
  ],

  // id (string) is the legacy identifier for a node (AKA device); you
  // can supply this value wherever {deviceId} is indicated in the
  // endpoint. Note that although "id" is still accpeted, "nodeId" is
  // preferred.
  "id": "393XXXXX735751060",

  // nodeID (string) is the preferred identifier for a node (AKA device);
  // supply this value wherever {deviceId} is indicated in the endpoint.
  // Find the node ID value as "ID" in the Tailscale admin console's
  // Machines tab, in the Machine Details section.
  "nodeId": "abcdZf5XXXX",

  // user (string) For nodes that are not tagged, this is the user who
  // originally created the node, or whose auth key was used to create the
  // node (tag would override the user).
  "user": "username@github",

  // name (string) is THE MagicDNS name of the device.
  // Learn more about MagicDNS at https://tailscale.com/kb/1081.
  "name": "go-test.namename.ts.net",

  // hostname (string) is the machine name in the admin console
  // Learn more about machine names at https://tailscale.com/kb/1098.
  "hostname": "go",

  // clientVersion (string) is the version of the Tailscale client
  // software; this is empty for external devices.
  "clientVersion": "",

  // updateAvailable (boolean) is 'true' if a Tailscale client version
  // upgrade is available. This value is empty for external devices.
  "updateAvailable": false,

  // os (string) is the operating system that the device is running.
  "os": "linux",

  // created (string) is the date on which the device was added
  // to the tailnet; this is empty for external devices.
  "created": "",

  // lastSeen (string) is when device was last active on the tailnet.
  "lastSeen": "2022-12-01T05:23:30Z",

  // keyExpiryDisabled (boolean) is 'true' if the keys for the device
  // will not expire. Learn more at https://tailscale.com/kb/1028.
  "keyExpiryDisabled": true,

  // expires (string) is the expiration date of the device's auth key.
  // Learn more about key expiry at https://tailscale.com/kb/1028.
  "expires": "2023-05-30T04:44:05Z",

  // authorized (boolean) is 'true' if the device has been
  // authorized to join the tailnet; otherwise, 'false'. Learn
  // more about device authorization at https://tailscale.com/kb/1099/.
  "authorized": true,

  // isExternal (boolean) if 'true', indicates that a device is not
  // a member of the tailnet, but is shared in to the tailnet;
  // if 'false', the device is a member of the tailnet.
  // Learn more about node sharing at https://tailscale.com/kb/1084.
  "isExternal": true,

  // machineKey (string) is for internal use and is not required for
  // any API operations. This value is empty for external devices.
  "machineKey": "",

  // nodeKey (string) is mostly for internal use, required for select
  // operations, such as adding a node to a locked tailnet.
  // Most operations require "nodeId" or "id" rather than "nodeKey".
  // Learn about tailnet locks at https://tailscale.com/kb/1226.
  "nodeKey": "nodekey:a1b2c3d4f6g6h7i8j9e5a1b2c3d4e5f6g6h7i8j9a1b2c3d4f6g6h7i8j9",

  // blocksIncomingConnections (boolean) is 'true' if the device is not
  // allowed to accept any connections over Tailscale, including pings.
  // Reported starting with Tailscale v1.3.x. This setting is
  // configured via the device's Tailscale client preferences.
  // Learn more in the "Allow incoming connections"
  // section of https://tailscale.com/kb/1072.
  "blocksIncomingConnections": false,

  // enabledRoutes (array of strings) are the subnet routes for this
  // device that have been approved by the tailnet admin.
  // Learn more about subnet routes at https://tailscale.com/kb/1019/.
  "enabledRoutes" : [
    "10.0.1.0/24",
    "1.2.0.0/16",
    "2.0.0.0/24"
  ],

  // advertisedRoutes (array of strings) are the subnets this device
  // intends to expose.
  // Learn more about subnet routes at https://tailscale.com/kb/1019/.
  "advertisedRoutes" : [
    "10.0.1.0/24",
    "1.2.0.0/16",
    "2.0.0.0/24"
  ],

  // clientConnectivity provides a report on your current physical
  // network conditions
  "clientConnectivity": {

    // endpoints (array of strings) Client's magicsock UDP IP:port
    // endpoints (IPv4 or IPv6)
    "endpoints":[
      "209.XXX.87.XXX:59128",
      "192.XXX.0.XXX:59128"
    ],

    // derp (string) is the IP:port of the designated encrypted relay
    // for packets (DERP) server currently being used; learn about DERP
    // servers here: https://tailscale.com/kb/1232
    "derp":"",

    // mappingVariesByDestIP (boolean) is 'true' if the host's network
    // address translation (NAT-enables multiple machines behind a router
    // to share the same public IP address) mappings vary based on the
    // destination IP
    "mappingVariesByDestIP":false,

    // latency (map) lists DERP server locations and their current
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

    // clientSupports (JSON object) features supported by the client's networking environment
    "clientSupports":{

      // hairpinning (boolean) is 'true' if your router can route connections
      // from endpoints on your LAN back to your LAN using those endpoints’
      // globally-mapped IPv4 addresses/ports
      "hairPinning":false,

      // ipv6 (boolean) is 'true' if the device OS supports IPv6,
      // regardless of whether IPv6 internet connectivity is available.
      "ipv6":false,

      // pcp (boolean) is 'true' if PCP port-mapping service exists on
      // your router
      "pcp":false,

      // pmp (boolean) is 'true' if NAT-PMP port-mapping service exists
      // on your router
      "pmp":false,

      // udp (boolean) is 'true' if UDP traffic is enabled on the
      // current network; if 'false', Tailscale may be unable to make
      // direct connections, and will rely on our DERP servers
      "udp":true,

      // upnp (boolean) is 'true' if UPnP port-mapping service exists
      // on your router
      "upnp":false
    },
  },

  // tags (array of strings) let you assign an identity to a device that
  // is separate from human users, and use it as part of an ACL to restrict
  // access. Once a device is tagged, the tag is the owner of that device.
  // A single node can have multiple tags assigned.
  // Learn more about tags at https://tailscale.com/kb/1068/acl-tags/.
  // This value is empty for external devices.
  "tags": [
    "tag:golink"
  ],

  // tailnetLockError (string) indicates an issue with the tailnet lock
  // node-key signature on this device.
  // This field is only populated when tailnet lock is enabled.
  "tailnetLockError": "",

  // tailnetLockKey (string) is the node's tailnet lock key. Every node
  // generates a tailnet lock key (so the value will be present) even if
  // tailnet lock is not enabled.
  // Learn more about tailnet lock at: https://tailscale.com/kb/1226/.
  "tailnetLockKey": "",
},
```

### Subnet Routes

Nodes (or devices) within a tailnet can be set up as subnet routers.
A subnet router acts as a gateway, relaying traffic from your Tailscale network onto your physical subnet.
Setting up subnet routers exposes routes to other nodes in the tailnet.
Learn more about [subnet routers](https://tailscale.com/kb/1019).

A device can act as a subnet router if its subnet routes are both advertised and enabled.
This is a two-step process, but the steps can occur in any order:
- The device that intends to act as a subnet router exposes its routes by **advertising** them.
  This is done in the Tailscale command-line interface.
- The tailnet admin must approve the routes by **enabling** them.
  This is done in the [**Machines**](https://login.tailscale.com/admin/machines) page of the Tailscale admin console or in this API via the [`POST /api/v2/device/{deviceID}/routes`](#set-enabled-subnet-routes-for-a-device) endpoint.

If a device has advertised routes, they are not exposed to traffic until they are enabled by the tailnet admin.
Conversely, if a tailnet admin pre-approves certain routes by enabling them, they are not available for routing until the device in question has advertised them.

The Devices endpoint exposes two methods for dealing with subnet routes:
  - Get routes: [`GET /api/v2/device/{deviceID}/routes`](#fetch-device-routes) to fetch lists of advertised and enabled routes for a device
  - Set routes: [`POST /api/v2/device/{deviceID}/routes`](#set-enabled-subnet-routes-for-a-device) to set enabled routes for a device

## Fetch the details for a device

``` http
GET /api/v2/device/{deviceid}
```

Retrieve the details for the specified device.
Returns a JSON `device` object listing either all device attributes, or a predefined subset of the attributes.

### Input parameters

#### `deviceid` (required in URL path)

Supply the device of interest in the path using its ID.

#### `fields` (optional in query string)

Controls whether the response returns **all** object fields or only a predefined subset of fields.
Currently, there are two supported options:
- **`all`:** return all object fields in the response
- **`default`:** return all object fields **except**:
  - `enabledRoutes`
  - `advertisedRoutes`
  - `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

Use commas to separate multiple options.
If more than one option is indicated, then `all` is used.
For example, for `fields=default,all`, all fields are returned.
If the `fields` parameter is not supplied, then the default (limited fields) option is used.

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
    "100.XXX.58.XXX"
    "a1b2:c3d4:f6g6:h7i8:j9e5:a1b2:c3d4:e5f6"
  ],
  "id":"12345",

  // Additional fields as documented in device "Attributes" section above
}
{
  "addresses":[
    "100.XXX.85.XXX"
    "a1b2:c3d4:f6g6:h7i8:j9e5:a1b2:c3d4:m4xY"
  ],
  "id":"67891",

  // Additional fields as documented in device "Attributes" section above
}
```

## Delete a device

``` http
DELETE /api/v2/device/{deviceID}
```

Deletes the supplied device from its tailnet.
The device must belong to the user's tailnet.
Deleting shared/external devices is not supported.
Supply the device to delete in the URL path using its ID.

Returns an empty response if successful; otherwise, a '501' response if the device is not owned by the tailnet.

### Input parameters

#### `deviceid` (required in URL path)
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

Fetch a list of subnet routes that are advertised, and a list of subnet routes that are enabled for a device.
Subnet routes are introduced [above](#subnet-routes) and discussed further in our [Knowledge Base](https://tailscale.com/kb/1019).

This API call retrieves the list of subnet routes that a device is advertising, as well as those that are enabled for it:
- **Enabled routes:** The subnet routes for this device that have been approved by the tailnet admin.
- **Advertised routes:** The subnets this device intends to expose.

### Input parameters

#### `deviceid` (required in URL path)
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

Set the subnet routes that are enabled for a device.
Subnet routes are introduced [above](#subnet-routes) and discussed further in our [Knowledge Base](https://tailscale.com/kb/1019/subnets/).

This call sets a device's enabled subnet routes by replacing the existing list of subnet routes with the supplied parameters.
Tailscale returns a JSON list with enabled subnet routes and a list of advertised subnet routes for a device.

### Input parameters

#### `deviceid` (required in URL path)
Supply the device of interest in the path using its ID.

#### `routes` (optional in `POST` body)

The new list of enabled subnet routes in JSON.
Supply this parameter as an array of strings in the `POST` body, as shown:

``` jsonc
{
  "routes": ["10.0.1.0/24", "10.0.2.0/24"]
}
```

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/11055/routes' \
-u "tskey-yourapikey123:" \
--data-binary '{"routes": ["10.0.1.0/24", "10.0.2.0/24"]}'
```

### Response

``` jsonc
{
   "advertisedRoutes" : [
      "10.0.1.0/24",
      "10.0.2.0/24",

   ],
   "enabledRoutes" : [
      "10.0.1.0/24",
      "10.0.2.0/24"
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

#### `deviceid` (required in URL path)
Supply the device of interest in the path using its ID.

#### `authorized` (optional in `POST` body)
Specify whether the device is authorized. Only 'true' is currently supported. Supply this parameter in the `POST` body, as shown:

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

Update the tags set on a device.
Tags let you assign an identity to a device that is separate from human users, and use that identity as part of an ACL to restrict access.
Tags are similar to role accounts, but more flexible.

Tags are created in the tailnet policy file (also known as the ACL file); a tag is created by defining an owner.
Once a device is tagged, the tag is the owner of that device.
A single node can have multiple tags assigned.

Consult the policy file for your tailnet in the [admin console](https://login.tailscale.com/admin/acls) for the list of tags that have been created for your tailnet.
Learn more about [tags](https://tailscale.com/kb/1068/acl-tags/).

Tailscale returns a 2xx code if successful, with an empty JSON object in the response body.

### Input parameters

#### `deviceid` (required in URL path)
Supply the device of interest in the path using its ID.

#### `tags` (optional in `POST` body)
The new list of tags for the device. Supply this parameter in the `POST` body as shown:

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

If the tags supplied in the `POST` call do not exist in the tailnet policy file, the response is '400 Bad Request':

``` jsonc
{
  "message": "requested tags [tag:madeup tag:wrongexample] are invalid or not permitted"
}
```

## Update device node key expiry
``` http
POST /api/v2/device/{deviceID}/key
```

Disable or enable the expiry of the device's node key.
When a device is added to a tailnet, its key expiry is set in the [General settings](https://login.tailscale.com/admin/settings/general) page of the admin console, with a duration between 1-180 days.
If the key is not refreshed and expires, the device can no longer communicate with other devices in the tailnet.

Use this API call setting `"keyExpiryDisabled": true` to disable key expiry for the device, so that the device can rejoin the tailnet.
You then have the option to update the key and call this endpoint again, this time with `"keyExpiryDisabled": false` to re-enable expiry.

### Input parameters

#### `deviceid` (required in URL path)
Supply the device of interest in the path using its ID.

#### `keyExpiryDisabled` (optional in `POST` body)
Supply this parameter as a boolean in the `POST` body as shown:

``` jsonc
{
  "keyExpiryDisabled": true
}
```

- Supply `true` to disable the device's key expiry.
  The original key expiry time is still maintained.
  Upon re-enabling, the key will expire at that original time.
- Supply `false` to enable the device's key expiry.
  Sets the key to expire at the original expiry time prior to disabling.
  The key may already have expired. In that case, the device must be re-authenticated.
- Empty value will not change the key expiry.

Tailscale returns a 2xx code on success, with an empty JSON object in the response body.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/device/11055/key' \
-u "tskey-yourapikey123:" \
--data-binary '{"keyExpiryDisabled": true}'
```

### Response
The response is 2xx on success. The response body is currently an empty JSON object.

# Tailnet

A tailnet is your private network, composed of all the devices on it and their configuration.
Learn more about [tailnets](https://tailscale.com/kb/1136/tailnet/).

When making API requests, URLs are structured as `/api/v2/tailnet/{tailnet}/`.

Where `tailnet` is indicated in the URL, you have two options:

- **Simply supply the `tailnet` value as a dash (`-`).**
  This refers to the default tailnet of the authenticated user making the API call and is the best option for most users.
  Your API call to the tailnet endpoint would start like this:

  ``` sh
  curl 'https://api.tailscale.com/api/v2/tailnet/-/...'
  ```

- Alternately, you can supply the **organization** name found on the **[General Settings](https://login.tailscale.com/admin/settings/general)**
  page of the Tailscale admin console (not to be confused with the "tailnet name" found in the DNS tab).

  For example, if your organization name is `alice@example.com`, your API call to the tailnet endpoint would start like this:

  ``` sh
  curl 'https://api.tailscale.com/api/v2/tailnet/alice@example.com/...'
  ```

Endpoints:

- [**ACL**](#acl-in-the-tailnet-policy-file)
  - Get policy file: [`GET /api/v2/tailnet/{tailnet}/acl`](#fetch-the-tailnet-policy-file)
  - Update policy file: [`POST /api/v2/tailnet/{tailnet}/acl`](#update-the-policy-file-for-a-tailnet)
  - Preview rule matches: [`POST /api/v2/tailnet/{tailnet}/acl/preview`](#preview-policy-file-rule-matches-for-a-resource)
  - Validate policy file: [`POST /api/v2/tailnet/{tailnet}/acl/validate`](#validate-and-test-tailnets-policy-file)
- [**Devices**](#tailnet-devices)
  - List devices: [`GET /api/v2/tailnet/{tailnet}/devices`](#fetch-a-list-of-tailnet-devices)
- [**Keys**](#tailnet-key-object)
  - Get tailnet keys: [`GET /api/v2/tailnet/{tailnet}/keys`](#fetch-the-keys-for-a-tailnet)
  - Create a key: [`POST /api/v2/tailnet/{tailnet}/keys`](#create-a-new-key-for-a-tailnet)
  - Get key details: [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](#fetch-information-for-a-specific-tailnet-key)
  - Delete a key: [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](#delete-a-specific-tailnet-key)
- [**DNS**](#dns)
  - **Nameservers**
    - Get nameservers: [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](#fetch-the-global-dns-nameservers-for-a-tailnet)
    - Set nameservers: [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](#replace-the-list-of-global-dns-nameservers-for-a-tailnet)
  - **Preferences**
    - Get DNS preferences: [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](#fetch-the-dns-preferences-for-a-tailnet)
    - Set DNS preferences: [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](#replace-the-dns-preferences-for-a-tailnet)
  - **Search paths**
    - Get search paths: [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths](#fetch-the-search-paths-for-a-tailnet)
    - Set search paths: [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](#replace-the-search-paths-for-a-tailnet)

## ACL in the tailnet policy file

Access control lists (ACL) and rules are stored in the tailnet policy file and can be expressed in two formats:
plain JSON and HuJSON (human JSON, a superset of JSON that allows comments and trailing commas).
Learn more about [network access controls](https://tailscale.com/kb/1018/).

Endpoints:

- Get policy file: [`GET /api/v2/tailnet/{tailnet}/acl`](#fetch-the-tailnet-policy-file)
- Update policy file: [`POST /api/v2/tailnet/{tailnet}/acl`](#update-the-policy-file-for-a-tailnet)
- Preview rule matches: [`POST /api/v2/tailnet/{tailnet}/acl/preview`](#preview-policy-file-rule-matches-for-a-resource)
- Validate policy file: [`POST /api/v2/tailnet/{tailnet}/acl/validate`](#validate-and-test-tailnets-policy-file)

## Fetch the tailnet policy file

``` http
GET /api/v2/tailnet/{tailnet}/acl
```

Retrieves the current policy file for the given tailnet; this includes the ACL along with the rules and tests that have been defined.
Supply the tailnet of interest in the path.
This endpoint can send back either the HuJSON of the ACL or a parsed JSON, depending on the `Accept` header.

Returns the ACL HuJSON by default.
Returns a parsed JSON of the ACL (sans comments) if the `Accept` type is explicitly set to `application/json`.
The response also includes an `ETag` header, which can be optionally used in `POST` requests to avoid missed updates.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### `Accept` (optional in request header)
Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

- **`application/hujson`:** The response will be parsed human JASON; this is also the default if no value is supplied.

- **`application/json`:** The response will be parsed JSON.

#### `details` (optional in query string)

Request a detailed description of the tailnet policy file by providing `details=1` in the URL query string as follows: `api/v2/tailnet/-/acl?details=1`.
If using this, do not supply an `Accept` parameter in the header.

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

Successful response returns an HTTP code of '200' and the tailnet policy file in HuJSON format, as per the request header.
No errors or warnings are returned.

``` jsonc
...
Content-Type: application/hujson
Etag: "a1b2c3d4f6g6h7i8j9e5a1b2c3d4e5f6g6h7i8j9a1b2c3d4f6g6h7i8j9"
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

Successful response returns an HTTP code of '200' and the tailnet policy file in JSON format, as per the request header.
No errors or warnings are returned.

``` jsonc
...
Content-Type: application/json
Etag: "a1b2c3d4f6g6h7i8j9e5a1b2c3d4e5f6g6h7i8j9a1b2c3d4f6g6h7i8j9"
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

Successful response returns an HTTP code of '200' and the tailnet policy file in a base64-encoded string representation of the huJSON format.
In addition, errors and warnings are returned.

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

Sets the ACL for the given tailnet.
HuJSON and JSON are both accepted inputs.
An `If-Match` header can be set to avoid missed updates.

On success, returns the updated ACL in JSON or HuJSON according to the `Accept` header.
Otherwise, errors are returned for incorrectly defined ACLs, ACLs with failing tests on attempted updates, and mismatched `If-Match` header and ETag.

### Input parameters

#### tailnet (required in URL path)
Supply the tailnet in the path.

#### `If-Match` (optional in request header)
This is a safety mechanism to avoid overwriting other users' updates to the tailnet policy file.

- Set the `If-Match` value to that of the ETag header returned in a `GET` request to `/api/v2/tailnet/{tailnet}/acl`.
  Tailscale compares the ETag value in your request to that of the current tailnet file and only replaces the file if there's a match.
  (A mismatch indicates that another update has been made to the file.)
  For example: `-H "If-Match: \"e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c\""`
- Alternately, set the `If-Match` value to `ts-default` to ensure that the policy file is replaced
  _only if the current policy file is still the untouched default_ created automatically for each tailnet.
  For example: `-H "If-Match: \"ts-default\""`

#### `Accept` (optional in request header)
Sets the return type of the updated tailnet policy file.
Response is parsed `JSON` if `application/json` is explicitly named, otherwise HuJSON will be returned.

#### Tailnet policy file entries (required in `POST` body)

Define the policy file in the `POST` body.
Include the entire policy file.
Note that the supplied object fully replaces your existing tailnet policy file.

The `POST` body should be a JSON- or [HuJSON](https://github.com/tailscale/hujson#readme)-formatted JSON object.
Learn about the [ACL policy properties you can include in the request](https://tailscale.com/kb/1018/acls/#tailscale-policy-syntax).

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
When given a user or IP port to match against, returns the tailnet policy rules that
apply to that resource without saving the policy file to the server.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### `type` (required in query string)

Specify for which type of resource (user or IP port) matching rules are to be fetched.
Supply this parameter in the query string as shown in the request example below.
Read about [previewing changes in the admin console](https://tailscale.com/kb/1018/acls/#previewing-changes).

- **`user`:** Specify 'user' if the `previewFor` value is a user's email.
  Note that `user` remains in the API for compatibility purposes, but has been replaced by "source" (`src`) in Tailscale.
- **`ipport`:** Specify 'ipport' if the `previewFor` value is an IP address and port.
  Note that `ipport` remains in the API for compatibility purposes, but has been replaced by "destination" (`dst`) in Tailscale.

#### `previewFor` (required in query string)

Supply this parameter in the query string as shown in the request example below.

- If `type`='user', supply the email of a valid user with registered machines.
- If `type`='ipport', supply an IP address + port in this format: "10.0.0.1:80".

The supplied policy file is queried with this parameter to determine which rules match.

#### Tailnet policy file (required in `POST` body)

Supply the tailnet policy file in the `POST` body in JSON or HuJSON format.
Learn about [tailnet policy file entries](https://tailscale.com/kb/1018).

### Request example

``` sh
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

A successful response returns an HTTP status of '200' and a list of rules that apply to the resource supplied as a list of matches as JSON objects.
Each match object includes:
- `users` as an array of strings indicating source entities affected by the rule
- `ports` as an array of strings representing destinations that can be accessed
- `lineNumber` as an integer indicating the rule's location in the policy file

The response also echoes the `type` and `previewFor` values supplied in the request.

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

- **Run ACL tests:** When the **request body contains ACL tests as a JSON array**,
  Tailscale runs ACL tests against the tailnet's current policy file.
  Learn more about [ACL tests](https://tailscale.com/kb/1018/acls/#tests).
- **Validate a new policy file:** When the **request body is a JSON object**,
  Tailscale interprets the body as a hypothetical new tailnet policy file with new ACLs, including any new rules and tests.
  It validates that the policy file is parsable and runs tests to validate the existing rules.

In either case, this endpoint does not modify the tailnet policy file in any way.

### Input parameters for "Run ACL tests" mode

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### ACL tests (required in `POST` body)

The `POST` body should be a JSON formatted array of ACL Tests.
Learn more about [tailnet policy file tests](https://tailscale.com/kb/1018/acls/#tests).

### Request example to run ACL tests

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate' \
  -u "tskey-yourapikey123:" \
  --data-binary '
  [
    {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]}
  ]'
```

### Input parameters for "Validate a new policy file" mode

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### Entire tailnet policy file (required in `POST` body)

The `POST` body should be a JSON object with a JSON or HuJSON representation of a tailnet policy file.

### Request example to validate a policy file

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

The HTTP status code will be '200' if the request was well formed and there were no server errors, even in the case of failing tests or an invalid ACL.
Look at the response body to determine whether there was a problem within your ACL or tests:
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
Refer to the Device resource description [above](#device-object).
This endpoint addresses the devices registered to a tailnet.

Endpoints:

- List devices: [`GET /api/v2/tailnet/{tailnet}/devices`](#fetch-a-list-of-tailnet-devices)

## Fetch a list of tailnet devices

``` http
GET /api/v2/tailnet/{tailnet}/devices
```

Lists the devices in a tailnet.
Supply the tailnet of interest in the path.
Optionally use the `fields` query parameter to explicitly indicate which fields are returned.

This call is also useful for retrieving a device's `deviceID` (returned as `"id"`).
A device ID is used in API requests where you must supply an ID in order to, for example, [fetch device details](#fetch-the-details-for-a-device) or [authorize a device](#authorize-a-device).

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### `fields` (optional in query string)

Controls whether the response returns **all** fields or only a predefined subset of fields.
Currently, there are two supported options:
- **`all`:** return all fields in the response
- **`default`:** return all fields **except**:
  * `enabledRoutes`
  * `advertisedRoutes`
  * `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

Supply this parameter in the query string as shown in the examples below.
Use commas to separate multiple options.
If more than one option is indicated, then `all` is used.
For example, for `fields=default,all`, all fields are returned.

If the `fields` parameter is not supplied, then the default (limited fields) option is used.

### Request example for default set of fields

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/devices' \
  -u "tskey-yourapikey123:"
```

### Request example for all fields

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/devices?fields=all' \
  -u "tskey-yourapikey123:"
```

### Response
If successful, Tailscale returns an HTTP code of '200' and a JSON list of the tailnet devices and their details.
If the request was for `all` fields, the response includes all fields (refer to the [Device object attributes](#attributes) section for descriptions and examples);
if the request was for the `default` set of fields, the response excludes `enabledRoutes`, `advertisedRoutes`, and `clientConnectivity`.

## Tailnet key object

This endpoint operates primarily on auth keys, and in some cases on [API access tokens](#api-access-token).

- Auth keys: Pre-authentication keys ("auth keys” for short) let you register new nodes without needing to sign in via a web browser.
  Auth keys are identifiable by the prefix `tskey-auth...`.
  Use them to add devices to your tailnet.
  Auth keys are used for _initial registration_ of a new device to your tailnet (after a device has joined the tailnet, there are additional keys used for subsequent authentication; these include the node key and the machine key).

  Generate or revoke an auth key in the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console.
  When you generate a new auth key, you can specify that the key should automatically authorize devices for which the auth key is used.
  When generating the auth key, you can choose the number of days (1 - 90 inclusive) for the automatic key expiry.
  To continue using an auth key after this key expires, you must generate a new key.

- API access tokens: Discussed [above](#api-access-token).

Recently expired and revoked keys are shown on the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console.
Learn more about [auth keys](https://tailscale.com/kb/1085/).

If you authenticate with a user-owned API access token, all the methods on tailnet keys operate on _keys owned by that user_.
If you authenticate with an access token derived from an OAuth client, then these methods operate on _keys owned by the tailnet_.
Learn more about [OAuth clients](https://tailscale.com/kb/1215).

The `POST /api/v2/tailnet/{tailnet}/keys` endpoint is used to create auth keys only.
The remaining three endpoints operate on auth keys and API access tokens.

Endpoints:

  - Get tailnet keys: [`GET /api/v2/tailnet/{tailnet}/keys`](#fetch-the-keys-for-a-tailnet)
  - Create a key: [`POST /api/v2/tailnet/{tailnet}/keys`](#create-a-new-key-for-a-tailnet)
  - Get key details: [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](#fetch-information-for-a-specific-tailnet-key)
  - Delete a key: [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](#delete-a-specific-tailnet-key)

### Attributes

``` jsonc
{
  // capabilities (JSON object) is a mapping of resources to permissible
  // actions.
  "capabilities": {

    // devices (JSON object) specifies the key's permissions over devices
    "devices": {

      // create (JSON object) specifies the key's permissions when
      // creating devices
      "create": {

        // reusable (boolean) for auth keys only; reusable auth keys
        // can be used to connect multiple nodes.
        // Learn more about reusable auth keys here:
        // https://tailscale.com/kb/1085/auth-keys/#types-of-auth-keys
        "reusable": false,

        // ephemeral (boolean) for auth keys only; ephemeral keys are
        // used to connect and then clean up short-lived devices.
        // Learn about ephemeral nodes here:
        // https://tailscale.com/kb/1111
        "ephemeral": false,

        // preauthorized (boolean) for auth keys only; these are also
        // referred to as "pre-approved" keys. 'true' means that Tailscale
        // network administrators have already reviewed and approved new
        // devices. Learn about device approval here:
        // https://tailscale.com/kb/1099
        "preauthorized": false,

        // tags (string) are the tags specified for the key; tags are
        // described in the "Update device tags" section above.
        // Learn about tags here: https://tailscale.com/kb/1068
        "tags": [
          "tag:example"
            ]
          }
        }
  }

  // expirySeconds (int) is the duration in seconds of the key's validity
  "expirySeconds": 86400
}
```

## Fetch the keys for a tailnet
``` http
GET /api/v2/tailnet/{tailnet}/keys
```

Returns a list of active auth keys and API access tokens for the tailnet supplied in the URL path, depending on permissions assigned to the caller:
- If the API call is made  with a user-owned API access token, Tailscale returns only the keys owned by the caller.
- If the API call is made with an access token derived from an OAuth client, Tailscale returns all keys owned by the tailnet that the caller's permissions allow.

Returns a JSON object with the IDs of all active keys.
In the future, this method may return more information about each key than just the ID.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys' \
  -u "tskey-yourapikey123:"
```

### Response

``` jsonc
{"keys": [
	{"id": "XXXX14CNTRL"},
	{"id": "XXXXZ3CNTRL"},
	{"id": "XXXX43CNTRL"},
	{"id": "XXXXgj1CNTRL"}
]}
```

## Create a new key for a tailnet

``` http
POST /api/v2/tailnet/{tailnet}/keys
```

Creates a new auth key in a tailnet supplied in the URL path.
The key will be associated with the user who owns the API access token used to make this call,
or, if the call is made with an access token derived from an OAuth client, the key will be owned by the tailnet.
Supply the tailnet in the path.

Returns a JSON object with the supplied capabilities in addition to the generated key.
The key should be recorded and kept safe and secure because it wields the capabilities specified in the request.
The identity of the key is embedded in the key itself and can be used to perform operations on the key (e.g., revoking it or retrieving information about it).
The full key can no longer be retrieved by the server.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### Tailnet key object (required in `POST` body)

Supply the tailnet key attributes as a JSON object in the `POST` body following the request example below.

At minimum, the request `POST` body must have a `capabilities` object (see below).
With nothing else supplied, such a request generates a single-use key with no tags.

Note the following about required vs. optional values:

- **`capabilities`:** A `capabilities` object is required and must contain `devices`.

- **`devices`:** A `devices` nested object is required within `capabilities`, but can be an empty JSON object.

- **`tags`:** Whether tags are required or optional depends on the owner of the auth key:
  - When creating an auth key _owned by the tailnet_, it must have tags.
    The auth tags specified for that new auth key must exactly match the tags that are on the OAuth client used to create that auth key (or they must be tags that are owned by the tags that are on the OAuth client used to create the auth key).
  - When creating an auth key _owned by a user_ (using an API access token), tags are optional.

- **`expirySeconds`:** Optional in `POST` body. Defaults to 90d if not supplied.

### Request example

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

The response is a JSON object that includes the `"key"` value, which will only be returned once.
Record and safely store the `"key"` returned.
It holds the capabilities specified in the request and can no longer be retrieved by the server.

``` jsonc
{
	"id":           "XXXX456CNTRL",
	"key":          "tskey-k123456CNTRL-abcdefghijklmnopqrstuvwxyz",
	"created":      "2021-12-09T23:22:39Z",
	"expires":      "2022-03-09T23:22:39Z",
  "revoked":      "2022-03-12T23:22:39Z",
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
}
```

## Fetch information for a specific tailnet key

``` http
GET /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Supply the tailnet and key ID of interest in the path.
The key ID can be found in the [admin console](https://login.tailscale.com/admin/settings/keys).

Returns a JSON object with information about specific key, such as its creation and expiration dates and its capabilities.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### `keyId` (required in URL path)
Supply the key ID in the path.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-yourapikey123:"
```

### Response

The response is a JSON object with information about the key supplied.

``` jsonc
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
        "tags": [
          "tag:bar",
          "tag:foo"
        ]
      }
    }
  }
}
```

## Delete a specific tailnet key

``` http
DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Deletes a specific key. Supply the tailnet and key ID of interest in the path.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### `keyId` (required in URL path)
Supply the key ID in the path. The key ID can be found in the [admin console](https://login.tailscale.com/admin/settings/keys).

### Request example

``` sh
curl -X DELETE 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-yourapikey123:"
```

### Response

Tailscale returns status 200 upon success.

## DNS

The tailnet DNS endpoints are provided for fetching and modifying various DNS settings for a tailnet.
These include nameservers, DNS preferences, and search paths.
Learn more about [nameservers](https://tailscale.com/kb/1054/).

Endpoints:

- **Nameservers**
  - Get nameservers: [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](#fetch-the-global-dns-nameservers-for-a-tailnet)
  - Set nameservers: [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](#replace-the-list-of-global-dns-nameservers-for-a-tailnet)
- **Preferences**
  - Get DNS preferences: [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](#fetch-the-dns-preferences-for-a-tailnet)
  - Set DNS preferences: [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](#replace-the-dns-preferences-for-a-tailnet)
- **Search paths**
  - Get search paths: [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths](#fetch-the-search-paths-for-a-tailnet)
  - Set search paths: [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](#replace-the-search-paths-for-a-tailnet)

## Fetch the global DNS nameservers for a tailnet

``` http
GET /api/v2/tailnet/{tailnet}/dns/nameservers
```

Lists the global DNS nameservers for a tailnet.
Supply the tailnet of interest in the path.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:"
```

### Response

``` jsonc
{
  "dns": ["8.8.8.8"],
}
```

## Replace the list of global DNS nameservers for a tailnet

``` http
POST /api/v2/tailnet/{tailnet}/dns/nameservers
```

Replaces the list of DNS nameservers for the given tailnet with the list supplied in the request.
Supply the tailnet of interest in the path.
Note that changing the list of DNS nameservers may also affect the status of MagicDNS (if MagicDNS is on; learn about [MagicDNS](https://tailscale.com/kb/1081).
If all nameservers have been removed, MagicDNS will be automatically disabled (until explicitly turned back on by the user).

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### `dns` (required in `POST` body)

The new list of DNS nameservers in JSON.

``` jsonc
{
  "dns":["8.8.8.8"]
}
```

### Request example: adding DNS nameservers with MagicDNS on

Adding DNS nameservers with the MagicDNS on:

``` sh
curl -X POST 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers' \
  -u "tskey-yourapikey123:" \
  --data-binary '{"dns": ["8.8.8.8"]}'
```

### Response example: adding DNS nameservers, MagicDNS on

The response is a JSON object containing the new list of nameservers and the status of MagicDNS.

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

The response is a JSON object containing the new list of nameservers and the status of MagicDNS.

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

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences' \
  -u "tskey-yourapikey123:"
```

### Response

``` jsonc
{
  "magicDNS":false,
}
```

## Replace the DNS preferences for a tailnet

``` http
POST /api/v2/tailnet/{tailnet}/dns/preferences
```

Replaces the DNS preferences for a tailnet; specifically, the MagicDNS setting.
Note that MagicDNS is dependent on DNS servers.
Learn about [MagicDNS](https://tailscale.com/kb/1081).

If there is at least one DNS server, then MagicDNS can be enabled.
Otherwise, it returns an error.

Note that removing all nameservers will turn off MagicDNS.
To reenable it, nameservers must be added back, and MagicDNS must be explicitly turned on.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

#### DNS preference (required in `POST` body)

The DNS preferences in JSON. Currently, MagicDNS is the only setting available:

- **`magicDNS`:** Automatically registers DNS names for devices in your tailnet.

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

### Response

If there are no DNS servers, Tailscale returns an error message:

``` jsonc
{
  "message":"need at least one nameserver to enable MagicDNS"
}
```

If there are DNS servers, Tailscale returns the MagicDNS status:

``` jsonc
{
  "magicDNS":true,
}
```

## Fetch the search paths for a tailnet

``` http
GET /api/v2/tailnet/{tailnet}/dns/searchpaths
```

Retrieves the list of search paths, also referred to as _search domains_, that is currently set for the given tailnet.
Supply the tailnet of interest in the path.

### Input parameters

#### `tailnet` (required in URL path)
Supply the tailnet in the path.

### Request example

``` sh
curl 'https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths' \
  -u "tskey-yourapikey123:"
```

### Response

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

#### `tailnet` (required in URL path)

Supply the tailnet in the path.

#### `searchPaths` (required in `POST` body)

Supply a list of search paths in JSON; for example:

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

### Response

The response is a JSON object containing the new list of search paths.

``` jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"],
}
```
