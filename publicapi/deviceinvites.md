# Device invites

A device invite is an invitation that shares a device with an external user (a user not in the device's tailnet).

Each device invite has a unique ID that is used to identify the invite in API calls.
You can find all device invite IDs for a particular device by [listing all device invites for a device](#list-device-invites).

### Attributes

```jsonc
{
  // id (strings) is the unique identifier for the invite.
  // Supply this value wherever {deviceInviteId} is indicated in the endpoint.
  "id": "12346",

  // created is the creation time of the invite.
  "created": "2024-04-03T21:38:49.333829261Z",

  // tailnetId is the ID of the tailnet to which the shared device belongs.
  "tailnetId": 59954,

  // deviceId is the ID of the device being shared.
  "deviceId": 11055,

  // sharerId is the ID of the user who created the share invite.
  "sharerId": 22012,

  // multiUse specifies whether this device invite can be accepted more than
  // once.
  "multiUse": false,

  // allowExitNode specifies whether the invited user is able to use the
  // device as an exit node when the device is advertising as one.
  "allowExitNode": true,

  // email is the email to which the invite was sent.
  // If empty, the invite was not emailed to anyone, but the inviteUrl can be
  // shared manually.
  "email": "user@example.com",

  // lastEmailSentAt is the last time the invite was attempted to be sent to
  // Email. Only ever set if Email is not empty.
  "lastEmailSentAt": "2024-04-03T21:38:49.333829261Z",

  // inviteUrl is the link to accept the invite.
  // Anyone with this link can accept the invite.
  // It is not restricted to the person to which the invite was emailed.
  "inviteUrl": "https://login.tailscale.com/admin/invite/<code>",

  // accepted is true when share invite has been accepted.
  "accepted": true,

  // acceptedBy is set when the invite has been accepted.
  // It holds information about the user who accepted the share invite.
  "acceptedBy": {
    // id is the ID of the user who accepted the share invite.
    "id": 33223,

    // loginName is the login name of the user who accepted the share invite.
    "loginName": "someone@example.com",

    // profilePicUrl is optionally the profile pic URL for the user who accepted
    // the share invite.
    "profilePicUrl": ""
  }
}
```

# API

**[Device invites](#device-invites)**

- Get device invite: [`GET /api/v2/device-invites/{deviceInviteId}`](#get-device-invite)
- Delete device invite: [`DELETE /api/v2/device-invites/{deviceInviteId}`](#delete-device-invite)
- Resend device invite (by email): [`POST /api/v2/device-invites/{deviceInviteId}/resend`](#resend-device-invite)
- Accept device invite [`POST /api/v2/device-invites/-/accept`](#accept-device-invite)

## Get device invite

```http
GET /api/v2/device-invites/{deviceInviteId}
```

Retrieve the specified device invite.

### Parameters

#### `deviceInviteId` (required in URL path)

The ID of the device share invite.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device-invites/12346" \
  -u "tskey-api-xxxxx:"
```

### Response

```jsonc
{
  "id": "12346",
  "created": "2024-04-03T21:38:49.333829261Z",
  "tailnetId": 59954,
  "deviceId": 11055,
  "sharerId": 22012,
  "multiUse": true,
  "allowExitNode": true,
  "email": "user@example.com",
  "lastEmailSentAt": "2024-04-03T21:38:49.333829261Z",
  "inviteUrl": "https://login.tailscale.com/admin/invite/<code>",
  "accepted": false
}
```

## Delete device invite

```http
DELETE /api/v2/device-invites/{deviceInviteId}
```

Delete the specified device invite.

### Parameters

#### `deviceInviteId` (required in URL path)

The ID of the device share invite.

### Request example

```sh
curl -X DELETE "https://api.tailscale.com/api/v2/device-invites/12346" \
  -u "tskey-api-xxxxx:"
```

### Response

The response is 2xx on success. The response body is an empty JSON object.

## Resend device invite

```http
POST /api/v2/device-invites/{deviceInviteId}/resend
```

Resend the specified device invite by email. You can only use this if the specified invite was originally created with an email specified. Refer to [creating device invites for a device](#create-device-invites).

Note: Invite resends are rate limited to one per minute.

### Parameters

#### `deviceInviteId` (required in URL path)

The ID of the device share invite.

### Request example

```sh
curl -X POST "https://api.tailscale.com/api/v2/device-invites/12346/resend" \
  -u "tskey-api-xxxxx:"
```

### Response

The response is 2xx on success. The response body is an empty JSON object.

## Accept device invite

```http
POST /api/v2/device-invites/-/accept
```

Resend the specified device invite by email. This can only be used if the specified invite was originally created with an email specified.
See [creating device invites for a device](#create-device-invites).

Note that invite resends are rate limited to once per minute.

### Parameters

#### `invite` (required in `POST` body)

The URL of the invite (in the form "https://login.tailscale.com/admin/invite/{code}") or the "{code}" component of the URL.

### Request example

```sh
curl -X POST "https://api.tailscale.com/api/v2/device-invites/-/accept" \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json" \
  --data-binary '[{"invite": "https://login.tailscale.com/admin/invite/xxxxxx"}]'
```

### Response

```jsonc
{
  "device": {
    "id": "11055",
    "os": "iOS",
    "name": "my-phone",
    "fqdn": "my-phone.something.ts.net",
    "ipv4": "100.x.y.z",
    "ipv6": "fd7a:115c:x::y:z",
    "includeExitNode": false
  },
  "sharer": {
    "id": "22012",
    "displayName": "Some User",
    "loginName": "someuser@example.com",
    "profilePicURL": ""
  },
  "acceptedBy": {
    "id": "33233",
    "displayName": "Another User",
    "loginName": "anotheruser@exmaple2.com",
    "profilePicURL": ""
  }
}
```
