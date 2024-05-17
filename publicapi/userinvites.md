# User invites

A user invite is an active invitation that lets a user join a tailnet with a pre-assigned [user role](https://tailscale.com/kb/1138/user-roles).

Each user invite has a unique ID that is used to identify the invite in API calls.
You can find all user invite IDs for a particular tailnet by [listing user invites](#list-user-invites).

### Attributes

```jsonc
{
  // id (string) is the unique identifier for the invite.
  // Supply this value wherever {userInviteId} is indicated in the endpoint.
  "id": "12346",

  // role is the tailnet user role to assign to the invited user upon accepting
  // the invite. Value options are "member", "admin", "it-admin", "network-admin",
  // "billing-admin", and "auditor".
  "role": "admin",

  // tailnetId is the ID of the tailnet to which the user was invited.
  "tailnetId": 59954,

  // inviterId is the ID of the user who created the invite.
  "inviterId": 22012,

  // email is the email to which the invite was sent.
  // If empty, the invite was not emailed to anyone, but the inviteUrl can be
  // shared manually.
  "email": "user@example.com",

  // lastEmailSentAt is the last time the invite was attempted to be sent to
  // Email. Only ever set if `email` is not empty.
  "lastEmailSentAt": "2024-04-03T21:38:49.333829261Z",

  // inviteUrl is included when `email` is not part of the tailnet's domain,
  // or when `email` is empty. It is the link to accept the invite.
  //
  // When included, anyone with this link can accept the invite.
  // It is not restricted to the person to which the invite was emailed.
  //
  // When `email` is part of the tailnet's domain (has the same @domain.com
  // suffix as the tailnet), the user can join the tailnet automatically by
  // logging in with their domain email at https://login.tailscale.com/start.
  // They'll be assigned the specified `role` upon signing in for the first
  // time.
  "inviteUrl": "https://login.tailscale.com/admin/invite/<code>"
}
```

# API

**[User invites](#user-invites)**

- Get user invite: [`GET /api/v2/user-invites/{userInviteId}`](#get-user-invite)
- Delete user invite: [`DELETE /api/v2/user-invites/{userInviteId}`](#delete-user-invite)
- Resend user invite (by email): [`POST /api/v2/user-invites/{userInviteId}/resend`](#resend-user-invite)

## Get user invite

```http
GET /api/v2/user-invites/{userInviteId}
```

Retrieve the specified user invite.

### Parameters

#### `userInviteId` (required in URL path)

The ID of the user invite.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/user-invites/29214" \
  -u "tskey-api-xxxxx:"
```

### Response

```jsonc
{
  "id": "29214",
  "role": "admin",
  "tailnetId": 12345,
  "inviterId": 34567,
  "email": "user@example.com",
  "lastEmailSentAt": "2024-05-09T16:23:26.91778771Z",
  "inviteUrl": "https://login.tailscale.com/uinv/<code>"
}
```

## Delete user invite

```http
DELETE /api/v2/user-invites/{userInviteId}
```

Delete the specified user invite.

### Parameters

#### `userInviteId` (required in URL path)

The ID of the user invite.

### Request example

```sh
curl -X DELETE "https://api.tailscale.com/api/v2/user-invites/29214" \
  -u "tskey-api-xxxxx:"
```

### Response

The response is 2xx on success. The response body is an empty JSON object.

## Resend user invite

```http
POST /api/v2/user-invites/{userInviteId}/resend
```

Resend the specified user invite by email. You can only use this if the specified invite was originally created with an email specified. Refer to [creating user invites for a tailnet](#create-user-invites).

Note: Invite resends are rate limited to one per minute.

### Parameters

#### `userInviteId` (required in URL path)

The ID of the user invite.

### Request example

```sh
curl -X POST "https://api.tailscale.com/api/v2/user-invites/29214/resend" \
  -u "tskey-api-xxxxx:"
```

### Response

The response is 2xx on success. The response body is an empty JSON object.
