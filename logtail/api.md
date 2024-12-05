# Tailscale Logs Service

The Tailscale Logs Service defines a REST interface for configuring, storing,
retrieving, and processing log entries.

# Overview

HTTP requests are received at the service **base URL**
[https://log.tailscale.io](https://log.tailscale.io), and return JSON-encoded
responses using standard HTTP response codes.

Authorization for the configuration and retrieval APIs is done with a secret
API key passed as the HTTP basic auth username. Secret keys are generated via
the web UI at base URL. An example of using basic auth with curl:

    curl -u <log_api_key>: https://log.tailscale.io/collections

In the future, an HTTP header will allow using MessagePack instead of JSON.

## Collections

Logs are organized into collections. Inside each collection is any number of
instances.

A collection is a domain name. It is a grouping of related logs. As a
guideline, create one collection per product using subdomains of your
company's domain name. Collections must be registered with the logs service
before any attempt is made to store logs.

## Instances

Each collection is a set of instances. There is one instance per machine
writing logs.

An instance has a name and a number. An instance has a **private** and
**public** ID. The private ID is a 32-byte random number encoded as hex.
The public ID is the SHA-256 hash of the private ID, encoded as hex.

The private ID is used to write logs. The only copy of the private ID
should be on the machine sending logs. Ideally it is generated on the
machine. Logs can be written as soon as a private ID is generated. 

The public ID is used to read and adopt logs. It is designed to be sent
to a service that also holds a logs service API key.

The tailscale logs service will store any logs for a short period of time.
To enable logs retention, the log can be **adopted** using the public ID
and a logs service API key.
Once this is done, logs will be retained long-term (for the configured
retention period).

Unadopted instance logs are stored temporarily to help with debugging:
a misconfigured machine writing logs with a bad ID can be spotted by
reading the logs.
If a public ID is not adopted, storage is tightly capped and logs are
deleted after 12 hours.

# APIs

## Storage

### `POST /c/<collection-name>/<private-ID>` — send a log

The body of the request is JSON.

A **single message** is an object with properties:

`{ }`

The client may send any properties it wants in the JSON message, except
for the `logtail` property which has special meaning. Inside the logtail
object the client may only set the following properties:

- `client_time` in the format of RFC3339: "2006-01-02T15:04:05.999999999Z07:00"

A future version of the logs service API will also support:

- `client_time_offset` a integer of nanoseconds since the client was reset
- `client_time_reset` a boolean if set to true resets the time offset counter

On receipt by the server the `client_time_offset` is transformed into a
`client_time` based on the `server_time` when the first (or
client_time_reset) event was received. 

If any other properties are set in the logtail object they are moved into
the "error" field, the message is saved and a 4xx status code is returned.

A **batch of messages** is a JSON array filled with single message objects:

`[ { }, { }, ... ]`

If any of the array entries are not objects, the content is converted
into a message with a `"logtail": { "error": ...}` property, saved, and
a 4xx status code is returned.

Similarly any other request content not matching one of these formats is
saved in a logtail error field, and a 4xx status code is returned.

An invalid collection name returns `{"error": "invalid collection name"}`
along with a 403 status code.

Clients are encouraged to:

- POST as rapidly as possible (if not battery constrained). This minimizes
  both the time necessary to see logs in a log viewer and the chance of
  losing logs.
- Use HTTP/2 when streaming logs, as it does a much better job of
  maintaining a TLS connection to minimize overhead for subsequent posts.

A future version of logs service API will support sending requests with
`Content-Encoding: zstd`.

## Retrieval

### `GET /collections` — query the set of collections and instances

Returns a JSON object listing all of the named collections.

The caller can query-encode the following fields:

- `collection-name` — limit the results to one collection

    ```
    {
      "collections": {
        "collection1.yourcompany.com": {
          "instances": {
            "<logid.PublicID>" :{
              "first-seen": "timestamp",
              "size": 4096
            },
            "<logid.PublicID>" :{
              "first-seen": "timestamp",
              "size": 512000,
              "orphan": true,
            }
          }
        }
      }
    }
    ```

### `GET /c/<collection_name>` — query stored logs

The caller can query-encode the following fields:

- `instances` — zero or more log collection instances to limit results to
- `time-start` — the earliest log to include
- One of:
    - `time-end` — the latest log to include
    - `max-count` — maximum number of logs to return, allows paging
    - `stream` — boolean that keeps the response dangling, streaming in
      logs like `tail -f`. Incompatible with logtail-time-end.

In **stream=false** mode, the response is a single JSON object:

    {
    	// TODO: header fields
    	"logs": [ {}, {}, ... ]
    }

In **stream=true** mode, the response begins with a JSON header object
similar to the storage format, and then is a sequence of JSON log
objects, `{...}`, one per line. The server continues to send these until
the client closes the connection.

## Configuration

For organizations with a small number of instances writing logs, the
Configuration API are best used by a trusted human operator, usually
through a GUI. Organizations with many instances will need to automate
the creation of tokens.

### `POST /collections` — create or delete a collection

The caller must set the `collection` property and `action=create` or
`action=delete`, either form encoded or JSON encoded. Its character set
is restricted to the mundane: [a-zA-Z0-9-_.]+

Collection names are a global space. Typically they are a domain name.

### `POST /instances` — adopt an instance into a collection

The caller must send the following properties, form encoded or JSON encoded:

- `collection` — a valid FQDN ([a-zA-Z0-9-_.]+)
- `instances` an instance public ID encoded as hex

The collection name must be claimed by a group the caller belongs to.
The pair (collection-name, instance-public-ID) may or may not already have
logs associated with it.

On failure, an error message is returned with a 4xx or 5xx status code:

`{"error": "what went wrong"}`