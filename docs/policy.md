# Policy reference

A policy is JSON. Unknown members are refused everywhere, including next to a tag:
`{"from": "fixed", "method": "GET", "path": "/x", "junk": 1}`, `{"do": "open", "junk": 1}`
and `{"kind": "body", "junk": 1}` are errors, not the plain forms. A device signs it with
`DeviceKey::sign_policy`, which also checks every rule below; an error names the place and
the rule, for example `policy invalid at operations[0].steps[1].inject[2]: header must be a
token, not reserved, and set once`. `Policy::summary()` prints a policy as one line per
field, caller, operation and step, for the owner to read before signing; a line that starts
with `!` marks something that widens what the caller may do; `summarize` gives the same in
structured form with risk flags ([Summaries and risk flags](#summaries-and-risk-flags)).
The JSON Schema of the format is `crates/engine/policy.schema.json`
([JSON Schema](#json-schema)).

```text
Policy
├── item:       ItemBinding          optional: a kind of item (see Typed items)
├── fields:     [FieldSpec]          1–32 (a secret may hold a session: expiry and renewal)
├── callers:    [Caller]             1–32
└── operations: [Operation]          1–16
    ├── name
    ├── input:  raw | json | rlp     (operations with no connection)
    ├── payment: amount, currency    optional: checked against the owner's spending limits
    ├── approval: true               optional: every use waits for the owner's approval
    ├── vend: lifetime_ms, expires   optional: hands back a credential minted from the secret, bounded
    └── steps:  [Step]               1–64
        ├── open     connection: https | tls | websocket | udp | browser, destinations, identity
        ├── send     https: request (caller contract | fixed) + inject;  tls: template;  browser: fill
        ├── receive  https: the response of the send;  tls: until a delimiter;  + capture
        ├── compute  into a name, from a template
        ├── run      site code or a reviewed library in the sandbox; output only to its origin
        ├── await    a challenge: a code from the owner's device, or a site the node polls
        ├── return   https: response projection;  tls: relay;  browser: nothing;  none: template
        ├── repeat   (syntax only, refused)
        └── if       (syntax only, refused)
```

Names (fields, callers, operations, temporaries, computed values, path parameters) are
tokens: 1 to 64 of `A–Z a–z 0–9 - _`.

This format replaces the operations of kind `http`, `stream` and `derive`. A policy of the
old format is converted with `credentials policy upgrade old.json --out new.json` (or
`engine::policy::legacy::upgrade_json`): see [Converting a policy](#converting-a-policy).
A converted policy is a new policy and **must be signed again**; the signing domain changed
too (`policy/v4`), so no old signature verifies.

## Fields

```json
{"name": "password", "secret": true, "optional": false, "guessable": true}
```

| Member | Meaning |
| --- | --- |
| `name` | Token, unique in the policy. |
| `secret` | A secret is tracked by the template analysis and searched for in responses. A public value (a user name, a client id) is not. |
| `optional` | The record may lack it: a value an operation fills in later, such as an access token. |
| `guessable` | Secret only. A value with few possibilities (PIN, password a person chose). A derivation may depend on it only through `len`: a hash, MAC, signature or encryption of it lets a guess be checked. |
| `session` | Secret only. The field holds a session the node obtains (a cookie, a bearer token): how long it lasts, where its expiry goes and how it is renewed. See [Sessions](#sessions). |

A record holds at most 32 fields and 16 MiB in all.

## Callers

```json
{"name": "billing-agent", "key": "<CallerPublicKey, base64url>",
 "operations": ["refresh", "call"], "limit": {"count": 100, "window_ms": 60000}}
```

Each call carries an `Authorization` that `CallerKey::authorize` makes: an Ed25519 signature
over the node key, the owner, record id and generation, the operation, the SHA-256 of the
request (or stream exchanges, or input), the time and a random 16-byte nonce. A node accepts
it within ±5 minutes of its clock, once. `limit` (optional) allows `count` calls (1 to
1,000,000) per `window_ms` for this caller on this record. The caller name is written to each
log entry.

## Operations

An operation is a name, an optional input schema and 1 to 64 steps over at most one
connection:

```json
{"name": "call",
 "steps": [
   {"do": "open", "connection": "https",
    "destinations": [{"host": "*.api.example.com", "port": 443}],
    "identity": {"cert": "{{cert}}", "key": "{{key}}"}},
   {"do": "send",
    "request": {"from": "caller", "methods": ["GET", "POST"],
                "paths": ["/v1/repos/{repo}/issues", "/v1/repos/{repo}"],
                "headers": ["Accept", "Content-Type"],
                "query": [{"name": "page", "min": "1", "max": "100"},
                          {"name": "state", "one_of": ["open", "closed"]}]},
    "inject": [{"target": {"kind": "header", "name": "Authorization"},
                "template": "Bearer {{access_token}}"},
               {"target": {"kind": "path_param", "name": "repo"}, "template": "{{repo_id}}"}]},
   {"do": "return", "response": {"headers": ["ETag"],
                                 "body": {"json": ["/total", "/items/*/id", "/items/*/title"]}}}
 ]}
```

The kind of connection decides what `send`, `receive` and `return` mean:

| Connection | `send` | `receive` | `return` | What the caller sends |
| --- | --- | --- | --- | --- |
| `https` | One request on its own TLS connection (HTTP/2 or HTTP/1.1, chosen by ALPN; see [HTTP versions and gRPC](#http-versions-and-grpc)): `request` and `inject`. | Reads the response of the `send` just before it, for its captures. | `response`: the projection of the last response, which may be streamed. | A request within the contract of each `send` that takes it. |
| `tls` | Writes a rendered `template`. | Reads up to and including the first of `until` (1 to 8 delimiters of 1 to 256 bytes). | `relay`: which of the caller's exchanges run after the steps. | Exchanges, each matched against `relay`. |
| `websocket` | The first is the handshake (an HTTPS `send` with a GET); each later one writes a message: `frame` and `template`. | After the handshake, reads its answer's headers; later, the next message. | `relay`: which of the caller's frames go to the server, and whether the server's go back. | Signed frames, each matched against `relay.frames`. |
| `browser` | The first is the handshake with the CDP endpoint (as for a WebSocket); each later one is a `fill` the node runs itself. | — (refused) | Nothing: the outcome and the page's final origin go back. | At most the handshake request, within its contract; no CDP command. |
| none (no `open`) | — | — | `template`: the output. | Its `input`, checked by the `input` schema. |

Rules for every operation:

- `open`, when present, is the first step; an operation opens one connection. Without it the
  operation has no connection and only `compute` and `return` are allowed.
- `return` is the last step, and every operation ends with one.
- On HTTPS, a `receive` follows the `send` whose response it reads; at most 8 sends.
- `compute` may appear anywhere after `open`.
- `run` needs an HTTPS connection and may appear anywhere after `open`.
- `await` may appear in an HTTPS operation or one with no connection, at most 4 times; not
  on TLS or a WebSocket, whose connection would stay open while it waits.
- `run` and `await` are refused on a WebSocket and a browser; `receive` on a browser.
- `repeat` and `if` are refused for now (see [Loops and branches](#loops-and-branches)).

Protocol connections (SSH, PostgreSQL, SMTP, IMAP, Redis) fit the same steps: each kind says
what its `send`, `receive` and `return` carry, and the template analysis stays the same (see
[Protocol connections](#protocol-connections)). Other kinds (MySQL, MQTT, AMQP) are not implemented yet; a browser over CDP is
[Browser fills](#browser-fills).

### `open`

| Member | Meaning |
| --- | --- |
| `connection` | `https`, `tls`, `websocket` (always `wss`), or a [protocol connection](#protocol-connections): `ssh`, `postgres`, `smtp`, `imap`, `redis`; `udp` (see [UDP](#udp)); or `browser` (a CDP endpoint over `wss`; see [Browser fills](#browser-fills)). |
| `destinations` | 1–32 hosts and ports. `*.example.com` matches exactly one label (`eu.example.com`, not `example.com` or `a.b.example.com`); `*.` must be followed by at least two labels, so `*.com` is refused. Hosts are lowercase labels of `a–z 0–9 -` (at most 253 bytes), and the port is not 0. The caller's request or stream names one of them. |
| `identity` | Optional client certificate for mutual TLS: two templates, handed to the transport only. |
| `protocol` | HTTPS only, optional: `h2` or `http1` pins the HTTP version. Without it the node offers both by ALPN and takes what the server picks. A pinned version the server does not agree to fails the call before the request is written (no downgrade). |
| `limits` | For a WebSocket, a browser or an operation whose response is streamed, optional: `idle_ms` (default 30 s, at most 120 s), `duration_ms` (default 10 min, at most 1 h) and `bytes` (both ways together; default 64 MiB, at most 1 GiB). On a browser the defaults are 10 s, 60 s and 16 MiB, and the duration is at most 5 minutes. Reaching one ends the connection. |

### `send` on HTTPS

`request` is `{"from": "caller", ...}`, the caller's request within a contract, or
`{"from": "fixed", "method": "POST", "path": "/oauth/token", "destination": {...}}`, a
request the policy fixes. A fixed request needs a `destination` unless the connection has
exactly one concrete destination; its path is checked like a caller's (strict) and a
placeholder in it is a whole segment.

#### The caller contract

| Member | Meaning |
| --- | --- |
| `methods` | Methods the caller may use (required): `GET HEAD POST PUT PATCH DELETE OPTIONS PROPFIND REPORT MKCOL COPY MOVE`. |
| `paths` | 1–32 path **templates** the caller's path (without its query) must match exactly. |
| `headers` | Headers the caller may set (none by default), each a token. A header an injection sets cannot also be a caller header. |
| `query` | Query parameters the caller may send (none by default), at most 32. |
| `encoded_percent` | `true` allows `%25` in the caller's path. Off by default (strict). |
| `override_params` | `true` allows the method-override parameter names in the query and the body. Off by default. |

A path template is segments separated by `/`:

| Segment | Matches |
| --- | --- |
| a literal (`repos`, `{repo}`) | exactly that text. A `{name}` segment is a placeholder: it must be a path parameter the `send` injects, and the caller writes `{name}` there for the node to fill. |
| `*` | one non-empty segment that holds no `{` or `}`. |
| `**` (last segment only) | one or more remaining segments that hold no `{` or `}`. |

`/v1/**` matches `/v1/` and `/v1/a/b`, not `/v1` or `/v10/a`; list `/v1` too when the bare
path is allowed. Every template of a `send` holds each of its path parameters exactly once,
as a whole segment. A placeholder anywhere else (inside a segment, in the query) is refused,
in the policy and in the caller's request: the node fills `{name}` only where the owner put
it.

A query rule:

```json
{"name": "page", "required": false, "equals": "1", "one_of": ["1", "2"],
 "pattern": "[0-9]{1,3}", "min": "1", "max": "100"}
```

`name` is the name as the server reads it (percent-decoded; visible ASCII without
`& = # + %`). Without `equals`, `one_of`, `pattern`, `min` or `max` any value is allowed, and
the summary flags it. `pattern` is a regular expression the whole decoded value must match
(the `regex` crate: linear time, at most 256 bytes). `min` and `max` are decimal integers of
up to 80 digits; the value must then be one too. A value checked by a rule may not hold `+`
(servers disagree whether it is a space): write `%20` or `%2B`. `required` makes the
parameter mandatory.

The node checks the caller's request before it writes a log entry or opens a connection:

1. the destination is one of `open`, the method one of `methods`;
2. the path: it starts with `/`, is visible ASCII, holds no `#` and no `\`; holds no `%2f`,
   `%5c` or `%2e`; holds no `%25` unless `encoded_percent`; and no segment reads as `.` or
   `..`, or holds a separator, as sent, with its `;` parameters stripped, after one decoding
   and after a second decoding (also with `;` parameters stripped);
3. placeholders: only whole segments that are path parameters of the `send`, each once, none
   in the query;
4. the pathname matches one of `paths`;
5. the query: every parameter is listed, appears once, is not a name the `send` injects (case
   and percent-encoding do not matter), is not a method-override name unless
   `override_params`, and has an allowed value; every `required` one is present;
6. the body: at most 8 MiB, and unless `override_params` it names no method-override
   parameter as a form field (decoded), a top-level JSON member or a multipart part;
7. the headers: listed, each once, values of visible ASCII and tabs.

The method-override names are `_method`, `__method`, `_httpmethod`,
`x-http-method-override`, `x-http-method` and `x-method-override` (any case). Nobody can set
`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`, `Trailer`,
`Expect`, `Accept-Encoding`, `Range`, `If-Range`, `Keep-Alive` or the method-override
headers; the engine sends `Accept-Encoding: identity` and `Connection: close`.

#### Injections

| `target` | Effect |
| --- | --- |
| `{"kind": "header", "name": "Authorization"}` | Sets a header (once). |
| `{"kind": "query", "name": "signature"}` | Appends a query parameter (the value is percent-encoded). The name must be a token, and the caller may not send it. |
| `{"kind": "path_param", "name": "token"}` | Replaces the `{token}` segment of the path. |
| `{"kind": "body"}` | Sets the body (at most one per send). |

### `send` on TLS

`{"do": "send", "template": "a1 LOGIN {{user}} {{password}}\r\n"}` writes the rendered
template.

### UDP

`"connection": "udp"` is for request and response protocols over datagrams that protect
their own messages with a MAC (RADIUS with Message-Authenticator, DNS with TSIG, STUN with
MESSAGE-INTEGRITY): each `send` writes its rendered template as one datagram, each `receive`
reads one datagram (`until` is empty) and captures from it, as on a TLS stream. The
destination is fixed by the policy like any other; the node connects its socket to the
address it resolved, so datagrams from any other address are dropped.

There is no TLS: what a datagram carries is readable on the path, and in an enclave by the
host that relays it. So:

- a `send` template on `udp` must not be tainted: a secret may go only through a one-way
  function (`hmac_md5(secret, message)`, `hmac_sha256`, a signature), never as itself or
  encrypted under a key some operation may use elsewhere, and a `guessable` field not at all
  (a MAC of a password is a test for each guess); the policy is refused at signing
  otherwise;
- `identity`, `protocol` and `limits` are refused on `udp`;
- a receive waits at most 10 seconds in all and sends the last datagram again after 1, 2 and
  4 seconds without an answer (the retransmission of RFC 2865 and RFC 8489); a datagram
  is at most 65,507 bytes;
- the `return` takes `relay` only, like a TLS stream: each caller exchange is one datagram
  and its `until` is empty, the answer is one datagram, searched for reflected secrets like
  every read.

The summary flags each `udp` operation with `plain_datagram`. DTLS is not offered
(`docs/design.md`, section 7b).

### HTTP versions and gRPC

The engine builds every request in HTTP/1.1 form; the transport sends it over HTTP/2 when
the server picks `h2` by ALPN, and hands the answer back in HTTP/1.1 form (a chunked body, and
the HTTP/2 trailers after it). Its HTTP/2 client is synchronous and minimal: one stream per
connection, no server push, HPACK with Huffman, strict frame and field checks (a field name
must be a lowercase token, a value holds no control byte, connection-specific fields and
unknown pseudo-headers are refused, `content-length` must agree with the body).

```json
{"do": "send", "grpc": true,
 "request": {"from": "fixed", "method": "POST", "path": "/pkg.Service/Get"},
 "inject": [{"target": {"kind": "header", "name": "authorization"},
             "template": "Bearer {{access_token}}"},
            {"target": {"kind": "body"}, "template": "{{ hexdecode(message) }}"}]}
```

`grpc: true` makes the send a unary gRPC call: the body is one message, sent
length-prefixed (uncompressed) with `content-type: application/grpc` and `te: trailers`, and
the answer must be one uncompressed message, which becomes the body the projection and the
captures read. It needs `protocol: "h2"` on the `open`, a POST, and no `content-type` in the
request (the node sets it). `grpc-status` and `grpc-message` come in the trailers: project them
with `trailers` or capture them with `{"from": "trailer", "name": "grpc-status"}` (a trailer
capture falls back to the header of the same name, as a trailers-only gRPC answer carries it).

### WebSocket

```json
{"name": "live",
 "steps": [
   {"do": "open", "connection": "websocket",
    "destinations": [{"host": "stream.example.com", "port": 443}],
    "limits": {"idle_ms": 60000, "duration_ms": 1800000}},
   {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/v1/socket"}},
   {"do": "send", "frame": "text", "template": "{\"op\":\"auth\",\"token\":\"{{access_token}}\"}"},
   {"do": "receive", "capture": [{"source": {"from": "regex", "pattern": "\"session\":\"([a-z0-9]{1,64})\""},
                                  "into": {"kind": "temp", "name": "session", "secret": false}}]},
   {"do": "return", "relay": {
     "frames": [{"kind": "text",
                 "shape": {"json": {"members": [
                   {"pointer": "/op", "equals": "subscribe"},
                   {"pointer": "/channel", "type": "string", "pattern": "[a-z]{1,32}"}]}}}],
     "server": true}}
 ]}
```

- The first `send` is the handshake: an HTTPS `send` with a GET, no body and no gRPC, over
  HTTP/1.1. The node adds `Upgrade`, `Connection`, `Sec-WebSocket-Version` and a fresh
  `Sec-WebSocket-Key`; the policy and the caller cannot set those or
  `Sec-WebSocket-Extensions`. The answer must be `101` with `Upgrade: websocket`, the right
  `Sec-WebSocket-Accept`, no extension, and a subprotocol only if the request offered one.
- A later `send` writes one message: `frame` (`text` or `binary`) and a `template` (the
  first-message authentication of many APIs). A `receive` right after the handshake reads the
  headers of its answer; a later one reads the next message (`between`, `regex` or
  `all`).
- `return` takes `relay` only: `frames` (at most 16 rules; each has a `kind`, an optional
  `shape` and an optional `template`) and `server`. A caller's frame goes to the server only
  when it is signed for this call, in sequence, and matches the first rule of its kind: its
  data must hold against `shape` (an [input schema](#input-schemas): a closed JSON schema, or
  `raw` with a `pattern`); the node writes the checked data, or the rendered `template`, which
  may read it as `$input` and the fields (a template that reads `$input` needs a shape). A frame
  that matches no rule, has a bad signature or is out of sequence ends the connection. A rule
  with no shape, or a `raw` shape with no pattern, is flagged `frames_unpinned`.
- The server's messages go back to the caller only with `server: true` (flagged
  `server_frames`), after the stream search for secrets; pings are answered by the node.
- `run` and `await` are refused; at most one WebSocket is open per call.

A WebSocket and a streamed response are open connections: a caller holds at most 4 at once,
an owner 16, a node 256. The node logs one entry when one opens (the `use`) and one when it
closes, with why it closed, the status, and the messages and bytes each way.

### Browser fills

An agent drives a browser somewhere else (its own controller: click, read, navigate). When
a login form needs a secret, the agent calls the node, and the **node** types it: the agent
never sees the value, and neither does whoever carries the agent's traffic.

```json
{"name": "login",
 "steps": [
   {"do": "open", "connection": "browser",
    "destinations": [{"host": "cdp.browser.example.net", "port": 443}],
    "limits": {"duration_ms": 60000}},
   {"do": "send",
    "request": {"from": "caller", "methods": ["GET"], "paths": ["/devtools/browser"],
                "query": [{"name": "session", "pattern": "[0-9a-f]{32}", "required": true}]},
    "inject": [{"target": {"kind": "header", "name": "Authorization"},
                "template": "Bearer {{key}}"}]},
   {"do": "send", "fill": {
     "origin": "https://login.example.com",
     "fields": [{"selector": "input[name=id]", "template": "{{user}}"},
                {"selector": "#password", "template": "{{password}}"}],
     "submit": {"selector": "form#login"},
     "wait_ms": 5000}},
   {"do": "return"}
 ]}
```

**Who connects.** The node connects to the CDP endpoint the policy fixes (`open`
destinations), over TLS from inside the enclave, through the same transport as a WebSocket.
The caller does not relay CDP to the node, for two reasons: CDP carries the value of a fill
in the clear inside its WebSocket, so a relay would read every value typed; and a relay
could answer for the browser (a page at the right origin that is not). The caller chooses
at most the handshake request within its contract (above: which browser session, by a query
parameter of a fixed pattern); the policy may inject the endpoint's own credential.

- The first `send` is the handshake: an HTTPS `send` with a GET, as for a
  [WebSocket](#websocket).
- Each later `send` is a `fill` (at most 8): nothing else, and no `receive` (nothing of the
  page is read into the operation). `compute` may come between.
- `return` takes nothing (`{"do": "return"}`): the caller gets the outcome only. There is no
  relay: the caller cannot send a CDP command through the node.
- `run` and `await` are refused.

| `fill` member | Meaning |
| --- | --- |
| `origin` | The page: exactly `https://host` or `https://host:port`, lowercase, no path. Only `https`. |
| `fields` | 1 to 16: `selector` (a CSS selector, 1 to 256 bytes of printable ASCII, passed to the page as data), optional `frame` (below), `template` (the value; secrets allowed; it must render to UTF-8). Each a different element. |
| `submit` | `selector` and optional `frame`: a form the node submits (`requestSubmit()`) or an element it clicks. |
| `frame` | The origin of the frame that holds the element: a **direct child** of the top frame at that origin. Without it, the element is in the top frame. A frame of another origin than the page is flagged `frame_origin`. |
| `navigate` | Optional: a path on `origin` the node loads the page at first, so that nothing an earlier client planted in the document survives. At most 2048 bytes, no dot segment, no placeholder. |
| `wait_ms` | How long the node waits for each element to appear and for the page to leave after the submit: default 5000, at most 30000. |

What the node does, in order. The CDP commands it issues are exactly `Target.getTargets`,
`Target.attachToTarget`, `Target.detachFromTarget`, `Page.navigate`, `Page.getFrameTree`,
`Page.createIsolatedWorld`, `Runtime.callFunctionOn` and `Runtime.releaseObjectGroup`; never
`Runtime.evaluate`. The only code it runs in a page is four fixed functions of its own
(`engine::cdp::FIND`, `FILL`, `SUBMIT`, `CLEAR`), with the selector, origins and value as
arguments.

1. It picks the one `page` target whose URL is at `origin` (none, or two, refuses) and
   refuses when another client is attached to it; then attaches (a flattened session).
2. For each field: it reads the frame tree; the top frame's URL (and the security origin the
   browser reports) must be at `origin`, and the element's frame must be the top frame or a
   direct child at the `frame` origin; a frame of any other origin is never used. In an
   isolated world of its own in that frame, `FIND` checks `location.origin` and
   `location.ancestorOrigins` in the page itself and looks up the selector, which must match
   exactly one element, in exactly one frame. A frame in another process is reached through
   its own target.
3. It reads the frame tree again: the same top frame and frame, with the same loaders. A
   navigation changes the loader, a frame swap the id; either refuses.
4. `FILL` sets the value on the element found (an `input` other than `hidden`, or a
   `textarea`), after checking the origins again in the same task, so no navigation can come
   between that check and the value; a document that changed makes the element's id unknown
   and the call fail. It dispatches `input` and `change`.
5. It reads the frame tree again, as in 3.
6. The submit element is found and checked the same way; `SUBMIT` runs on it. The node waits
   up to `wait_ms` for the top frame to load another document: `navigated`; otherwise
   `submitted`, and it blanks every field it filled (`CLEAR`), so a later reader of the page
   does not find the values there.

Every message of the browser is read strictly: an answer to a command the node did not send,
a second answer, an answer from another session, a binary message or JSON that does not
parse ends the fill; events are counted (at most 10,000) and dropped unread; a message is at
most 4 MiB, and a connection issues at most 2,000 commands. A refusal is
`Error::FillRefused` with a fixed text: nothing the browser or the page sent.

The call is an HTTP call (`{"kind": "http"}`, with the handshake request when its contract
takes one) and answers `{"kind": "fill", "fill": {"outcome", "origin", "fields",
"duration_ms", "log_seqs"}}`: `outcome` is `navigated` or `submitted`, `origin` the top
frame's origin at the end (searched for secrets like any response). A browser connection
takes one of the open-connection slots while it runs (4 per caller, 16 per owner, 256 per
node), and the node logs one entry when it opens (the handshake, as any request) and one
when it closes, with why (`navigated`, `submitted`, `refused`, `idle`, `duration`, `bytes`,
`limit`) and the messages and bytes sent.

What CDP cannot give, and what stays trusted: the node cannot see the page's TLS through CDP
(the certificate and the connection are the browser's), and a browser that lies can show
any page at any origin. The browser behind the endpoint is trusted with the values, as is
the page at the origin, which reads them as it would from a person. A script of the page
(or one an earlier client planted in it, unless `navigate` reloads it) can read the field
back and keep it; the node blanks the fields when the page stays, but cannot stop that.
Every browser operation is flagged `browser_fill`. A typed item has no browser operation
yet.

### Protocol connections

`ssh` (with SFTP and local port forwarding), `postgres`, `mysql`, `smtp`, `imap`, `redis`,
`mqtt` and `amqp` are standard protocol families, never a site's:
the node signs in with the item's secret, runs the commands the policy fixes or shapes, and
hands back results after the reflection search. Each is its own client in the engine
(`engine::proto`), synchronous, with only modern algorithms.

```json
{"name": "deploy",
 "steps": [
   {"do": "open", "connection": "ssh",
    "destinations": [{"host": "build.example.com", "port": 22}],
    "host_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpE5S3nEfaq9h6S6l5bSkF1H0R1mAEbvYMVg4Ccmi6G"],
    "login": {"user": "deploy", "key": "{{ssh_key}}"},
    "limits": {"idle_ms": 30000, "duration_ms": 300000}},
   {"do": "send", "command": {"text": "uptime"}},
   {"do": "receive", "capture": [{"source": {"from": "regex", "pattern": "load average: ([0-9.]{1,8})"},
                                  "into": {"kind": "temp", "name": "load", "secret": false}}]},
   {"do": "return", "relay": {"commands": [
     {"name": "restart", "text": "sudo systemctl restart", "params": [{"pattern": "(web|worker)[0-9]{0,2}"}]},
     {"name": "logs", "text": "journalctl -n 200 -u", "params": [{"pattern": "[a-z0-9-]{1,32}"}]}
   ]}}
 ]}
```

The `open` of a protocol connection:

| Member | Meaning |
| --- | --- |
| `login` | Required. `user` and one credential, each a template: `password`; `key` (SSH: an Ed25519 or ECDSA P-256/P-384 key in PKCS#8, or an unencrypted OpenSSH key; RSA in PKCS#8 or PKCS#1); `token` (an OAuth 2.0 bearer token for `xoauth2`, or the MQTT `token` mechanism); or `answers` (SSH keyboard-interactive: up to 8 `{"prompt": <regular expression the whole prompt must match>, "template"}`). Literals: `database` (PostgreSQL, MySQL), `client_id` (MQTT, 1 to 64 visible ASCII bytes; without it a random `credentials-...` one, so two connections never take over each other's session) and `vhost` (AMQP, default `/`). `mechanism` is optional. The credential must be the one its mechanism uses. `user` may be empty for Redis and MQTT. |
| `mechanism` | SSH `password`, `publickey`, `keyboard-interactive`; PostgreSQL `scram-sha-256`; MySQL `caching-sha2-password`; SMTP `plain`, `login`, `xoauth2`; IMAP `login`, `plain`, `xoauth2`; Redis `auth`; MQTT `password`, `token`; AMQP `plain`. Without it, the kind's default for the credential given. The node uses this mechanism or none: a server that does not offer it is refused, never answered with another. |
| `host_keys` | SSH only, required: 1 to 16 pinned host keys, `type base64` as in `known_hosts` (`ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa` for an RSA key verified with `rsa-sha2-256/512` only). The node offers only the algorithms of the pinned keys and refuses a key that is not pinned before it sends any credential. |
| `tls` | SMTP and IMAP: `implicit` (default; ports 465 and 993) or `starttls` (587 and 143). A server that does not offer STARTTLS, or sends anything after its go-ahead before the handshake, is refused. PostgreSQL and MySQL always ask for TLS (`SSLRequest`) before anything else and refuse a server that does not take it; Redis, MQTT and AMQP are TLS from the first byte; SSH encrypts itself. |
| `version` | MQTT only: `3.1.1` (default) or `5`. |
| `limits` | As for a WebSocket: idle, duration and bytes (both ways). Reaching one ends the connection. |

`send` takes `command`: `{"text": <template>, "params": [<template>, ...]}`, a command the
policy fixes (an SSH command line, an SQL statement with `$1`... (PostgreSQL) or `?` (MySQL)
for the parameters, an IMAP command without its tag, a Redis command name, or a verb: MQTT
`publish` (topic, payload) or `subscribe` (filter), AMQP `publish` (exchange, routing key,
body) or `get` (queue)), and for MQTT `qos` 0 or 1. A `receive` after it captures from what
came back (`between`, `regex` or `all`). `run`, `await` and HTTP requests are refused. An MQTT
`subscribe` the policy sends stays subscribed for the rest of the connection.

`return` takes `relay`:

- `commands` (at most 32): the commands the caller may run by `name`, each a `text` the caller
  cannot change and `params`. A parameter is a `template` of the policy; the caller's value
  under a `pattern` (matched whole) and `max_len` (default and at most 64 KiB); or both, a
  `template` that reads the caller's value, checked by the `pattern`, as `$input`
  (`"level={{ $input }}"`). A parameter of the caller with no pattern is flagged
  `param_unpinned`. `columns` (PostgreSQL, MySQL) keeps only those columns of the rows.
  Members of some kinds: `channel` (SSH: `exec` by default, `sftp`, `direct-tcpip`), `qos`
  (MQTT, 0 or 1), `max_messages` (MQTT `subscribe`, AMQP `get`: 1 to 256, default 16) and
  `wait_ms` (MQTT `subscribe`: 1 to 60,000, default 5,000).
- `mail` (SMTP only, and the only relay of SMTP): `senders` and `recipients`, 1 to 16 patterns
  each that the whole envelope addresses must match, `max_recipients` (default and at most 100)
  and `max_bytes` (default and at most 8 MiB).
- `frames` and `server`: a streaming call, as for a WebSocket. SSH: an interactive shell (no
  commands), or a forward (every command a `direct-tcpip` rule; the call names one). The
  caller's signed frames go to the shell or the forwarded connection within their rules; what
  comes back goes back with `server: true`, after the stream search. MQTT: `server: true` alone
  hands back the messages of the subscriptions the policy's `send` steps made, each as a text
  part `{"topic", "payload", "qos", "retain"}` after the reflection search of that message
  whole; MQTT takes no frames.

The caller sends `{"session": {"destination", "commands": [{"name", "params": [...]}],
"mail": [{"from", "to": [...], "data": <base64>}]}}`. Every command and message is checked
against its rule **before** anything is logged or the connection opens: an unknown name, a
parameter outside its pattern or length, the wrong number of parameters, a sender or
recipient outside the mail rule, or a message with a CR or LF outside a CRLF (SMTP smuggling)
fails the call. Each result comes back as `{"name", "status", "data", "stderr"}`; an error
stops the rest and is returned next to the results that completed.

What each kind does with them:

- **SSH** (own client on ring): key exchange `curve25519-sha256`, `ecdh-sha2-nistp256/384/521`
  with strict key exchange (Terrapin); ciphers `aes256-gcm`, `aes128-gcm` and
  `chacha20-poly1305` (only under strict key exchange). SHA-1, CBC, CTR with a MAC, `ssh-rsa`
  signatures, DSA and the finite-field groups are never offered. A rekey is refused (the
  connection is short). A command line is the rule's text, then each parameter as one POSIX
  single-quoted word, so `x; rm -rf /` stays an argument. The result is the output, the error
  output and the exit status.
- **PostgreSQL**: TLS, then SCRAM-SHA-256 only. A server that asks for cleartext or MD5, says
  the sign-in succeeded before SCRAM proved it knows the password, sends a server signature
  that does not verify, or asks for fewer than 4096 (or more than 1,000,000) iterations is
  refused. Channel binding is not used: TLS already ties the connection to the destination's
  certificate. Queries go by the extended protocol with every parameter bound as text, never
  spliced into the SQL. The result is `{"columns", "rows", "tag"}` (values as text, `null` for
  NULL), or `{"error": {"code", "message"}}` with status 1.
- **SMTP** (submission): `EHLO`, then `AUTH` with the named mechanism, then `MAIL FROM`,
  `RCPT TO` and `DATA`, dot-stuffed. The result is the last reply and its code.
- **IMAP**: `CAPABILITY`, then `LOGIN` (refused if the server says `LOGINDISABLED`) or
  `AUTHENTICATE`; commands are tagged, each parameter a quoted string (a CR, LF or NUL is
  refused). The result is the whole response, literals included, and its completion (0 `OK`,
  1 `NO`, 2 `BAD`). Reading a code from a message is a fixed `send` (`UID FETCH ...
  BODY[TEXT]`) and a `receive` that captures it into a temp; it never goes back.
- **Redis**: `AUTH [user] password`, then each command as an array of bulk strings: the rule's
  text is literal words, each parameter one argument whatever bytes it holds. The reply comes
  back as JSON (an error as `{"error": ...}` with status 1).
- **MySQL**: the server's greeting must offer TLS; the node answers with an `SSLRequest` and
  nothing else before the handshake, and refuses a server without TLS, or bytes after the
  greeting before the handshake (injection), before writing anything. Then
  `caching_sha2_password` only: the scramble, and when the server asks for full
  authentication, the password over the verified TLS (never the server's RSA key exchange, and
  never on a plain connection). A switch to `mysql_native_password`, cleartext or any other
  plugin, a second switch, or a `LOCAL INFILE` request is refused; `CLIENT_LOCAL_FILES`,
  multi-statements and multi-results are never offered. Each command is a prepared statement
  (`COM_STMT_PREPARE`, `COM_STMT_EXECUTE` with every parameter bound as a string,
  `COM_STMT_CLOSE`), so a parameter is never SQL. The result is `{"columns", "rows"}` (values
  as text, `null` for NULL) or `{"columns": [], "rows": [], "affected", "insert_id"}`; an error
  is `{"error": {"code", "state", "message"}}` with status 1.
- **MQTT** (3.1.1 or 5) over TLS: `CONNECT` with a clean session, no will, keep-alive 60 s,
  the user and the password (or the token as the password); version 5 also states the most the
  node reads (16 MiB). `publish` and `subscribe` at QoS 0 or 1, never 2, never retained. A
  topic or filter of the caller never holds `+` or `#` (only the policy's may); a message on a
  topic no subscription matches, at QoS 2, or with a topic alias is refused. A `subscribe` of
  the caller subscribes, collects up to `max_messages` within `wait_ms`, unsubscribes, and
  returns the messages as `[{"topic", "payload", "qos", "retain"}]` (`payload` as text, or
  `{"base64"}` when it is not UTF-8); a `publish` returns `{"reason"}`.
- **AMQP 0-9-1** over TLS: `PLAIN` only (a server that does not offer it, or that asks for
  more with `connection.secure`, is refused before or instead of answering), heartbeats off,
  frames of at most 128 KiB. Channel 1 in confirm mode: each `publish` is mandatory and waits
  for its confirmation (`{"confirmed": true}`; a returned message is `{"error": {"code",
  "message"}}` with status 1). `get` takes up to `max_messages` with `basic.get`,
  acknowledging each, as `[{"exchange", "routing_key", "redelivered", "payload"}]`. The
  exchange, routing key and queue of a caller's command are templates of the policy, never the
  caller's.
- **SFTP** (SSH, `channel: "sftp"`, version 3): `read` (the path) returns the whole file;
  `write` (the path, the bytes) creates or truncates it. A path is absolute with no empty, `.`
  or `..` segment, no trailing `/`, backslash or NUL, checked when the policy is signed (a
  literal path), before anything is logged (the caller's value) and again before it is sent.
  The node follows no symbolic link: the server's canonical form of the path (`REALPATH`), or
  of its directory for a write, must be the path itself, and the file (`LSTAT`, which does not
  follow links) must be a regular file, or absent for a write. A race on the server between
  that check and the open remains (see the threat model).
- **Forwarding** (SSH, `channel: "direct-tcpip"`): the rule's `text` is the `host:port` the
  server connects to, fixed by the policy, with no parameters; the caller names the rule, never
  a destination. The node opens one `direct-tcpip` channel on a streaming call and relays the
  caller's signed frames to it and the bytes back through the stream search. The summary flags
  each forward rule with its destination.

Every result is redacted and searched for secrets before it goes back, in the form the server
sent it (a value in a row, a bulk string) and as JSON, and across results. A protocol
connection takes a slot like a WebSocket (a caller holds at most 4 at once, an owner 16, a
node 256), and the node logs its `use` and its `closed` entry, with the commands and bytes
each way.

```json
{"name": "orders",
 "steps": [
   {"do": "open", "connection": "postgres",
    "destinations": [{"host": "db.example.com", "port": 5432}],
    "login": {"user": "reporting", "password": "{{db_password}}", "database": "shop"}},
   {"do": "return", "relay": {"commands": [
     {"name": "order", "text": "SELECT id, status, total FROM orders WHERE id = $1",
      "params": [{"pattern": "[0-9]{1,12}"}], "columns": ["id", "status", "total"]}
   ]}}
 ]}
```

```json
{"name": "notify",
 "steps": [
   {"do": "open", "connection": "smtp", "tls": "starttls",
    "destinations": [{"host": "smtp.example.com", "port": 587}],
    "login": {"user": "alerts@example.com", "password": "{{smtp_password}}"}},
   {"do": "return", "relay": {"mail": {"senders": ["alerts@example\\.com"],
                                       "recipients": ["[a-z0-9.]{1,64}@example\\.com"],
                                       "max_recipients": 5, "max_bytes": 262144}}}
 ]}
```

```json
{"name": "inbox_code",
 "steps": [
   {"do": "open", "connection": "imap",
    "destinations": [{"host": "imap.example.com", "port": 993}],
    "login": {"user": "me@example.com", "token": "{{access_token}}", "mechanism": "xoauth2"}},
   {"do": "send", "command": {"text": "SELECT INBOX"}},
   {"do": "send", "command": {"text": "UID SEARCH UNSEEN FROM", "params": ["no-reply@example.com"]}},
   {"do": "receive", "capture": [{"source": {"from": "regex", "pattern": "\\* SEARCH ([0-9]{1,10})"},
                                  "into": {"kind": "temp", "name": "uid", "secret": false}}]},
   {"do": "send", "command": {"text": "UID FETCH {{uid}} BODY.PEEK[TEXT]"}},
   {"do": "receive", "capture": [{"source": {"from": "regex", "pattern": "code: ([0-9]{6})"},
                                  "into": {"kind": "field", "name": "last_code"}}]},
   {"do": "return", "relay": {"commands": [{"name": "noop", "text": "NOOP"}]}}
 ]}
```

```json
{"name": "cache",
 "steps": [
   {"do": "open", "connection": "redis",
    "destinations": [{"host": "cache.example.com", "port": 6380}],
    "login": {"user": "reader", "password": "{{redis_password}}"}},
   {"do": "return", "relay": {"commands": [
     {"name": "get", "text": "GET", "params": [{"pattern": "session:[0-9a-f]{32}"}]}
   ]}}
 ]}
```

```json
{"name": "orders_mysql",
 "steps": [
   {"do": "open", "connection": "mysql",
    "destinations": [{"host": "db.example.com", "port": 3306}],
    "login": {"user": "reporting", "password": "{{db_password}}", "database": "shop"}},
   {"do": "return", "relay": {"commands": [
     {"name": "order", "text": "SELECT id, status FROM orders WHERE id = ?",
      "params": [{"pattern": "[0-9]{1,12}"}], "columns": ["id", "status"]}
   ]}}
 ]}
```

```json
{"name": "sensors",
 "steps": [
   {"do": "open", "connection": "mqtt", "version": "5",
    "destinations": [{"host": "broker.example.com", "port": 8883}],
    "login": {"user": "device-7", "password": "{{mqtt_password}}", "client_id": "node-7"}},
   {"do": "return", "relay": {"commands": [
     {"name": "set", "text": "publish", "qos": 1,
      "params": [{"template": "devices/7/set"},
                 {"pattern": "[0-9]{1,3}", "template": "level={{ $input }}"}]},
     {"name": "read", "text": "subscribe", "max_messages": 8, "wait_ms": 2000,
      "params": [{"pattern": "sensors/[a-z0-9]{1,16}"}]}
   ]}}
 ]}
```

```json
{"name": "watch",
 "steps": [
   {"do": "open", "connection": "mqtt",
    "destinations": [{"host": "broker.example.com", "port": 8883}],
    "login": {"user": "device-7", "password": "{{mqtt_password}}"},
    "limits": {"idle_ms": 60000}},
   {"do": "send", "command": {"text": "subscribe", "params": ["sensors/+"]}},
   {"do": "return", "relay": {"server": true}}
 ]}
```

```json
{"name": "queue",
 "steps": [
   {"do": "open", "connection": "amqp",
    "destinations": [{"host": "mq.example.com", "port": 5671}],
    "login": {"user": "app", "password": "{{amqp_password}}", "vhost": "shop"}},
   {"do": "return", "relay": {"commands": [
     {"name": "new", "text": "publish",
      "params": [{"template": "orders"}, {"template": "new"},
                 {"pattern": "[0-9]{1,9}", "template": "order:{{ $input }}"}]},
     {"name": "next", "text": "get", "max_messages": 4, "params": [{"template": "replies"}]}
   ]}}
 ]}
```

```json
{"name": "reports",
 "steps": [
   {"do": "open", "connection": "ssh",
    "destinations": [{"host": "files.example.com", "port": 22}],
    "host_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpE5S3nEfaq9h6S6l5bSkF1H0R1mAEbvYMVg4Ccmi6G"],
    "login": {"user": "reports", "key": "{{ssh_key}}"}},
   {"do": "return", "relay": {"commands": [
     {"name": "report", "text": "read", "channel": "sftp",
      "params": [{"pattern": "/srv/reports/[a-z0-9_-]{1,32}\\.csv"}]},
     {"name": "upload", "text": "write", "channel": "sftp",
      "params": [{"pattern": "[a-z0-9_-]{1,32}", "template": "/srv/inbox/{{ $input }}.txt"},
                 {"max_len": 65536}]}
   ]}}
 ]}
```

```json
{"name": "tunnel",
 "steps": [
   {"do": "open", "connection": "ssh",
    "destinations": [{"host": "bastion.example.com", "port": 22}],
    "host_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpE5S3nEfaq9h6S6l5bSkF1H0R1mAEbvYMVg4Ccmi6G"],
    "login": {"user": "tunnel", "key": "{{ssh_key}}"},
    "limits": {"idle_ms": 60000, "duration_ms": 900000}},
   {"do": "return", "relay": {"server": true,
     "frames": [{"kind": "binary"}],
     "commands": [{"name": "db", "text": "db.internal:5432", "channel": "direct-tcpip"}]}}
 ]}
```

### `receive` and captures

```json
{"do": "receive", "capture": [{"source": {"from": "json", "pointer": "/access_token"},
                               "into": {"kind": "field", "name": "access_token"},
                               "optional": false}]}
```

On TLS, `receive` also takes `until`: `{"do": "receive", "until": ["a1 OK", "a1 NO"]}`.

| `source` | Reads |
| --- | --- |
| `{"from": "status"}` | The status code. |
| `{"from": "header", "name": "X-Request-Id"}` | A response header. |
| `{"from": "header_param", "name": "WWW-Authenticate", "param": "nonce", "scheme": "Digest"}` | A parameter of an authentication challenge. |
| `{"from": "cookie", "name": "session"}` | A `Set-Cookie` value. |
| `{"from": "json", "pointer": "/data/token"}` | A JSON pointer (RFC 6901). Strings come unescaped, numbers as written. |
| `{"from": "between", "start": "token=", "end": "&"}` | The bytes between two delimiters. |
| `{"from": "html", "selector": "input[name=_csrf]", "attribute": "value"}` | The first element of an HTML body that the selector matches: the value of `attribute` (entities decoded), or without it the element's text up to its end tag. The selector is one compound selector of at most 256 bytes: an optional tag (or `*`), then any of `#id`, `.class`, `[attr]`, `[attr=value]`, `[attr="value"]`; no combinators. The contents of raw-text elements (script, style, title, textarea and the like) are text, not tags. |
| `{"from": "regex", "pattern": "sid=([a-z0-9]+)", "group": 1}` | A group of the first match of a regular expression of at most 256 bytes: group 1 when the pattern has a group, else the whole match, unless `group` says otherwise (it must exist). Linear time (the `regex` crate: no backreferences or look-around), ASCII classes, matched on bytes; the compiled program is at most 256 KiB and its cache 1 MiB. |
| `{"from": "all"}` | The whole body. |

On TLS only `between`, `regex` and `all` apply. `html` and `regex` read at most 2 MiB
(`extract::MAX_SCAN`); a longer body fails the capture. A value with two parts, such as
`key,value`, is split either by two `regex` captures or by one capture and
`between(v, "", ",")` / `between(v, ",", "")` in the templates that read it.

| `into` | Effect |
| --- | --- |
| `{"kind": "field", "name": "..."}` | Replaces a **secret** field, from the response of a **fixed** request or a TLS read only. The node logs an `update` and returns a new record one generation later, even if a later step fails. A captured value that holds another secret field is refused. |
| `{"kind": "temp", "name": "...", "secret": true}` | A temporary value later steps of the same operation may read (a session cookie, a challenge nonce). At most 1 MiB of temporaries per operation. |

A captured value is at most 64 KiB. Captured secrets are replaced by `[redacted]` in what the
caller receives.

### `compute`

```json
{"do": "compute", "into": "signature", "template": "{{ hex(hmac_sha256(secret, $unix + $nonce)) }}"}
```

Renders a template once into a new name later steps read like a temporary value. The name
is new (no field, temporary or other computed value has it) and is read only after the step.
For the analysis the name has **exactly the properties of its template** (tainted,
controlled, caller-chosen, secret key, guessable), so writing a value through `compute` is
the same as writing its template inline: every rule below applies across steps. With no
connection, `compute` reads what the `return` template reads (`$input` included); with a
connection, the clock and `$nonce`.

### `run`

```json
{"name": "login",
 "steps": [
   {"do": "open", "connection": "https",
    "destinations": [{"host": "login.example.com", "port": 443}]},
   {"do": "run",
    "module": {"url": "https://login.example.com/static/enc.wasm",
               "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
    "entry": "encrypt", "inputs": ["{{password}}", "{{ $unix }}"], "into": "enc"},
   {"do": "send",
    "request": {"from": "fixed", "method": "POST", "path": "/login"},
    "inject": [{"target": {"kind": "body"}, "template": "pw={{ b64url(enc) }}"}]},
   {"do": "return"}
 ]}
```

Runs code that must compute on secret bytes (a site's own JavaScript or WebAssembly that
encrypts or packages a password before the login call) in the sandbox of layer 3
(`docs/design.md`, section 8e; the runtime and its measurements are in
[`docs/sandbox.md`](sandbox.md)). The code is never the caller's or an agent's:

| `module` | The code |
| --- | --- |
| `{"url": "https://host[:port]/path", "sha256": "<64 hex>"}` | Fetched by the node with `GET` from the destination's own origin, over the operation's connection, as a logged request. The host and port must be one of the connection's destinations (concrete or matched by a `*.` pattern). `sha256` (optional) pins the bytes; without it the summary flags `run_unpinned`, since the site may change the code at any time. A status other than 200, a module over 8 MiB or a pin mismatch stops the operation (`ModuleRefused`) before any later request. |
| `{"library": "lenprefix8"}` | A reviewed module compiled into the node (and so into its measurement, PCR2). `destination` names where its output may go; it may be left out when the connection has one concrete destination. |

| Member | Meaning |
| --- | --- |
| `entry` | The exported function `() -> ()` to call (a token). |
| `inputs` | 0 to 16 templates, rendered like a `compute` (fields, temporaries, the clock and `$nonce`; no request variable): secrets may go in. |
| `into` | A new token name for the output; never a field. |
| `destination` | For a library only: the destination its output may go to. |

The module sees only its inputs: it imports at most `input_count`, `input_len`,
`input_read` and `output` of the module `credentials` (no WASI, no clock, no randomness
unless an input carries it, no I/O), exports its memory as `memory`, and runs under a fuel
limit (10⁹ units, 1.25 s measured) and a memory limit (64 MiB), with at most 64 KiB of output.
A failure is `Sandbox` with a fixed reason (`Fuel`, `Memory`, `Trap`, `Import`, ...):
nothing the module computed reaches an error.

The output is **confined to the module's origin** (the URL's host and port, or a library's
`destination`). When the policy is signed:

- `run` needs an HTTPS connection; an operation with no connection or a TLS stream cannot
  have one (its output could only go back to the caller or to a stream the caller drives).
- the output, every `compute` that reads it, and every temporary value captured from the
  response of a request that carried it, may only be injected into a `send` whose request the
  policy **fixes** to that origin: not a request of the caller (the caller would choose the
  path, for example an endpoint that echoes), not another destination, not `return`;
- every `run` of an operation has the same origin.

At run time the output is also searched for in every response, like a rendered secret: a
response that echoes it is refused (`Reflection`). The log records the request as for any
`send` (method, host, path, the SHA-256 and length of the body, sealed to the owner), never
the output.

### `await`

The operation waits for the owner. The node keeps it, with every value it holds, in its
memory under a random id and hands the caller a pending reply instead of a result
([Operations that wait](#operations-that-wait)); the caller resumes it with the id.

```json
{"do": "await", "challenge": {"kind": "sms", "hint": "The code your bank texts you",
                              "into": "otp", "pattern": "[0-9]{6}", "timeout_ms": 120000}}
```

A **code** (`sms`, `email`, `app`, `3ds`) comes from a device of the owner, signed and sealed
to the node; never from the caller. It goes into the secret temporary value `into` (a new
token), which later steps read like a captured secret and which is redacted from what goes
back. `pattern` is a regular expression the whole code must match (by default
`[0-9A-Za-z-]{1,64}`); a code is 1 to 256 bytes.

```json
{"do": "await", "challenge": {"kind": "external", "hint": "Approve the payment in your bank's app",
  "poll": {"send": {"request": {"from": "fixed", "method": "GET", "path": "/v1/status"},
                    "inject": [{"target": {"kind": "header", "name": "Authorization"},
                                "template": "Bearer {{token}}"}]},
           "success": {"source": {"from": "json", "pointer": "/state"}, "one_of": ["approved"]},
           "failure": {"source": {"from": "json", "pointer": "/state"}, "one_of": ["declined", "expired"]},
           "every_ms": 3000}}}
```

An **external** challenge carries no code: the site waits for the owner in another app. Each
time the caller resumes, and no sooner than `every_ms` (1 second to the timeout) after the
last poll, the node sends the fixed request of `poll` (checked like any `send`; it is logged
like any request) and reads its response: `success` lets the operation go on, with that
response as the last one, `failure` fails it (`challenge_failed`), anything else keeps it
waiting. A condition reads one capture source (not `all`) and compares it with 1 to 16
values of at most 256 bytes, exactly.

| Member | Meaning |
| --- | --- |
| `kind` | `sms`, `email`, `app`, `3ds` (a code) or `external`. |
| `hint` | What the owner is told: 1 to 256 bytes without control characters, written by the owner in the policy. The caller writes no part of it. |
| `into`, `pattern` | Codes only. |
| `poll` | `external` only, required. |
| `timeout_ms` | How long the operation waits: 1000 to 300000 (the default, five minutes). |

### `return`

#### HTTPS: the response projection

```json
{"do": "return", "response": {"headers": ["ETag", "Location"],
                              "body": {"json": ["/id", "/items/*/name"]}}}
```

The status always goes back. A header goes back only when it is listed (at most 32, case does
not matter), and the body only as `body` says:

| `body` | What goes back |
| --- | --- |
| absent | nothing |
| `"all"` | the whole body (the summary flags it) |
| `{"json": [pointers]}` | a JSON object from each pointer to the JSON text of its value, numbers as written; a `*` token stands for every element of an array (`/items/*/id` gives an array of ids). A pointer that reaches nothing is left out. A body that is not JSON fails the call. At most 32 pointers. |
| `"stream"` | the whole body, handed on as it arrives when the caller asks for a stream (server-sent events, chunked bodies); a plain call gets it whole, as with `"all"` (the summary flags it the same way). The `send` must be the step just before `return`, and not gRPC. |

`trailers` lists the trailer fields that go back (at most 32, case does not matter), such as
`grpc-status`. `{"do": "return"}` alone returns the status only. Whatever goes back is still
redacted and searched for secrets.

A streamed body is searched as it passes: the node holds back the last bytes of what it
has read (one less than the longest form of a secret it searches for, times six for JSON
escapes), so a secret split across chunks, in any form the search knows (raw, Base64 in both
alphabets, JSON-escaped, percent-encoded, hex in both cases, and `\u00XX` escapes), is found
before any byte of it leaves. A secret found mid-stream ends the stream; what was already
handed on held none of it. A captured secret in a streamed body ends it too, since it cannot be
redacted in place. The status and the listed headers go first, the body in parts, then the
listed trailers.

#### TLS: the relay

```json
{"do": "return", "relay": {"sends": ["a[0-9]{1,4} (NOOP|LOGOUT)\\r\\n", "a[0-9]{1,4} FETCH [0-9]+ BODY\\[\\]\\r\\n"]}}
```

After the steps, the caller's exchanges (at most 64, each a send and the delimiters to read
until) run on the connection when **every** send matches one of 1 to 16 patterns **whole**
(linear-time regular expressions of at most 256 bytes; `.` does not match a line end). The
sends are checked before anything is logged or the connection opens. Without `relay`, a
call with exchanges is refused. Every read is redacted and searched before it is returned;
an error stops the exchanges and is returned next to the reads that completed.

#### WebSocket: the relay

```json
{"do": "return", "relay": {"frames": [{"kind": "binary", "shape": {"raw": {"max_len": 256, "pattern": "[0-9a-f]{2,256}"}},
                                       "template": "{{ hexdecode($input) }}"}],
                           "server": false}}
```

See [WebSocket](#websocket). A server message is searched as a whole, with the end of the
one before it, so a secret split across two messages is found too.

#### Browser: the outcome

`{"do": "return"}`: the outcome and the final origin of the page (see
[Browser fills](#browser-fills)); nothing of the page, and no relay.

#### No connection: the output

```json
{"do": "return", "template": "{{ k256_sign_recoverable(key, keccak256($input)) }}"}
```

The output of the template goes back to the caller. A template whose output could hand a
secret back is refused when the policy is signed.

### Input schemas

An operation with no connection that reads `$input` declares what the input may be; the
node checks it before it opens the record, and the templates read the checked input. At most
1 MiB.

```json
{"name": "sign-token",
 "input": {"json": {"members": [
   {"pointer": "/aud", "type": "string", "equals": "https://api.example.com"},
   {"pointer": "/scope", "one_of": ["read", "write"]},
   {"pointer": "/amount", "type": "number", "min": "1", "max": "100000"},
   {"pointer": "/note", "optional": true},
   {"pointer": "/iat", "set": "unix"},
   {"pointer": "/exp", "set": "unix", "offset": 300}
 ]}},
 "steps": [{"do": "return", "template": "{{ b64urlraw(hmac_sha256(key, $input)) }}"}]}
```

| Schema | Input |
| --- | --- |
| `{"raw": {"max_len": 64, "pattern": "[a-z0-9]+"}}` | Bytes; both members optional. `{"raw": {}}` is any bytes, and the summary flags it. |
| `{"json": {"members": [...]}}` | A JSON value. The schema is **closed**: a member that is not declared (and not under a declared member without rules) is refused, and so are duplicate keys. The checked value is written back compactly; numbers keep their digits. |
| `{"rlp": {"prefix": "02", "items": [...]}}` | Optional prefix bytes (hex), then one canonical RLP value. Closed like JSON: every item is declared. |

A JSON member has a `pointer` (RFC 6901, empty for the whole value) and optionally `optional`,
`type` (`string`, `number`, `boolean`, `null`, `object`, `array`), `equals`, `one_of`,
`pattern`, `min`, `max` (as for query values: they read the text of a string, or a number,
`true`, `false` or `null` as written), or `set` (`unix` or `unix_ms`) with an `offset`: the node
writes its clock there, whatever the caller sent. An RLP item has a `pointer` of list indexes
(`/3`, `/8/0`), `optional`, `equals` or `one_of` in hex, and `min` and `max` read as a
big-endian unsigned integer (no leading zero byte; the empty string is 0). At most 64 members
or items, 32 levels deep.

EIP-712 typed data can be bounded with a JSON schema today, but no template function hashes it
yet; an `eip712` schema and hash are next.

### Loops and branches

```json
{"do": "repeat", "times": 3, "until": "done", "steps": [ ... ]}
{"do": "if", "name": "status", "equals": "OK", "then": [ ... ], "else": [ ... ]}
```

This is the syntax of the next part of the language: a loop with a fixed bound and a branch
on a public captured value. A policy that uses them is refused (`loops and branches are part
of the syntax but not run yet; write the steps out`) until the analysis covers them: each
path through the steps must keep the properties above, and a branch on a value must not tell
the caller anything about a secret.

## Secure defaults

Where two answers were reasonable and the design left the choice open, the policy takes the
one that gives the caller less:

| Choice | Why |
| --- | --- |
| The status is the only thing an HTTPS operation returns unless `response` says more. | A server's answer may hold what the policy never meant to hand out (temporary credentials minted by the call); the owner lists what the caller needs. |
| A caller may send no query parameter that is not listed; there is no wildcard for names. | An unlisted parameter can change what the signed request does (an action, a scope, a limit). |
| A `run` output goes only into a request the policy fixes, not one of the caller's, even to the same origin. | The caller would choose the path and query around it, and so could send it to an endpoint of the site that echoes what it receives. |
| The output of a `run`, and what the response to a request that carried it gives into temporary values, are confined alike. | A site that echoes the output would otherwise hand it to a capture that may go anywhere. |
| A `run` module's limits (fuel, memory, output) are the node's, not the policy's. | One bound to audit; a policy cannot raise them. |
| The sandbox runtime is an interpreter (wasmi), not a JIT. | No code is generated at run time, and it adds about 1.3 MB to the node instead of 11.5 MB (`docs/sandbox.md`). |
| A caller may never send a query name the `send` injects. | Servers disagree on which of two equal names wins. |
| `%25` in a caller's path is refused unless `encoded_percent`. | A server or proxy that decodes twice reads another path than the one checked. Measured: no test or example of the repository needed it. |
| Dot segments are checked as sent, after `;` parameters are stripped and after one and two decodings. | Servers strip path parameters (`..;`) or decode twice. |
| Method-override parameters are refused in the query and the body unless `override_params`. | Frameworks read them as the method, so an allowed POST becomes a DELETE. |
| Placeholders are whole segments of a template the owner signs. | A placeholder the caller places can carry a secret into a parameter of its choice. |
| Old prefixes convert to templates that match the same paths (`/v1/` → `/v1/**`; `/v1` → `/v1` and `/v1/**`; `/` → `/**`). | The conversion neither widens nor silently narrows paths. |
| A stream relays nothing until `relay` lists the sends, and a send must match a pattern whole. | After the login, a caller's command runs under the owner's session. |
| An operation that reads `$input` must declare `input`; JSON and RLP schemas are closed; duplicate JSON keys are refused; the checked JSON is written back. | A key signs what the owner bounded, not what a parser disagreement lets through. |
| One `open` per operation, first; an HTTPS `receive` directly follows its `send`. | Every response read is the one of the request before it, and every step runs on the connection the log names. |
| Loops and branches are refused. | The analysis does not cover them yet. |
| A field the kind marks secret or masked must be `secret: true` in the policy. | Masked values are still secrets in transit: the taint analysis and the reflection search must track them. Only `describe` shows the masked projection. |
| A public field of the kind that the policy keeps secret is not described. | The owner chose to hide it; `describe` follows the policy, not the kind. |
| Card number, expiry and code are `guessable`. | Each has few enough values (a code has 1,000 to 10,000) that a hash or MAC of it is a lookup table. |
| A one-time-code seed has at least 128 bits. | RFC 4226 asks for 128 bits and recommends 160; shorter seeds are guessable offline from a few codes. |
| The expiry is masked to its year only. | Month and year together narrow a card down; the year tells an agent whether it is current. |
| `describe` works on typed records only. | An untyped record has no schema saying which fields are public; describing it would guess. |
| Any caller the policy lists may `describe`; there is no separate permission. | What `describe` returns is public or masked by the kind and logged; a caller that may use the item already learns that much from its results. Listing it per caller would be a widening knob with no narrowing value. |
| The ssh kind allows SSH only, with the item's whole host key pinned; the vpn kind allows no connection. | A TLS stream to port 22 would send a key to a server whose host key nobody checked; a fingerprint pin cannot be compared with the key the server proves; the node speaks no VPN protocol. |
| A typed protocol login is exactly the kind's fields. | `{{password}}` as the user, or inside other text, would send the secret where the kind did not mean it. |
| MySQL refuses every plugin but `caching_sha2_password`, and full authentication without TLS. | `mysql_native_password` is SHA-1 based and replayable from a captured exchange; cleartext and the RSA exchange put the password in a form the node did not choose. |
| SFTP follows no symbolic link. | A link planted under a permitted path would reach a file outside the pattern. |
| A forward's destination is a literal of the policy. | A caller-chosen destination would make the SSH server a proxy into its network. |
| Wildcards, client certificates, relays and whole response bodies are refused unless the kind allows them; the reviewed kinds allow them only for `api`. | A kind exists to make a typical credential safe without the owner reading every line. |
| Plain HTTP and plain database, FTP or broker connections need a named sign-off in the binding, and are flagged in the summary. | A sign-off is an explicit, signed act of the owner, visible in every summary and diff. |

## Typed items

A policy may bind its record to a **kind of item**: a schema of fields, each `secret`,
`masked` or `public`, with checks on its value and a **shape** of what a policy of that kind
may do. The node re-derives the shape from the kind on every signature check and refuses a
policy that is wider, so a card policy cannot hand back the number even when a device signed
it.

```json
{"kind": "login", "pins": {"origin": "https://shop.example"}}
```

`pins` holds the value of each `pinned` field of the kind (an origin, a host, a port, a host
key): the policy fixes it, and the sealed record must hold the same value. `signoff` lists
the flags the owner signs off (`plain_http` for an `http://` origin, `plain` for an
unencrypted database, FTP or broker connection).

The reviewed kinds ship in the node (`crates/engine/src/items.json`, or `item_kinds()` in the
`client` crate):

| Kind | Fields (secret · masked · public) | Shape |
| --- | --- | --- |
| `card` | cvc · number (brand and last four), expiry (year) · holder, billing | HTTPS to the owner's destinations; JSON members back; every use waits for the owner's approval |
| `login` | password, totp, session · username (email) · origin (pinned), session_expires | HTTPS to the pinned origin only; may capture `session` |
| `oauth` | client_secret, refresh_token, access_token · — · provider (pinned), client_id, scopes | HTTPS; JSON members back; captures the tokens |
| `identity` | national_id · name, birth_date, phone, email, address · — | HTTPS; JSON members back |
| `totp` | seed (≥128 bits) · account · digits, period, issuer | derivations only |
| `ssh` | password, private_key · — · host, port, host_key (pinned), user | SSH to the pinned host and port, pinning exactly the item's host key (a whole key); signs in with exactly `{{user}}` and `{{password}}` or `{{private_key}}`; relay allowed (commands, shell, SFTP, forwards) |
| `database` | password · — · engine, host, port, tls (pinned), database, user, ca | TLS to the pinned host and port; relay allowed |
| `ftp` | password · — · host, port, mode (pinned), user | TLS to the pinned host and port; relay allowed |
| `mail` | password, token · user (email) · smtp_host, smtp_port, imap_host, imap_port (pinned) | SMTP to the pinned SMTP server, IMAP to the pinned IMAP server; signs in with exactly `{{user}}` and `{{password}}` or `{{token}}`; relay allowed |
| `queue` | password, sasl_secret, nkey_seed, client_key · — · protocol, host, port, tls (pinned), user, client_id | TLS to the pinned host and port; relay allowed |
| `vpn` | private_key, psk · — · protocol, host, port (pinned), peer_public_key, identity | none yet |
| `api` | free fields, as an untyped record | anything an untyped policy may do; nothing is described |

The checks a field may carry:

| Check | Holds when |
| --- | --- |
| `luhn` | 12 to 19 digits whose Luhn checksum holds. |
| `expiry` | `MM/YY` or `MM/YYYY`, and the node's clock is before the first day of the next month (UTC). Checked when the device seals (by its clock) and by the node on every use (by its own). |
| `cvc` (`number`) | 3 digits, or 4 for a brand that uses 4 (IIN 34 and 37); 3 or 4 when the brand is unknown. |
| `origin` | exactly `https://host[:port]`: lower case, no path, query, fragment, user info, wildcard or leading-zero port; `http://` only with the `plain_http` sign-off. |
| `host` | a lower-case DNS name. |
| `integer` (`min`, `max`) | a decimal without leading zeros within the bounds. |
| `length` (`min`, `max`) | the byte length within the bounds. |
| `pattern` (`regex`) | the whole value matches (the `regex` crate, at most 256 bytes). |
| `one_of` (`values`) | one of the values, exactly. |
| `email` | `local@domain`: a local part of at most 64 printable characters, and a lower-case host name of at least two labels. |
| `date` | `YYYY-MM-DD`, a real day (leap years included). |
| `base32` (`min_bits`) | RFC 4648 base32 (spaces and padding ignored) of at least that many bits. |
| `base64_key` (`bytes`) | standard base64 of exactly that many bytes. |
| `ssh_host_key` | `algorithm base64` whose blob names the same algorithm (`rsa-sha2-*` keys carry `ssh-rsa`; an Ed25519 key is 32 bytes), or `SHA256:` and a 32-byte fingerprint. |
| `signoff` (`values`, `flag`) | the value is not one of `values`, or the binding signs off `flag`. |

Card brands follow the IIN ranges of ISO/IEC 7812 (Visa, Mastercard, American Express,
Discover, JCB, Diners Club, UnionPay, Mir); no kind or check names a company or site
beyond that standard.

A policy of a kind must, beyond every rule of an untyped policy:

- declare only fields of the kind, keep every required field, keep secret and masked fields
  secret and guessable fields guessable;
- pin every pinned field it declares, with a value that passes the field's checks, and sign
  off only flags the kind's checks name;
- use only the connections of the shape; send only to the pinned origin (`login`) or the
  pinned host and port (`ssh`, `database`, `ftp`, `queue`), or the pinned server of its
  connection (`mail`: SMTP and IMAP each to their own), with no wildcard unless the
  shape allows one; use no client certificate, relay or capture the shape does not allow;
- return no more than the shape: `status` < `json` (JSON members) < `all` (the whole body);
- on a protocol connection (`ssh`, `smtp`, `imap`), sign in with each `login` member exactly
  `{{field}}` of the field the shape's `login` names for it (`user`, `password`, `key`,
  `token`), and nothing else (no answers, no literals around the secret); for SSH, pin exactly
  the item's `host_key`, which must be a whole key: a `SHA256:` fingerprint passes the field's
  check but not this rule, since the node compares keys, not fingerprints. A shape with a
  protocol connection must name its `login` (and `host_key` for SSH) and route to pinned
  hosts only. The database, queue and VPN kinds allow no protocol connection yet.

### Custom kinds

The owner's device can sign a kind of its own (`DeviceKey::sign_kind`, `sign_kind` in the
`client` crate); a policy binds it with `"custom": <signed kind>`. The node checks the
signature against the owner's known devices like a policy's, and holds the kind to the same
rules as a reviewed one, so no node release is needed. A custom kind cannot take the name of
a reviewed kind.

```json
{"name": "door", "description": "A door code.",
 "fields": [{"name": "site", "disclosure": "public", "pinned": true, "checks": [{"check": "origin"}]},
            {"name": "code", "disclosure": "secret", "guessable": true,
             "checks": [{"check": "pattern", "regex": "[0-9]{6}"}]}],
 "shape": {"connections": ["https"], "destinations": {"from": "origin", "field": "site"},
           "returns": "status"}}
```

### `describe`

A call of operation `:describe` with body `{"kind": "describe"}` on a typed record returns
the public fields and the masked projection of masked fields, computed by the node, never a
secret field:

```text
{"kind": "card", "fields": [{"name": "number", "disclosure": "masked", "value": "visa ••••4242"},
                            {"name": "expiry", "disclosure": "masked", "value": "2027"},
                            {"name": "holder", "disclosure": "public", "value": "Jane Doe"}]}
```

Any caller the policy lists may ask (`sign_describe_call` in the `client` crate). The node
checks the call's signature like any other, writes a `describe` entry to the log, then
answers. A record without a kind is refused (`the record is not a typed item`).

Masks: `card` (brand and last four, from 12 digits), `email` (first character and domain),
`initial` (first character), `year` (of an expiry or a date), `last2` (from 8 characters),
`last4` (from 12 characters). Shorter values show bullets only.

## Summaries and risk flags

`summarize(policy, previous)` (`engine::policy::summarize`, and `summarize` in the `client`
crate, which checks the policy first) gives the owner, in JSON:

- per secret field: each place it goes (scheme, host, port), in what form (a header, a query
  parameter, a path parameter, the body, a client identity, a stream send, the sign-in of a
  protocol connection and its mechanism, a command on one, a browser field with its selector
  and frame (going to the page's origin and to the CDP endpoint), or the output of a
  derivation and whether that is one-way);
- per operation: the connection and destinations, each request (fixed, or the caller's
  methods, path templates, headers and query allow-list), the injections, the response
  projection or relay patterns, the input schema, and each `run` step (`runs`: the module's
  URL or library, its origin, its pin or `unpinned`, the entry, the inputs and the output
  name); a secret read by a module's input is listed as going in `module_input` to the
  module's origin;
- the callers with their operations and limits, and the item with its pins and sign-offs;
- `lines`, the text of `Policy::summary()`;
- the risk flags, each with a code, a place and words:

| Code | When |
| --- | --- |
| `outside_origin` | A destination is not the item's origin or under it. |
| `wildcard` | A destination is a `*.` pattern. |
| `plain_http` | The item's origin is `http://`. |
| `plain_signoff` | The owner signs off another plain-text connection. |
| `raw_input` | An operation takes any bytes (`{"raw": {}}`). |
| `derive_reversible` | An output is not one-way: it holds an encryption, a key agreement or an XOR of a secret. |
| `relay` | A stream relays the caller's sends, or a WebSocket the caller's frames. |
| `relay_broad` | A relay pattern matches broadly (`.*`, `.+`, a negated class). |
| `response_all` | The whole response body goes back (`"all"` or `"stream"`). |
| `query_any` | A caller's query parameter takes any value. |
| `encoded_percent` | The caller's path may hold `%25`. |
| `override_params` | The caller may send method-override parameters. |
| `client_certificate` | A client certificate goes to a destination. |
| `run_unpinned` | A `run` step fetches its module without a `sha256` pin: the site can change the code that reads the secrets. |
| `frames_unpinned` | A WebSocket relays the caller's frames of a kind with no shape (or a `raw` shape with no pattern). |
| `server_frames` | A WebSocket hands the server's messages back to the caller, or an SSH shell what it prints. |
| `password_to_server` | A protocol connection signs in with a mechanism that hands the server the password itself: SSH `password`, `plain`, `login`, Redis `auth` (not `scram-sha-256`, `publickey` or `xoauth2`). |
| `param_unpinned` | A command parameter of the caller has no pattern (only its length bounds it). |
| `mail_relay` | The caller sends mail over SMTP as the item's account. |
| `shell_relay` | The caller types into an SSH shell. |
| `plain_datagram` | An operation sends UDP datagrams, without TLS: what they carry is readable on the path. |
| `browser_fill` | The node types secrets into a page in a browser over CDP: the page and the browser behind the endpoint get them, and the node cannot check the page's TLS through CDP. |
| `frame_origin` | A fill puts values into a frame of another origin than the page's. |
| `vend` | An operation hands back a credential minted from the secret ([Vending](#vending)): the caller holds it until it expires. |
| `wider` | Against `previous`: a new destination, method, path, header, query rule, injection, operation, caller or caller key; more of the response; a looser limit; a new sign-in, host key, TLS mode, command or mail rule; a browser fill changed; a field made public or not guessable; a payment changed or an approval dropped; a session rule changed; a vended lifetime made longer or its expiry read elsewhere; open limits or a protocol changed; the item unbound or its pins and sign-offs changed. |
| `new_destination` | Against `previous`: a destination it did not have. |

What changed without widening (an operation or a caller removed) is listed in `changes`.
The diff is conservative: a change it cannot rank counts as wider.

## JSON Schema

`crates/engine/policy.schema.json` (`engine::policy::JSON_SCHEMA`, `policy_json_schema()` in
the `client` crate) is a JSON Schema (draft 2020-12) of the policy, the item binding and
kinds. It is written by hand and tested: every policy of the README and its translations,
every block of this reference, the converted fixtures, typed policies and the reviewed kinds
hold against it, and a member the parser refuses anywhere in them, the schema refuses too. A
draft that holds is well formed; signing also runs the checks a schema cannot express (the
analysis, path templates, the shape of the kind).

## Approvals

An operation that needs the owner's approval ([Operations that wait](#operations-that-wait))
is described by the node in an `ApprovalSummary`: a random id, the node, owner, record
and generation, caller and operation, destination and origin, an amount (a decimal and an
ISO 4217 code), the item's `describe` view and at most 32 lines, created and expiring at
most five minutes apart. The caller writes no part of it. The owner's device signs an
`Approval`: the id, the SHA-256 of the summary's canonical bytes (domain
`approval-summary/v1`), the device and the time, signed under the domain `approval/v1` with
the node, owner and record. The node accepts it when the id and hash are those of the summary
it built, the device is a known device of the owner, and it was issued while the summary was
open. `approve` in the `client` crate refuses a summary of another node or one that lapsed.

## Operations that wait

An operation waits for the owner at an `await`, or before it sends anything when it needs
the owner's approval. The node then keeps it **in memory only**: the opened fields, the
temporary values, the last response, under a random 16-byte id, for at most five minutes.
Nothing of it is written anywhere or handed back. It is dropped when it lapses, when the
owner revokes the node's grant and when the node restarts. A node keeps at most 8 waiting
operations per owner, 256 in all and 128 MiB of their values; an operation that may wait is
refused (`parked_full`, HTTP 429) before it sends anything when there is no room.

The caller gets, as the `ok` of `POST /call` (`Output::Pending`):

```text
{"kind": "challenge", "id": "<base64url>", "challenge": "sms", "hint": "...", "expires_ms": ...}
{"kind": "approval_required", "id": "<base64url>", "summary": {...}}
```

and resumes with a call of the **same caller, record and operation** whose body is
`{"kind": "resume", "id": "<base64url>"}` (`Body::resume`, `sign_resume_call` in the `client`
crate), signed like any call. While the operation still waits, the node answers with the same
pending reply. An id is taken only from the caller that started the operation, on the record
it was left with (the one the node sealed before it waited, if it sealed one): for anyone
else, and once the operation went on, lapsed or was dropped, the node answers
`parked_unknown`, the same as for an id nobody parked.

The owner's device acts on it, never the caller:

- **A code**: `DeviceKey::answer_challenge` (`answer_challenge` in the `client` crate) signs
  the node, owner, id, the SHA-256 of the code, the device and the time (domain `answer/v1`)
  and seals all of it with the code to the node (HPKE, as a grant). `POST /answer` takes it
  when a known device of the owner signed it, after the challenge opened, for a challenge
  that waits for a code, and the code matches the pattern; once. The log records an `answer`
  entry (operation and device), never the code.
- **An approval**: an `Approval` of the summary the node built (`POST /approve`, see
  [Approvals](#approvals)). The log records an `approve` entry with the summary's SHA-256.

### Approvals at run time

An operation waits for approval before it sends anything when:

- the operation says `"approval": true`;
- the item's kind says so: every use of a `card` waits (`"approval": true` in its shape),
  whatever the policy or the spending limits say;
- it declares a `payment` that no spending limit of the record covers, or that is above one.

The node builds the summary: the destination of the first request, the origin (the
merchant: `https://host[:port]` of that destination, else the item's origin), the amount and
currency of the payment, the item's `describe` view, and lines the node writes itself (why it
waits). Nothing in it comes from the caller as text. An approval is for that summary only:
another amount, another id, or the same approval again is refused.

### Payments and spending limits

```json
{"name": "charge",
 "payment": {"amount": {"from": "query", "name": "amount"}, "currency": "EUR", "exponent": 2},
 "steps": [
   {"do": "open", "connection": "https", "destinations": [{"host": "pay.example", "port": 443}]},
   {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/v1/charges"],
                              "query": [{"name": "amount", "required": true, "min": "1", "max": "500000"}]},
    "inject": [{"target": {"kind": "header", "name": "Authorization"}, "template": "Bearer {{key}}"}]},
   {"do": "return"}
 ]}
```

`payment` says how much the operation pays, as an integer of minor units (`exponent` digits
after the point: 2 for EUR, 0 for JPY, at most 8) of `currency` (an ISO 4217 code the policy
fixes). The amount comes only from a value the contract checked:

| `amount` | Where |
| --- | --- |
| `{"from": "query", "name": "amount"}` | A query parameter of the caller's request whose rule is `required` with `min` (at least 0) and `max` (at most 10^18). |
| `{"from": "input", "pointer": "/amount"}` | A member of the checked JSON input that is a required `number` with `min` and `max`, not `set`. |
| `{"from": "fixed", "value": "500"}` | A decimal integer the policy states. |

At run time a value that is not a decimal integer (`12.5`, `1e3`), or a parameter given twice,
is refused before anything happens.

The owner's device signs **spending limits** for one record on one node
(`DeviceKey::sign_limits`, `sign_limits` in the `client` crate; `POST /limits`):

```text
{"node": "...", "owner": "alice", "record_id": "card",
 "rules": [{"currency": "EUR", "per_payment": "50", "per_day": "100", "per_month": "500"},
           {"currency": "EUR", "merchant": "https://shop.example", "per_day": "20"}],
 "device": "...", "issued_ms": ..., "signature": "..."}
```

Each rule bounds one currency, at one merchant (an exact origin) or at any, with at most a
decimal `per_payment`, `per_day` (the last 24 hours) and `per_month` (the last 30 days). A
node takes them from a known device of the owner, issued within five minutes of its clock and
after the limits it holds; they replace those. Before an operation with a `payment` sends
anything, the node checks the amount against every rule that applies, with the payments it
counted. Within all of them (and at least one applies), the payment is counted at once,
under the same lock as the check, so payments made together cannot each fit a limit they
exceed together; otherwise the operation waits for approval, and the payment is counted when
it goes on. Limits and payments are written to the log sealed under a key only the node
derives from its own key (`limits` and `spend` entries), so a restarted node counts them again
and the log store reads neither amounts nor merchants. A node remembers at most 4096 payments
of a record within 30 days; beyond, every payment waits.

### Sessions

```json
{"name": "session", "secret": true, "optional": true,
 "session": {"lifetime_ms": 3600000, "expires": "session_expires",
             "renew": {"by": "operation", "name": "login"}}}
```

A secret field that holds a session the node obtains. When a `receive` captures into it, the
node writes `now + lifetime_ms` (at most 30 days) into the field `expires` (public, optional,
with no session of its own) and seals both into the new record, as any capture. Before an
operation reads the session, the node checks its expiry; when it lapsed (or there is none):

- `{"by": "operation", "name": "login"}`: the node runs that operation of the policy first
  (HTTPS, a fixed request only, no `await`, `payment` or approval; it captures into the
  session and does not read it; a login with the stored password), then the operation asked
  for, with the new session;
- `{"by": "owner"}`: the node refuses with `session_expired`; the owner logs in on the
  device and seals the new session with `Record::update` (`update_record` in the `client`
  crate), which writes its expiry too, one generation later.

### Vending

```json
{"name": "mint",
 "vend": {"lifetime_ms": 3600000,
          "expires": {"source": {"from": "json", "pointer": "/expires_in"}, "format": "seconds"}},
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "sts.example.com", "port": 443}]},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/token"},
   "inject": [{"target": {"kind": "header", "name": "Authorization"}, "template": "Bearer {{access_token}}"},
              {"target": {"kind": "body"}, "template": "scope=read&duration=900"}]},
  {"do": "return", "response": {"body": {"json": ["/token", "/expires_in"]}}}]}
```

An operation whose output is a credential the secret mints: a short-lived token of a token
service, a signed URL, a token the node signs itself. The caller keeps what it gets, so the
node bounds it: the credential must expire within `lifetime_ms` (1 second to 12 hours).

- **HTTPS**: the requests are fixed by the policy (no caller contract: the caller chooses no
  scope and no lifetime); the expiry is read from the response by a capture source (`json`,
  `header`, `regex`, …, not `all`), and the operation returns declared JSON members only.
  After the response, before anything goes back, the node reads the expiry in `format`
  (`unix` seconds, `unix_ms`, `rfc3339`, or `seconds` from now) and checks it is at most
  `now + lifetime_ms + 60 s` (clock allowance). An expiry that is missing, unreadable or too
  late refuses the call with `vend_refused`, and the response never leaves the node.
- **No connection**: the expiry is a member of the operation's JSON input that the node
  `set`s (`unix` or `unix_ms`, the format's unit) with an `offset` at most `lifetime_ms`,
  checked when the policy is signed; the output template reads `$input`, the checked input
  that holds it. Whatever the caller sends in that member is overwritten.

A vend is logged (`vend`, with the expiry) under the owner. A summary flags `vend`, and a
new version that makes the lifetime longer or reads the expiry elsewhere counts as wider.

### Delegation and emergency access

An owner can let another owner's callers use one record, without handing over the record key
or the values (`docs/design.md`, section 8b). A device of the owner signs a `Delegation`
(`client::delegate`, `POST /delegate` with the record):

- **the delegated policy**: the record's policy or narrower, signed by the same device. It
  declares the same fields and item binding; every operation it has is one the record's
  policy has, no wider (the [summary diff](#summaries-and-risk-flags) against the record's
  policy finds nothing wider); it captures into no field (a delegate never seals a new
  generation of the owner's record); its callers are the delegate's. A delegate's call
  names the delegation's id (signed with the call) and runs under this policy only; its
  log entries carry the caller as `delegate/caller`, under the owner, and the call costs the
  owner's rate limits like any;
- **the record's policy, by hash**: if the owner changes the record's policy, the
  delegation no longer holds (`delegation_unknown`), and the owner delegates again;
- **the record and log keys, sealed to the node** (HPKE), so the node runs a delegated call
  even while the owner holds no grant — which emergency access needs;
- **a lifetime** of at most 366 days, and a **waiting period**: 0, or 1 hour to 90 days for
  emergency access. The delegate's first call starts the wait (an `access_request` entry
  under both owners) and is refused with `delegation_waiting` and the time it opens; a
  device of the owner can cancel the request meanwhile (`client::change_delegation`,
  `cancel`, `POST /delegation/change`), and the next call waits the whole period again.

A device ends a delegation with `revoke`; a revocation of the owner's grant ends all of its
delegations; a delegation whose device the node no longer knows stops working. At most 16
delegations per record and 64 per owner. Delegations survive a restart (the log keeps them
sealed under the node's state key) but not a hand-over to a successor: the record key is
sealed to this node, so the owner delegates again on the new one.

### Next

Reading a code from a `mail` item of the owner, `await` on TLS, and amounts read from a
request body contract are not done yet.

## Worked examples: signing and encryption schemes

The schemes below are policies over the existing functions and steps, with no code for any
scheme. Each operation here is the one `crates/engine/tests/schemes.rs` reads from this file,
signs, runs in-process against a fake server and checks against the scheme's published
examples or a verifier written in the test (results and test names: `docs/design.md`,
section 11). Field names: `key` is a private key (a raw P-256 scalar for ES256, a PEM block for
RSA), `secret` a shared key, `access_token`, `refresh_token`, `card_number` and
`web_session` secrets, `client_id`, `user`, `server_key` (an RSA public key, PEM) and `recipient`
(a P-256 public key, SEC1) public.

A public key a header must carry (a JWK) comes from the private key: `hpke_public("p256",
key)` is the SEC1 point of a raw P-256 scalar, so `x` and `y` are its bytes 1 to 32 and 33 to
64. A JSON header is written as text around `{{ }}` in a `compute`, which needs one level of
escaping in JSON instead of three.

### DPoP (RFC 9449)

A refresh at the token endpoint with a DPoP proof, retried with the server's nonce. The proof
is an ES256 JWT over `jti` (`$nonce`, new for every request), `htm`, `htu`, `iat` and, on the
retry, `nonce`; the new tokens are sealed into the record.

```json
{"name": "dpop-token",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "auth.example.com", "port": 443}]},
  {"do": "compute", "into": "dpop_header", "template": "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"1\", \"32\")) }}\",\"y\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"33\", \"32\")) }}\"}}"},
  {"do": "compute", "into": "dpop_head", "template": "{{ b64urlraw(dpop_header) }}"},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/token"},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/x-www-form-urlencoded"},
    {"target": {"kind": "header", "name": "DPoP"}, "template": "{{ dpop_head + \".\" + b64urlraw(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix)) + \".\" + b64urlraw(p256_sign(key, dpop_head + \".\" + b64urlraw(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix)))) }}"},
    {"target": {"kind": "body"}, "template": "grant_type=refresh_token&client_id={{ pct(client_id) }}&refresh_token={{ pct(refresh_token) }}"}]},
  {"do": "receive", "capture": [{"source": {"from": "header", "name": "DPoP-Nonce"}, "into": {"kind": "temp", "name": "dpop_nonce", "secret": false}}]},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/token"},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/x-www-form-urlencoded"},
    {"target": {"kind": "header", "name": "DPoP"}, "template": "{{ dpop_head + \".\" + b64urlraw(json_set(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix), \"nonce\", dpop_nonce)) + \".\" + b64urlraw(p256_sign(key, dpop_head + \".\" + b64urlraw(json_set(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix), \"nonce\", dpop_nonce)))) }}"},
    {"target": {"kind": "body"}, "template": "grant_type=refresh_token&client_id={{ pct(client_id) }}&refresh_token={{ pct(refresh_token) }}"}]},
  {"do": "receive", "capture": [
    {"source": {"from": "json", "pointer": "/access_token"}, "into": {"kind": "field", "name": "access_token"}},
    {"source": {"from": "json", "pointer": "/refresh_token"}, "into": {"kind": "field", "name": "refresh_token"}}]},
  {"do": "return", "response": {"body": {"json": ["/token_type", "/expires_in"]}}}
 ]}
```

A resource request with the bound token adds `ath`, the SHA-256 of the token. `ath` is a
hash of a secret alone, so it stays *tainted* (rule 3): it is the **last** member, because
`json_set` refuses a tainted object meeting a controlled value (rule 2), and the server's
`nonce` is controlled. The caller's request (GET only, so the retry repeats nothing that
changes state) goes once without a nonce and once with the one the server answered:

```json
{"name": "dpop-call",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
  {"do": "compute", "into": "dpop_header", "template": "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"1\", \"32\")) }}\",\"y\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"33\", \"32\")) }}\"}}"},
  {"do": "compute", "into": "dpop_head", "template": "{{ b64urlraw(dpop_header) }}"},
  {"do": "send", "request": {"from": "caller", "methods": ["GET"], "paths": ["/v1/**"]},
   "inject": [
    {"target": {"kind": "header", "name": "Authorization"}, "template": "DPoP {{ access_token }}"},
    {"target": {"kind": "header", "name": "DPoP"}, "template": "{{ dpop_head + \".\" + b64urlraw(json_set(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix), \"ath\", b64urlraw(sha256(access_token)))) + \".\" + b64urlraw(p256_sign(key, dpop_head + \".\" + b64urlraw(json_set(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix), \"ath\", b64urlraw(sha256(access_token)))))) }}"}]},
  {"do": "receive", "capture": [{"source": {"from": "header", "name": "DPoP-Nonce"}, "into": {"kind": "temp", "name": "dpop_nonce", "secret": false}}]},
  {"do": "send", "request": {"from": "caller", "methods": ["GET"], "paths": ["/v1/**"]},
   "inject": [
    {"target": {"kind": "header", "name": "Authorization"}, "template": "DPoP {{ access_token }}"},
    {"target": {"kind": "header", "name": "DPoP"}, "template": "{{ dpop_head + \".\" + b64urlraw(json_set(json_set(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix), \"nonce\", dpop_nonce), \"ath\", b64urlraw(sha256(access_token)))) + \".\" + b64urlraw(p256_sign(key, dpop_head + \".\" + b64urlraw(json_set(json_set(json_set_number(json_set(json_set(json_set(\"{}\", \"jti\", $nonce), \"htm\", $method), \"htu\", \"https://\" + $host + $pathname), \"iat\", $unix), \"nonce\", dpop_nonce), \"ath\", b64urlraw(sha256(access_token)))))) }}"}]},
  {"do": "return", "response": {"body": "all"}}
 ]}
```

Without `if` the retry is unconditional: it is right for a server that always asks for a
nonce first. A server that accepts the first proof sends no `DPoP-Nonce`, the capture
fails, and the call fails; a retry only on `use_dpop_nonce` waits for `if`
([Loops and branches](#loops-and-branches)).

### HTTP Message Signatures (RFC 9421)

The caller's request signed over `@method`, `@authority`, `@path`, `@query` and
`Content-Digest` (RFC 9530) of its body. The signature base, unescaped:

```text
"@method": {{$method}}
"@authority": {{$host}}
"@path": {{$pathname}}
"@query": ?{{$query}}
"content-digest": sha-256=:{{ b64(sha256($body)) }}:
"@signature-params": {{sig_params}}
```

```json
{"name": "signed-call",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
  {"do": "compute", "into": "sig_params", "template": "(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created={{ $unix }};keyid=\"client-1\";alg=\"ed25519\""},
  {"do": "send", "request": {"from": "caller", "methods": ["GET", "POST"], "paths": ["/v1/**"],
                             "query": [{"name": "page", "pattern": "[0-9]{1,4}"}]},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Digest"}, "template": "sha-256=:{{ b64(sha256($body)) }}:"},
    {"target": {"kind": "header", "name": "Signature-Input"}, "template": "sig1={{ sig_params }}"},
    {"target": {"kind": "header", "name": "Signature"}, "template": "sig1=:{{ b64(ed25519_sign(key, \"\\\"@method\\\": \" + $method + \"\\n\\\"@authority\\\": \" + $host + \"\\n\\\"@path\\\": \" + $pathname + \"\\n\\\"@query\\\": ?\" + $query + \"\\n\\\"content-digest\\\": sha-256=:\" + b64(sha256($body)) + \":\\n\\\"@signature-params\\\": \" + sig_params)) }}:"}]},
  {"do": "return", "response": {"body": "all"}}
 ]}
```

The other algorithms change the function and `alg`: `ecdsa-p256-sha256` is
`p256_sign(key, ...)` (`r || s`, as RFC 9421 section 3.3.4 asks), `rsa-pss-sha512` is
`rsa_sign_pss("sha512", pem(key), ...)` (salt of 64 bytes), `hmac-sha256` is
`hmac_sha256(secret, ...)`. `@authority` is `$host` because the destination's port is 443;
`$authority` adds any other port. A header field the policy injects can be covered
(`content-digest` here, or a `Date` from `time($unix, ...)`), and so can a header the
**caller** sets, with `$header("name")` for a header the contract lists
([Request components, AEAD parts and public keys](#request-components-aead-parts-and-public-keys)).

### Hawk

The `Authorization: Hawk` header over the request and a payload hash. The policy fixes the
content type, which the payload hash covers, and the port (`443`); `hawk-call-headers` below
reads both from the request instead (`$header("content-type")`, `$port`):

```json
{"name": "hawk-call",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
  {"do": "send", "request": {"from": "caller", "methods": ["GET", "POST"], "paths": ["/v1/**"]},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/json"},
    {"target": {"kind": "header", "name": "Authorization"}, "template": "Hawk id=\"{{ user }}\", ts=\"{{ $unix }}\", nonce=\"{{ $nonce }}\", hash=\"{{ b64(sha256(\"hawk.1.payload\\napplication/json\\n\" + $body + \"\\n\")) }}\", mac=\"{{ b64(hmac_sha256(secret, \"hawk.1.header\\n\" + $unix + \"\\n\" + $nonce + \"\\n\" + $method + \"\\n\" + $path + \"\\n\" + $host + \"\\n443\\n\" + b64(sha256(\"hawk.1.payload\\napplication/json\\n\" + $body + \"\\n\")) + \"\\n\\n\")) }}\""}]},
  {"do": "return", "response": {"body": "all"}}
 ]}
```

### ACME (RFC 8555) and JWS

A new account: a nonce from `newNonce`, then the caller's payload in a flattened JWS with the
account key as `jwk`:

```json
{"name": "acme-new-account",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "acme.example.com", "port": 443}]},
  {"do": "compute", "into": "acme_jwk", "template": "{\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"1\", \"32\")) }}\",\"y\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"33\", \"32\")) }}\"}}"},
  {"do": "send", "request": {"from": "fixed", "method": "HEAD", "path": "/acme/new-nonce"}},
  {"do": "receive", "capture": [{"source": {"from": "header", "name": "Replay-Nonce"}, "into": {"kind": "temp", "name": "nonce1", "secret": false}}]},
  {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/acme/new-account"]},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/jose+json"},
    {"target": {"kind": "body"}, "template": "{\"protected\":\"{{ b64urlraw(json_set(json_set(acme_jwk, \"nonce\", nonce1), \"url\", \"https://\" + $host + $pathname)) }}\",\"payload\":\"{{ b64urlraw($body) }}\",\"signature\":\"{{ b64urlraw(p256_sign(key, b64urlraw(json_set(json_set(acme_jwk, \"nonce\", nonce1), \"url\", \"https://\" + $host + $pathname)) + \".\" + b64urlraw($body))) }}\"}"}]},
  {"do": "return", "response": {"headers": ["Location", "Replay-Nonce"], "body": "all"}}
 ]}
```

Every later request is signed with `kid`, the account URL. The operation finds it by key
(`onlyReturnExisting`, RFC 8555 section 7.3.1), so nothing is stored between calls; each
request takes the nonce of the response before it:

```json
{"name": "acme-call",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "acme.example.com", "port": 443}]},
  {"do": "compute", "into": "acme_jwk", "template": "{\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"1\", \"32\")) }}\",\"y\":\"{{ b64urlraw(slice(hpke_public(\"p256\", key), \"33\", \"32\")) }}\"}}"},
  {"do": "send", "request": {"from": "fixed", "method": "HEAD", "path": "/acme/new-nonce"}},
  {"do": "receive", "capture": [{"source": {"from": "header", "name": "Replay-Nonce"}, "into": {"kind": "temp", "name": "nonce1", "secret": false}}]},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/acme/new-account"},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/jose+json"},
    {"target": {"kind": "body"}, "template": "{\"protected\":\"{{ b64urlraw(json_set(json_set(acme_jwk, \"nonce\", nonce1), \"url\", \"https://\" + $host + $pathname)) }}\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"{{ b64urlraw(p256_sign(key, b64urlraw(json_set(json_set(acme_jwk, \"nonce\", nonce1), \"url\", \"https://\" + $host + $pathname)) + \".eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\")) }}\"}"}]},
  {"do": "receive", "capture": [
    {"source": {"from": "header", "name": "Location"}, "into": {"kind": "temp", "name": "kid", "secret": false}},
    {"source": {"from": "header", "name": "Replay-Nonce"}, "into": {"kind": "temp", "name": "nonce2", "secret": false}}]},
  {"do": "send", "request": {"from": "caller", "methods": ["POST"],
                             "paths": ["/acme/new-order", "/acme/order/*", "/acme/authz/*", "/acme/chall/*", "/acme/finalize/*", "/acme/cert/*"]},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/jose+json"},
    {"target": {"kind": "body"}, "template": "{\"protected\":\"{{ b64urlraw(json_set(json_set(json_set(json_set(\"{}\", \"alg\", \"ES256\"), \"kid\", kid), \"nonce\", nonce2), \"url\", \"https://\" + $host + $pathname)) }}\",\"payload\":\"{{ b64urlraw($body) }}\",\"signature\":\"{{ b64urlraw(p256_sign(key, b64urlraw(json_set(json_set(json_set(json_set(\"{}\", \"alg\", \"ES256\"), \"kid\", kid), \"nonce\", nonce2), \"url\", \"https://\" + $host + $pathname)) + \".\" + b64urlraw($body))) }}\"}"}]},
  {"do": "return", "response": {"headers": ["Location", "Replay-Nonce"], "body": "all"}}
 ]}
```

`eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9` is `{"onlyReturnExisting":true}`; an empty caller
body is a POST-as-GET (an empty `payload`). Other JWS algorithms change the signature
function: `p384_sign` (ES384), `ed25519_sign` (EdDSA, its JWK `x` from
`ed25519_public(key)`), `rsa_sign_pkcs1("sha256", ...)` (RS256),
`rsa_sign_pss` (PS256 to PS512), `hmac_sha256` (HS256).

### JWE (RFC 7516)

A card number sealed into a compact JWE for the server's RSA key, RSA-OAEP-256 with
A256GCM. The content key and IV are computed once, so the key the server unwraps is the one
that encrypted; the AAD is the encoded header (RFC 7516 section 5.1, step 14):

```json
{"name": "jwe-rsa",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
  {"do": "compute", "into": "cek", "template": "{{ random(\"32\") }}"},
  {"do": "compute", "into": "iv", "template": "{{ random(\"12\") }}"},
  {"do": "compute", "into": "head", "template": "{{ b64urlraw(json_set(json_set(\"{}\", \"alg\", \"RSA-OAEP-256\"), \"enc\", \"A256GCM\")) }}"},
  {"do": "compute", "into": "plaintext", "template": "{{ json_set(\"{}\", \"number\", card_number) }}"},
  {"do": "compute", "into": "sealed", "template": "{{ aes_gcm_encrypt(cek, iv, plaintext, head) }}"},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/v1/cards"},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/json"},
    {"target": {"kind": "body"}, "template": "{\"card\":\"{{ head + \".\" + b64urlraw(rsa_encrypt_oaep(\"sha256\", pem(server_key), cek)) + \".\" + b64urlraw(iv) + \".\" + b64urlraw(slice(sealed, \"0\", len(plaintext))) + \".\" + b64urlraw(slice(sealed, len(plaintext), \"16\")) }}\"}"}]},
  {"do": "return", "response": {"body": {"json": ["/token"]}}}
 ]}
```

ECDH-ES+A128KW with A128GCM: the operation's ephemeral P-256 key is the `epk`, Concat KDF
(RFC 7518 section 4.6.2, no `apu` or `apv`) gives the key that wraps the content key:

```json
{"name": "jwe-ecdh",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
  {"do": "compute", "into": "cek", "template": "{{ random(\"16\") }}"},
  {"do": "compute", "into": "iv", "template": "{{ random(\"12\") }}"},
  {"do": "compute", "into": "header", "template": "{\"alg\":\"ECDH-ES+A128KW\",\"enc\":\"A128GCM\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{{ b64urlraw(slice(ecdh_public(\"p256\"), \"1\", \"32\")) }}\",\"y\":\"{{ b64urlraw(slice(ecdh_public(\"p256\"), \"33\", \"32\")) }}\"}}"},
  {"do": "compute", "into": "head", "template": "{{ b64urlraw(header) }}"},
  {"do": "compute", "into": "kek", "template": "{{ concat_kdf(\"sha256\", ecdh(\"p256\", recipient), be32(len(\"ECDH-ES+A128KW\")) + \"ECDH-ES+A128KW\" + be32(\"0\") + be32(\"0\") + be32(\"128\"), \"16\") }}"},
  {"do": "compute", "into": "plaintext", "template": "{{ json_set(\"{}\", \"number\", card_number) }}"},
  {"do": "compute", "into": "sealed", "template": "{{ aes_gcm_encrypt(cek, iv, plaintext, head) }}"},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/v1/cards"},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/json"},
    {"target": {"kind": "body"}, "template": "{\"card\":\"{{ head + \".\" + b64urlraw(aes_kw_wrap(kek, cek)) + \".\" + b64urlraw(iv) + \".\" + b64urlraw(slice(sealed, \"0\", len(plaintext))) + \".\" + b64urlraw(slice(sealed, len(plaintext), \"16\")) }}\"}"}]},
  {"do": "return", "response": {"body": {"json": ["/token"]}}}
 ]}
```

`dir` with A256GCM under a shared key the caller never sees, over the caller's own body (the
IV is the request's `$nonce`, the same in every place of one request):

```json
{"name": "jwe-dir",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
  {"do": "compute", "into": "head", "template": "{{ b64urlraw(json_set(json_set(\"{}\", \"alg\", \"dir\"), \"enc\", \"A256GCM\")) }}"},
  {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/v1/messages"]},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/jose"},
    {"target": {"kind": "body"}, "template": "{{ head + \"..\" + b64urlraw(slice(hexdecode($nonce), \"0\", \"12\")) + \".\" + b64urlraw(slice(aes_gcm_encrypt(secret, slice(hexdecode($nonce), \"0\", \"12\"), $body, head), \"0\", len($body))) + \".\" + b64urlraw(slice(aes_gcm_encrypt(secret, slice(hexdecode($nonce), \"0\", \"12\"), $body, head), len($body), \"16\")) }}"}]},
  {"do": "return", "response": {"body": "all"}}
 ]}
```

A plaintext that mixes the caller's bytes with a secret (`json_set($body, "number",
card_number)`) is refused: the ciphertext is then both tainted and controlled, and `slice`
cuts no such value (rule 2), so the ciphertext and the tag cannot be separated by it. Such a
JWE takes `aead_ciphertext` and `aead_tag` instead (`jwe-mixed` in
[Request components, AEAD parts and public keys](#request-components-aead-parts-and-public-keys)).

### Client authentication by JWT (RFC 7523)

`private_key_jwt`: a client credentials grant with an RS256 assertion; the access token is
sealed into the record and never returned:

```json
{"name": "client-assertion",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "auth.example.com", "port": 443}]},
  {"do": "compute", "into": "assertion_head", "template": "{{ b64urlraw(json_set(json_set(\"{}\", \"alg\", \"RS256\"), \"typ\", \"JWT\")) }}"},
  {"do": "compute", "into": "assertion_claims", "template": "{{ b64urlraw(json_set_number(json_set_number(json_set(json_set(json_set(json_set(\"{}\", \"iss\", client_id), \"sub\", client_id), \"aud\", \"https://auth.example.com/oauth2/token\"), \"jti\", $nonce), \"iat\", $unix), \"exp\", add($unix, \"300\"))) }}"},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/oauth2/token"},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/x-www-form-urlencoded"},
    {"target": {"kind": "body"}, "template": "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={{ assertion_head + \".\" + assertion_claims + \".\" + b64urlraw(rsa_sign_pkcs1(\"sha256\", pem(key), assertion_head + \".\" + assertion_claims)) }}"}]},
  {"do": "receive", "capture": [{"source": {"from": "json", "pointer": "/access_token"}, "into": {"kind": "field", "name": "access_token"}}]},
  {"do": "return", "response": {"body": {"json": ["/token_type", "/expires_in"]}}}
 ]}
```

`client_secret_jwt` is the same operation with `"alg"` `HS256` and
`hmac_sha256(secret, assertion_head + "." + assertion_claims)` as the signature.

### SAML login through the identity provider's form

The node as the user's browser: the service provider's redirect, the identity provider's
login form (its CSRF token read by `html`), the auto-posting form that carries the
`SAMLResponse` (captured as a secret temporary), and the service provider's session cookie
sealed into the record. `regex` reads bodies only, so the parameters of the redirect's
`Location` are cut with `between`, in the order the service provider writes them:

```json
{"name": "saml-login",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "sp.example.com", "port": 443}, {"host": "idp.example.com", "port": 443}]},
  {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/login", "destination": {"host": "sp.example.com", "port": 443}}},
  {"do": "receive", "capture": [{"source": {"from": "header", "name": "Location"}, "into": {"kind": "temp", "name": "sso_url", "secret": false}}]},
  {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/sso", "destination": {"host": "idp.example.com", "port": 443}},
   "inject": [
    {"target": {"kind": "query", "name": "SAMLRequest"}, "template": "{{ pctdecode(between(sso_url, \"SAMLRequest=\", \"&\")) }}"},
    {"target": {"kind": "query", "name": "RelayState"}, "template": "{{ pctdecode(between(sso_url, \"RelayState=\", \"\")) }}"}]},
  {"do": "receive", "capture": [
    {"source": {"from": "html", "selector": "input[name=csrf]", "attribute": "value"}, "into": {"kind": "temp", "name": "csrf", "secret": false}},
    {"source": {"from": "cookie", "name": "idp"}, "into": {"kind": "temp", "name": "idp_cookie", "secret": true}}]},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/login", "destination": {"host": "idp.example.com", "port": 443}},
   "inject": [
    {"target": {"kind": "header", "name": "Cookie"}, "template": "idp={{ idp_cookie }}"},
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/x-www-form-urlencoded"},
    {"target": {"kind": "body"}, "template": "username={{ pct(user) }}&password={{ pct(password) }}&csrf={{ pct(csrf) }}"}]},
  {"do": "receive", "capture": [
    {"source": {"from": "html", "selector": "input[name=SAMLResponse]", "attribute": "value"}, "into": {"kind": "temp", "name": "saml_response", "secret": true}},
    {"source": {"from": "html", "selector": "input[name=RelayState]", "attribute": "value"}, "into": {"kind": "temp", "name": "relay_back", "secret": false}}]},
  {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/acs", "destination": {"host": "sp.example.com", "port": 443}},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/x-www-form-urlencoded"},
    {"target": {"kind": "body"}, "template": "SAMLResponse={{ pct(saml_response) }}&RelayState={{ pct(relay_back) }}"}]},
  {"do": "receive", "capture": [{"source": {"from": "cookie", "name": "sp_session"}, "into": {"kind": "field", "name": "web_session"}}]},
  {"do": "return"}
 ]}
```

An OpenID Connect login through a form is the same steps, with the authorization code
captured from the redirect and redeemed by `client-assertion`'s request. Signing a SAML
message as a service provider is not covered: the HTTP-Redirect binding DEFLATEs the message
and the POST binding signs XML after Exclusive XML Canonicalization, and neither family is a
function.

## Converting a policy

`credentials policy upgrade old.json --out new.json` (or
`engine::policy::legacy::upgrade_json`, or `upgrade_policy` of the `client` crate) reads a
policy of the old format, signed or not, and writes the step language, with notes (on stderr)
for what it narrowed:

| Old | New |
| --- | --- |
| `{"kind": "http", destinations, methods, paths, caller_headers, identity, steps}` | `open` (https) with the destinations and identity; for each step a `send` (the caller's request with `methods`, the paths as templates and `caller_headers` as `headers`, or the fixed request) and, when it captures, a `receive`; then `{"do": "return"}`. |
| `{"kind": "stream", destinations, identity, script}` | `open` (tls); `send` for each script `send`, `receive` for each `expect`; then `{"do": "return"}` (no relay). |
| `{"kind": "derive", template}` | `{"do": "return", "template": ...}`, with `"input": {"raw": {}}` when the template reads `$input`. |

The result returns the status only, takes no caller query parameter, relays no stream
exchange and accepts any input where it did before (flagged). A caller path parameter that
the old format let the caller place anywhere has to be written by the owner as a `{name}`
segment of a template: until then the converted policy does not validate. Read the summary,
widen what is needed, and **sign the result again**.

## Templates

`{{ ... }}` holds one expression: a name, a `$variable`, a `"string"` (escapes `\n \r \t \0 \" \\`),
a function call, or several joined with `+`. Text outside `{{ }}` is copied, so JSON bodies
with nested braces work. A template is at most 8 KiB, 512 nodes and 24 levels deep.

| Variable | Value | Where |
| --- | --- | --- |
| `$method` `$host` `$path` `$pathname` `$query` `$body` | The request being built | HTTPS `send` injections |
| `$unix` `$unix_ms` | The node's clock | everywhere |
| `$nonce` | 32 random hex characters, the same throughout one request (or TLS send, or operation with no connection) | everywhere |
| `$boundary` | A random multipart boundary | HTTPS `send` injections |
| `$input` | The caller's input, after its schema | operations with no connection |
| `$port` `$scheme` `$authority` `$target_uri` | The destination port in decimal; `https`; the host in lowercase, then `:` and the port unless it is 443 (RFC 9421 `@authority`); `https://` + `$authority` + `$path` (`@target-uri`) | HTTPS `send` injections |
| `$header("name")` | The caller's header of that name (case does not matter), as RFC 9110 section 5.3 combines field lines: each value without the spaces and tabs around it, joined by `, `; empty when the caller sent none | HTTPS `send` injections of a `send` that takes the caller's request, for a header its contract lists |
| `$query_param("name")` | The caller's query parameter as RFC 9421 section 2.2.8 (`@query-param`) normalizes it: parsed as `application/x-www-form-urlencoded` (`+` is a space) and percent-encoded again, so a space is `%20`; the name is written encoded the same way; empty when absent | as `$header`, for a parameter its contract lists |

TLS sends and identities can read `$host`, `$unix`, `$unix_ms` and `$nonce`; `compute` on a
connection reads `$unix`, `$unix_ms` and `$nonce`, and with no connection what the `return`
reads.

| Group | Functions |
| --- | --- |
| Encoding | `b64` `b64raw` `b64url` `b64urlraw` `b64decode` `b32decode` `hex` `hexdecode` `pct` `pctdecode` `json` `pem` |
| Text | `upper` `lower` `trim` `replace(text, from, to)` `json_set(object, key, value)` `json_set_number(object, key, integer)` `canonical_query` `time(unix, format)` `len` `xor(a, b)` `slice(value, start, length)` `between(value, start, end)` |
| Numbers | `add(a, b)` (signed 64-bit decimal); fixed-width encoders of a decimal number: `u8`, `be16` `be32` `be64`, `le16` `le32` `le64` |
| Random | `random(n)`: n fresh bytes (1 to 1024), new at every call |
| Hash and MAC | `md4` `md5` `sha1` `sha256` `sha384` `sha512` `sha512_256` `keccak256` `sha3_224` `sha3_256` `sha3_384` `sha3_512` `shake128(msg, length)` `shake256(msg, length)` `turboshake128(msg, domain, length)` `turboshake256(msg, domain, length)` `kt128(msg, customization, length)` `kt256(msg, customization, length)` `hmac_md5(key, msg)` `hmac_sha1` `hmac_sha256` `hmac_sha384` `hmac_sha512` `aes_cmac(key, msg)` `aes_cbc_mac(key, msg)` `pbkdf2(hash, password, salt, rounds[, length])` `pbkdf2_sha256(password, salt, rounds[, length])` `totp(seed[, digits[, period]])` |
| Key derivation | `hkdf(hash, ikm, salt, info, length)` `hkdf_expand(hash, prk, info, length)` `concat_kdf(hash, z, other_info, length)` `kbkdf_counter(hash, key, fixed_input, length)` `nfold(value, bits)` `kerberos_dk(key, constant)` |
| Signature | `ed25519_sign(key, msg)` `ed448_sign(key, msg[, context])` `p256_sign` `p256_sign_der` `p384_sign` `p521_sign` `k256_sign` `k256_sign_recoverable(key, digest32)` `ecdsa_sign_prehash(curve, key, digest)` `rsa_sign_pkcs1(hash, key, msg)` `rsa_sign_pss(hash, key, msg)` `rsa_sign_pkcs1_sha256(key, msg)` `rsa_sign_pss_sha256(key, msg)` `dsa_sign(hash, key, msg)` `dsa_sign_der(hash, key, msg)` `mldsa_sign(level, seed, msg[, context])` `mldsa_public(level, seed)` `sm2_sign(key, msg[, id])` |
| Key agreement | `ecdh(curve, peer_public[, private])` `ecdh_public(curve)` |
| HPKE (RFC 9180) | `hpke_seal(suite, mode, recipient_public, info, aad, plaintext[, psk, psk_id][, sender_private])` `hpke_open(suite, mode, recipient_private, enc, info, aad, ciphertext[, psk, psk_id][, sender_public])` `hpke_export(suite, mode, recipient_public, info, context, length[, ...])` `hpke_receiver_export(suite, mode, recipient_private, enc, info, context, length[, ...])` `hpke_public(kem, private)` `hpke_derive_key(kem, ikm)` |
| TLS channel binding | `tls_exporter(label, context, length)` (only in a TLS `send`) |
| Encryption | `aes_gcm_encrypt(key, nonce12, msg[, aad])` `aes_cbc_encrypt(key, iv16, msg)` `aes_cbc_hmac_encrypt(key, iv16, msg[, aad])` `aes_ccm_encrypt(key, nonce, tag_length, msg[, aad])` `aes_eax_encrypt(key, nonce16, msg[, aad])` `aes_cts_encrypt(key, iv16, msg)` `chacha20_poly1305_encrypt(key32, nonce12, msg[, aad])` `rsa_encrypt_oaep(hash, public_key, msg)` `rsa_encrypt_pkcs1(public_key, msg)` |
| Key wrapping | `aes_kw_wrap(kek, key)` `aes_kwp_wrap(kek, key)` |
| AEAD parts | `aead_ciphertext(encryption)` `aead_tag(encryption)`, around an AEAD call written in place |
| Public keys | `ed25519_public(key)` `ed448_public(key)` `ecdsa_public(curve, key)` `rsa_public(form, key)` |
| CBOR | `cbor_int(n)` `cbor_bytes(value)` `cbor_text(value)` `cbor_array(item, ...)` `cbor_map(key, value, ...)` `cbor_tag(number, item)` |

Keys are raw bytes or PKCS#8 DER (PKCS#1 DER for RSA); use `pem(...)` to read a PEM field.
Hash names are `sha1`, `sha256`, `sha384` and `sha512`: `pbkdf2` and `rsa_sign_pkcs1` take all
four, `rsa_sign_pss` the last three (salt of the digest length), `rsa_encrypt_oaep` all four
(MGF1 with the same hash, empty label). `pbkdf2` gives the digest length by default and at most
64 bytes. AES-GCM takes 16-, 24- and 32-byte keys. RSA public keys are SubjectPublicKeyInfo or
PKCS#1 `RSAPublicKey` DER, 1024 to 8192 bits; RSA signatures with SHA-256, -384 and -512 use
ring, the SHA-1 PKCS#1 v1.5 signature and the encryptions use RustCrypto `rsa`.

The second group of families (`docs/design.md` section 8d), each checked against published
vectors (`crates/engine/src/vectors_families.rs` names the source of each):

- SHA-3 (FIPS 202): `sha3_*` are digests; `shake128` and `shake256` give `length` bytes, 1 to
  8192.
- KDFs take `sha256`, `sha384` or `sha512` and a `length` in bytes. `hkdf` is RFC 5869 (an
  empty salt is a zero salt; at most 255 blocks); `hkdf_expand` is its expand step alone from
  a PRK. `concat_kdf` is the single-step KDF of NIST SP 800-56A, `H([i]32 || z || other_info)`,
  as JOSE and COSE ECDH-ES use it: the template builds `other_info` (for JOSE, `be32(len(x)) +
  x` for the algorithm and both party infos, then `be32` of the key length in bits).
  `kbkdf_counter` is the counter mode of NIST SP 800-108 with HMAC: `HMAC(key, [i]32 ||
  fixed_input)`; the template builds the fixed input, usually `label + "\0" + context +
  be32(bits)` (Kerberos, RFC 8009: `label + "\0" + be32(bits)`). Both KDFs give at most 8192
  bytes.
- Kerberos (RFC 3961, RFC 3962): `nfold(value, bits)` is n-fold to a multiple of 8 bits;
  `kerberos_dk(key, constant)` is DK for AES keys (16 or 32 bytes), the constant n-folded to
  one block when it is not one already. String-to-key for AES is
  `kerberos_dk(pbkdf2("sha1", password, salt, rounds, "16"), "kerberos")` (32 for AES-256);
  a key usage constant (RFC 3961 section 5.3) is `be32(usage) + hexdecode("aa")` for Ke,
  `"99"` for Kc and `"55"` for Ki.
- AES modes take 16-, 24- or 32-byte keys and return the ciphertext followed by the tag.
  `aes_ccm_encrypt` (NIST SP 800-38C) takes a 7- to 13-byte nonce (the length field is 15
  minus it) and an even tag of 4 to 16 bytes, so COSE's AES-CCM-16-64-128 is nonce 13, tag 8.
  `aes_cbc_hmac_encrypt` is RFC 7518 section 5.2 with a 32-, 48- or 64-byte key (A128CBC-HS256,
  A192CBC-HS384, A256CBC-HS512) and a tag of half the key. `aes_eax_encrypt` takes a 16-byte
  nonce and gives a 16-byte tag. `aes_cts_encrypt` is CBC with ciphertext stealing as Kerberos
  uses it (CBC-CS3, RFC 3962), for messages of at least 16 bytes. `aes_cmac` is RFC 4493;
  `aes_cbc_mac` is CBC-MAC with a zero IV and zero padding (16 bytes; cut it with `slice`).
  `aes_kw_wrap` is RFC 3394 (a key of 16 or more bytes, a multiple of 8), `aes_kwp_wrap`
  RFC 5649 (any length).
- `ed448_sign` is Ed448 (RFC 8032) with an optional context of up to 255 bytes; the key is the
  57-byte secret or PKCS#8 DER. `ecdsa_sign_prehash(curve, key, digest)` signs a digest the
  template computed (16 to 64 bytes) on `p256`, `p384`, `p521`, `k256`, or the brainpool
  curves `bp256` and `bp384` (RFC 5639; COSE ESB256 and ESB384 sign the SHA-256 and SHA-384
  of the structure), with the RFC 6979 nonce, `r || s`. `dsa_sign` and `dsa_sign_der` are DSA (FIPS 186-4) with `sha1`, `sha256`,
  `sha384` or `sha512` and the RFC 6979 nonce, `r || s` (each as long as q) or DER; the key is
  PKCS#8 DER.
- `mldsa_sign(level, seed, msg[, context])` is ML-DSA (FIPS 204) with the parameter set `44`,
  `65` or `87` and a context of up to 255 bytes, hedged (32 fresh random bytes per
  signature, the default of FIPS 204: the deterministic variant would sign the same message
  the same way, which fault attacks use). The key is the 32-byte seed of key generation, the
  private key form of the JOSE, COSE and LAMPS drafts. `mldsa_public(level, seed)` is its
  encoded public key (1312, 1952 or 2592 bytes).
- `sm2_sign(key, msg[, id])` is SM2 with SM3 (GB/T 32918.2, RFC 8998): the SM3 of
  `Z_A || msg` signed with an RFC 6979 nonce, `r || s`; the identifier is
  `1234567812345678` unless given. The key is the 32-byte scalar or PKCS#8 DER.

`slice` counts bytes from 0 and fails when the range is outside the value. `between` fails when
a delimiter is missing; an empty `start` means the beginning, an empty `end` the end.
`json_set_number` writes the integer unquoted (`-?(0|[1-9][0-9]*)`, at most 20 characters).
`add` fails on overflow, the fixed-width encoders on a number that does not fit.

#### Key agreement

`ecdh(curve, peer_public)` is the shared secret of the peer's public key and the **ephemeral**
key of the operation on `curve` (`p256`, `p384`, `p521`, `x25519` or `x448`): the x-coordinate
for the NIST curves (the peer key in SEC1 form, compressed or not), the 32 bytes of X25519 or
the 56 of X448 (an all-zero result, from a low-order point, fails). `ecdh_public(curve)` is that ephemeral key's public
key: SEC1 uncompressed for the NIST curves, 32 bytes for X25519, 56 for X448. The node makes one ephemeral
key pair per curve and operation, the first time either function asks for it, and erases it
when the operation ends; every step and template of the operation sees the same pair, the
private key never leaves the node, and the next operation has a new one. With a third
argument, `ecdh(curve, peer_public, private)` uses a static private key instead (a field: the
raw scalar or PKCS#8 DER for NIST curves, 32 raw bytes for X25519, 56 for X448). A key
agreement counts as a signature in the budget, and so does each `ed448_sign`,
`ecdsa_sign_prehash`, `dsa_sign`, `dsa_sign_der`, `mldsa_sign`, `mldsa_public`, `sm2_sign`
and HPKE call (but `hpke_derive_key`).

The shared secret is a secret (tainted), the public key is not. For a fresh IV or nonce that
must appear twice (in the encryption and next to the ciphertext), use `hexdecode($nonce)`
(16 bytes), which is the same everywhere in one request; `random(n)` is new at every call.

An envelope that encrypts a password to a server's P-256 key, composed from these:

```text
{{ b64(aes_cbc_encrypt(sha256(hex(ecdh("p256", hexdecode(between(keys, ",", ""))))),
                       hexdecode($nonce),
                       u8(len(session)) + session + u8(len(user)) + user + u8(len(password)) + password))
   + "," + b64(hexdecode($nonce)) + "," + hex(ecdh_public("p256")) + "," + session }}
```

(`keys` is a public temp captured as `session,server-public-key-hex`, `session` a second
capture of its first part.)

#### CBOR

The `cbor_*` functions write RFC 8949 in its deterministic form (section 4.2.1): shortest
heads, definite lengths, map keys sorted by their encoded bytes and never repeated. Each
returns one encoded item; `cbor_array`, `cbor_map` and `cbor_tag` take encoded items (up to
32 arguments, so 16 map pairs) and refuse an argument that is not exactly one well-formed,
deterministic item. Simple values are literals: `hexdecode("f4")`, `hexdecode("f5")` and
`hexdecode("f6")` are false, true and null. Floating-point numbers are refused. A `COSE_Sign1` with EdDSA over the caller's payload:

```text
{{ cbor_tag("18", cbor_array(cbor_bytes(cbor_map(cbor_int("1"), cbor_int("-8"))), cbor_map(),
     cbor_bytes($input),
     cbor_bytes(ed448_sign(key, cbor_array(cbor_text("Signature1"),
       cbor_bytes(cbor_map(cbor_int("1"), cbor_int("-8"))), cbor_bytes(""), cbor_bytes($input)))))) }}
```

`COSE_Mac0` and `COSE_Encrypt0` are the same shape with `MAC_structure` and `Enc_structure`
(tags 17 and 16).

#### HPKE

`hpke_*` are RFC 9180 single-shot HPKE (section 6), checked against the RFC's vectors
(`crates/engine/tests/fixtures/vectors/README.md`). `suite` is `kem,kdf,aead`: the KEM is
`p256`, `p384`, `p521`, `x25519` or `x448` (DHKEM with the HKDF of its curve), the KDF
`sha256`, `sha384` or `sha512`, the AEAD `aes128gcm`, `aes256gcm`, `chacha20poly1305` or
`export` (export only: `hpke_seal` and `hpke_open` refuse it). `mode` is `base`, `psk`,
`auth` or `auth_psk`; the PSK modes take `psk` and `psk_id` after the fixed arguments, the
auth modes then the sender's private key (sending) or public key (receiving). Public keys
are the serialized KEM keys (SEC1 uncompressed for the NIST curves), private keys the raw
scalar or the 32 or 56 bytes of X25519 and X448.

- `hpke_seal` gives `enc || ciphertext`, with a fresh ephemeral key at each call (no
  ephemeral key can be given: a fixed one would reuse a nonce). It counts as a signature in
  the budget, like every HPKE call.
- `hpke_open` gives the plaintext; it fails when the tag does not verify.
- `hpke_export` gives `enc || secret` (the `length`-byte exported secret, 1 to 8192, after
  the `enc` the receiver needs); `hpke_receiver_export` gives the secret on the receiving
  side.
- `hpke_public(kem, private)` is the public key of a private key, `hpke_derive_key(kem, ikm)`
  the private key of `DeriveKeyPair` (section 7.1.3) from at least 32 bytes of `ikm`.

Choices the RFC leaves open, made the stricter way: a PSK is at least 32 bytes and its id is
not empty (section 5.1.2 asks for 32 bytes of entropy; a short PSK would be guessable from a
recorded `enc`), and `hpke_derive_key` takes at least 32 bytes (section 7.1.3 asks for as
many as the private key).

#### TurboSHAKE and KangarooTwelve

`turboshake128` and `turboshake256` are RFC 9861 TurboSHAKE with the domain byte `domain` (a
decimal number, 1 to 127, fixed by the policy) and `length` bytes of output, 1 to 8192.
`kt128` and `kt256` are KangarooTwelve (KT128, KT256) with a customization string (empty
for none). They are plain hashes (rule 3).

#### TLS channel binding

`tls_exporter(label, context, length)` is the keying material exported from the TLS
connection of the operation (RFC 8446 section 7.5), `length` bytes, 1 to 8192. Over
TLS 1.2 it fails: rustls does not report whether the extended master secret (RFC 7627) was
agreed, and without it an exporter does not bind the connection (RFC 9266 section 3). RFC 9266's `tls-exporter` binding is
`tls_exporter("EXPORTER-Channel-Binding", "", "32")`. It is rendered after the handshake, so
it is available only in the template of a `send` of a `tls` connection; anywhere else
(a `compute`, an HTTPS request, a derivation) the policy is refused at signing. The value is
a secret (tainted), known to the node and the server only.

`tls-unique` (RFC 5929) is not offered: it reads the first Finished message, which rustls does
not expose, it is undefined for TLS 1.3, and RFC 9266 replaces it with the exporter.
`tls-server-end-point` and an exporter inside an HTTPS request are not offered yet: the
request is rendered before its connection exists (`docs/design.md`, Appendix A).

#### Request components, AEAD parts and public keys

A signature can cover what the caller sends. `$header("name")` and `$query_param("name")`
read the caller's request; the name is a string literal, so the analysis knows each value a
template reads, and signing refuses a name the `send`'s contract does not list (a caller
cannot send a header outside its contract, so it cannot put one into a signature base
either) and any use outside the injections of a `send` that takes the caller's request.
Their values are chosen by the caller, like `$body`: *controlled* and not secret. The RFC 9421
derived components are `$method` (`@method`), `$target_uri` (`@target-uri`), `$authority`
(`@authority`), `$scheme` (`@scheme`), `$path` (`@request-target`), `$pathname` (`@path`),
`"?" + $query` (`@query`) and `$query_param("name")` (`@query-param`); a header field is
`$header("name")`. `$path` and `$pathname` are the path before path parameters are filled.

The caller's request signed over its method, target URI, authority (port 8443 here), one
query parameter, two of its headers and the digest of its body:

```json
{"name": "signed-call-headers",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 8443}]},
  {"do": "compute", "into": "sig_params", "template": "(\"@method\" \"@target-uri\" \"@authority\" \"@query-param\";name=\"page\" \"content-type\" \"content-digest\" \"idempotency-key\");created={{ $unix }};keyid=\"client-1\";alg=\"ed25519\""},
  {"do": "send", "request": {"from": "caller", "methods": ["GET", "POST"], "paths": ["/v1/**"], "headers": ["Content-Type", "Idempotency-Key"], "query": [{"name": "page", "pattern": "[0-9]{1,4}"}]},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Digest"}, "template": "sha-256=:{{ b64(sha256($body)) }}:"},
    {"target": {"kind": "header", "name": "Signature-Input"}, "template": "sig1={{ sig_params }}"},
    {"target": {"kind": "header", "name": "Signature"}, "template": "sig1=:{{ b64(ed25519_sign(key, \"\\\"@method\\\": \" + $method + \"\\n\\\"@target-uri\\\": \" + $target_uri + \"\\n\\\"@authority\\\": \" + $authority + \"\\n\\\"@query-param\\\";name=\\\"page\\\": \" + $query_param(\"page\") + \"\\n\\\"content-type\\\": \" + $header(\"content-type\") + \"\\n\\\"content-digest\\\": sha-256=:\" + b64(sha256($body)) + \":\\n\\\"idempotency-key\\\": \" + $header(\"idempotency-key\") + \"\\n\\\"@signature-params\\\": \" + sig_params)) }}:"}]},
  {"do": "return", "response": {"body": "all"}}
 ]}
```

Hawk over the caller's content type (its media type without parameters, in lowercase, as
Hawk normalizes it) and the port from `$port`:

```json
{"name": "hawk-call-headers",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 8000}]},
  {"do": "send", "request": {"from": "caller", "methods": ["GET", "POST"], "paths": ["/v1/**"], "headers": ["Content-Type"]},
   "inject": [
    {"target": {"kind": "header", "name": "Authorization"}, "template": "Hawk id=\"{{ user }}\", ts=\"{{ $unix }}\", nonce=\"{{ $nonce }}\", hash=\"{{ b64(sha256(\"hawk.1.payload\\n\" + lower(trim(between($header(\"content-type\") + \";\", \"\", \";\"))) + \"\\n\" + $body + \"\\n\")) }}\", mac=\"{{ b64(hmac_sha256(secret, \"hawk.1.header\\n\" + $unix + \"\\n\" + $nonce + \"\\n\" + $method + \"\\n\" + $path + \"\\n\" + $host + \"\\n\" + $port + \"\\n\" + b64(sha256(\"hawk.1.payload\\n\" + lower(trim(between($header(\"content-type\") + \";\", \"\", \";\"))) + \"\\n\" + $body + \"\\n\")) + \"\\n\\n\")) }}\""}]},
  {"do": "return", "response": {"body": "all"}}
 ]}
```

`aead_ciphertext(...)` and `aead_tag(...)` take an AEAD call written in place
(`aes_gcm_encrypt`, `chacha20_poly1305_encrypt`, `aes_cbc_hmac_encrypt`, `aes_ccm_encrypt`,
`aes_eax_encrypt`; anything else is refused) and give its ciphertext and its tag: the tag is
the last 16 bytes, the CCM tag length, or half the AES-CBC-HMAC key. Each part has exactly the
properties of the encryption. The encryption is deterministic, so the two calls agree when
the key and nonce are computed once (a `compute` name, or `$nonce`). This is what a JWE
whose plaintext mixes the caller's bytes with a secret needs: `slice` cannot cut such a value
(rule 2), and should not, since a cut at a length the caller chooses would select a piece of
the secret; the parts cut where the algorithm puts the tag, and each covers the whole
message. A card number added to the caller's JSON, sealed for the server's RSA key
(RSA-OAEP-256, A256GCM):

```json
{"name": "jwe-mixed",
 "steps": [
  {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
  {"do": "compute", "into": "cek", "template": "{{ random(\"32\") }}"},
  {"do": "compute", "into": "iv", "template": "{{ random(\"12\") }}"},
  {"do": "compute", "into": "head", "template": "{{ b64urlraw(json_set(json_set(\"{}\", \"alg\", \"RSA-OAEP-256\"), \"enc\", \"A256GCM\")) }}"},
  {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/v1/payments"]},
   "inject": [
    {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/jose"},
    {"target": {"kind": "body"}, "template": "{{ head + \".\" + b64urlraw(rsa_encrypt_oaep(\"sha256\", pem(server_key), cek)) + \".\" + b64urlraw(iv) + \".\" + b64urlraw(aead_ciphertext(aes_gcm_encrypt(cek, iv, json_set($body, \"card\", card_number), head))) + \".\" + b64urlraw(aead_tag(aes_gcm_encrypt(cek, iv, json_set($body, \"card\", card_number), head))) }}"}]},
  {"do": "return", "response": {"body": "all"}}
 ]}
```

The public key of a signing key comes from the private key, so a JWK needs no separate
field: `ed25519_public(key)` (32 bytes) and `ed448_public(key)` (57) for raw or PKCS#8 keys,
`ecdsa_public(curve, key)` (SEC1 uncompressed; `x` and `y` are the two halves after the first
byte) on `p256`, `p384`, `p521`, `k256`, `bp256`, `bp384` and `sm2`, and `rsa_public(form,
key)` with `form` `n` or `e` (the JWK members, big-endian without leading zeros), `spki` or
`pkcs1` (DER). Each is one-way, like `hpke_public`, and counts as a signature in the budget.
A JWS whose header carries the Ed25519 key that signs it:

```json
{"name": "jws-eddsa-jwk", "input": {"raw": {}},
 "steps": [
  {"do": "compute", "into": "header", "template": "{\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{{ b64urlraw(ed25519_public(key)) }}\"}}"},
  {"do": "compute", "into": "head", "template": "{{ b64urlraw(header) }}"},
  {"do": "return", "template": "{{ head + \".\" + b64urlraw($input) + \".\" + b64urlraw(ed25519_sign(key, head + \".\" + b64urlraw($input))) }}"}
 ]}
```

### The analysis

Every template is analysed before the policy is signed. Each expression has four properties:

| Property | Set by | Kept through | Removed by |
| --- | --- | --- | --- |
| *tainted*: holds a secret in reversible form | secret fields (guessable or not), secret temps, every `ecdh`, `tls_exporter`, `hpke_open`, `hpke_export` and `hpke_receiver_export` result; a key derived from a tainted value (`hkdf`, `hkdf_expand`, `concat_kdf`, `kbkdf_counter`, `kerberos_dk`, `hpke_derive_key`: rule 8); a plain hash (`md4` `md5` `sha1` `sha256` `sha384` `sha512` `sha512_256` `keccak256` `sha3_*` `shake128` `shake256` `turboshake*` `kt*`) of a tainted value with no controlled bytes in it | every function not listed as removing it, and `+`: the encodings, `slice`, `between`, `add`, the fixed-width encoders, `json_set_number`, `nfold`, the `cbor_*` functions, and encryption to a public key (`rsa_encrypt_*`, and `hpke_seal` when the info, AAD or plaintext is tainted, or a PSK or sender key that is not a *secret key*: whoever holds the private key reads it) | a plain hash of a value that is also controlled; `hmac_*`, `pbkdf2`, `pbkdf2_sha256`, `totp`, `hpke_public`, the signatures and `len`; `aes_cmac` and `aes_cbc_mac` under a secret key; symmetric encryption and key wrapping, only as rule 4 says |
| *controlled*: chosen by the caller or the server | `$method` `$path` `$pathname` `$query` `$body` `$input`, captured values (temps) | everything except `ecdh`, `tls_exporter`, `hpke_export` and `hpke_receiver_export`, whose result depends on a key nobody chooses, and a key derived from a tainted value, of which the caller chooses no byte | — |
| *caller-chosen*: chosen by the caller (not only a server) | `$method` `$path` `$pathname` `$query` `$body` `$input` | everything except `ecdh`, `tls_exporter`, `hpke_export`, `hpke_receiver_export` and a key derived from a tainted value | — |
| *secret key*: a strong secret nobody else knows, usable as a key | a secret field that is not guessable | `b64decode` `b32decode` `hexdecode` `pem` `trim` `slice` of it | everything else, including hashes, MACs and `+`: a hash or MAC of a key is a new value some operation may hand back |
| *guessable*: a guess can be checked against it | guessable fields | every function except `len`, and `+` | `len` |

An argument is *mixed* when it is both tainted and controlled (a secret and chosen bytes in one
value).

Rules:

1. A mixed value may not reach a sensitive argument, where failing or not, or the result,
   would tell the caller something about the secret:

   | Function | Sensitive arguments |
   | --- | --- |
   | `b64decode` `b32decode` `hexdecode` `pctdecode` `pem` `canonical_query` `u8` `be16` `be32` `be64` `le16` `le32` `le64` `random` | the input |
   | `time(unix, format)` | both |
   | `totp(seed, digits, period)` | `digits` and `period` |
   | `pbkdf2_sha256(password, salt, rounds, length)` `pbkdf2(hash, password, salt, rounds, length)` | `rounds` and `length` |
   | `aes_gcm_encrypt(key, nonce12, ...)` `aes_cbc_encrypt(key, iv16, ...)` `chacha20_poly1305_encrypt(key32, nonce12, ...)` `aes_cbc_hmac_encrypt(key, iv16, ...)` `aes_eax_encrypt(key, nonce16, ...)` `aes_cts_encrypt(key, iv16, ...)` | the key and the nonce or IV |
   | `aes_ccm_encrypt(key, nonce, tag_length, ...)` | the key, the nonce and the tag length |
   | `aes_kw_wrap(kek, key)` `aes_kwp_wrap(kek, key)` `aes_cmac(key, msg)` `aes_cbc_mac(key, msg)` `kerberos_dk(key, constant)` | the key (the KEK) |
   | `hkdf`, `hkdf_expand`, `concat_kdf`, `kbkdf_counter`, `shake128`, `shake256`, `nfold`, `kt128`, `kt256`, `tls_exporter`, `hpke_export`, `hpke_receiver_export` | the length |
   | `turboshake128` `turboshake256` | the domain byte and the length |
   | `hpke_seal` `hpke_export` | the recipient's public key, the PSK, its id and the sender's key |
   | `hpke_open` `hpke_receiver_export` | every argument after the mode: whether the call fails tells whether they match what the sender used |
   | `hpke_public` `hpke_derive_key` | the key or `ikm` |
   | `mldsa_sign` `mldsa_public` `sm2_sign` | the key |
   | the signatures | the key |
   | `rsa_encrypt_oaep(hash, public_key, msg)` `rsa_encrypt_pkcs1(public_key, msg)` | the public key |
   | `ecdh(curve, peer_public, private)` | the peer key and the private key |
   | `cbor_int` `cbor_text` | the input |
   | `cbor_array` `cbor_map` `cbor_tag` | every argument (each is checked to be one item) |
   | `ed25519_public` `ed448_public` | the key |
   | `ecdsa_public(curve, key)` `rsa_public(form, key)` | the key |

   A tainted value in one sensitive argument of `time`, `totp`, `pbkdf2_sha256` or `pbkdf2` and
   a controlled value in another are refused too: `time(secret, $input)` lets the caller pick
   which digits of the secret come out.
2. A tainted and a controlled value may not meet anywhere in `replace`, `xor`, `slice`,
   `between`, `add` or `json_set_number`: `slice(key, $input, "1")` would hand the secret out
   a byte at a time, `between(key, $input, "")` would tell where a chosen text sits in it, and
   `add` would fail or not with its size. A captured secret temp is both tainted and
   controlled, so these functions cut only public temps and secret fields (with fixed
   numbers and delimiters). In `json_set(object, key, value)`, a tainted object or key may not
   meet a controlled value in any argument (the value itself is only escaped and appended).
   In `cbor_map`, a tainted key may not meet a controlled key: the order of the pairs, and
   whether two keys are equal, compare them.
3. A hash of secret bytes alone is as good as the secret wherever the secret is hashed
   before use (an HMAC key longer than its block, an Ed25519 seed), so it stays tainted:
   `hex(sha256(key))` is refused as a derivation output, `hex(sha256(key + $input))` is not.
4. Encryption under a secret key hides only the key: the output is tainted when the nonce, the
   message or the AAD is tainted. A secret in the message stays readable, because another
   operation may encrypt chosen bytes under the same key and a chosen nonce and so give back
   the keystream. Under a key that is not a secret key, the output is tainted when any
   argument is. The same holds for `aes_cbc_hmac_encrypt`, `aes_ccm_encrypt`,
   `aes_eax_encrypt`, `aes_cts_encrypt`, and for `aes_kw_wrap` and `aes_kwp_wrap` (the wrapped
   key is the message: a fresh `random(16)` wrapped under a secret KEK is not tainted, a secret
   field wrapped under any KEK is). `aes_cmac` and `aes_cbc_mac` are one-way under a secret
   key; under any other key they keep the taint, since a one-block CBC-MAC is the block
   encrypted and whoever knows the key decrypts it.
5. The output of an operation with no connection (a derivation) may not be tainted or
   guessable. Since only `len` removes
   *guessable*, a derivation may depend on a guessable field only through `len`.
6. An argument that names a hash or a curve (`pbkdf2`, `rsa_sign_pkcs1`, `rsa_sign_pss`,
   `rsa_encrypt_oaep`, `ecdh`, `ecdh_public`, `hkdf`, `hkdf_expand`, `concat_kdf`,
   `kbkdf_counter`, `ecdsa_sign_prehash`, `dsa_sign`, `dsa_sign_der`, the suite and mode of
   the `hpke_*` functions, the KEM of `hpke_public` and `hpke_derive_key`, the domain byte of
   `turboshake*`, the parameter set of `mldsa_sign` and `mldsa_public`) must be neither tainted nor controlled: the policy fixes the algorithm, so no caller can downgrade it.
   So must the curve of `ecdsa_public` and the form of `rsa_public`.
7. The public key of `rsa_encrypt_oaep`, `rsa_encrypt_pkcs1`, `hpke_seal` and `hpke_export`,
   and the PSK, PSK id and sender key of every `hpke_*` function, must not be caller-chosen: it
   comes from the policy (a literal or a field) or from a capture of the destination's
   response. A key from `$input`, `$body`, `$query` or another request variable would let the
   caller encrypt the secret to itself, or pass as the sender of an authenticated HPKE mode.
8. A key derived from a secret is a secret: the output of `hkdf`, `hkdf_expand`,
   `concat_kdf`, `kbkdf_counter`, `kerberos_dk` and `hpke_derive_key` is tainted when any input is, and then not
   controlled, since the caller chooses no byte of it (as with `ecdh`). So a plain hash of it
   stays tainted, a derivation cannot hand it back, and it may key an encryption whose
   output then stays tainted (it is not a *secret key*: some operation may derive the same
   key and use it where its output is seen). An HMAC or a signature of it is one-way as
   usual.
9. An argument that sets the output's length or where a cut falls must not be tainted:
   `random(n)`, the length of `pbkdf2_sha256`, `pbkdf2`, `hkdf`, `hkdf_expand`, `concat_kdf`,
   `kbkdf_counter`, `shake128`, `shake256`, `turboshake128`, `turboshake256`, `kt128`,
   `kt256`, `nfold`, `tls_exporter`, `hpke_export` and `hpke_receiver_export`, the tag length of
   `aes_ccm_encrypt`,
   the start and length of `slice`, the delimiters of `between`, and the text `replace` looks
   for. The length of the output, or whether the call fails, would give the secret back
   through `len`. The value being cut or searched may be a secret (`slice(key, "0", "4")`).
   `aead_ciphertext` and `aead_tag` take no length: they cut at the tag length the algorithm
   fixes (the CCM tag length is the argument above), counted from the end, so a secret in the
   message changes neither where the cut falls nor which bytes each part covers.

The request components (`$header`, `$query_param`, `$target_uri`) are controlled and
caller-chosen like `$body`, so every rule above applies to them unchanged: a header value
signed with a secret key is the normal signing case, and a header value that meets a secret in
`slice`, a decoder or a key argument is refused like `$body` would be. `$port`, `$scheme` and
`$authority` come from the destination, like `$host`. `aead_ciphertext` and `aead_tag` have the
properties of the encryption they split (never a *secret key*). `ed25519_public`,
`ed448_public`, `ecdsa_public` and `rsa_public` remove the taint, like `hpke_public`, and keep
*guessable*.

A template that breaks rule 1, 2, 6, 7 or 9 is refused wherever it appears; rule 5 applies to the
`return` of an operation with no connection. A computed name carries the properties of its
template, so the rules hold across steps exactly as they do inside one template.

A short tainted value in a request (a byte cut by `slice`, a `u8` of a secret) is shorter
than the 4 bytes the reflection search needs; the rules above keep its position fixed by the
policy, so a caller cannot move it across the secret.

### Budgets

One operation may render at most 128 MiB in all, 1,000,000 PBKDF2 rounds and 32 signatures
and key agreements together.
Exceeding one is a `Budget` error before anything is logged or sent.
