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
├── fields:     [FieldSpec]          1–32
├── callers:    [Caller]             1–32
└── operations: [Operation]          1–16
    ├── name
    ├── input:  raw | json | rlp     (operations with no connection)
    └── steps:  [Step]               1–64
        ├── open     connection: https | tls, destinations, identity
        ├── send     https: request (caller contract | fixed) + inject;  tls: template
        ├── receive  https: the response of the send;  tls: until a delimiter;  + capture
        ├── compute  into a name, from a template
        ├── run      site code or a reviewed library in the sandbox; output only to its origin
        ├── return   https: response projection;  tls: relay;  none: template
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
| `https` | One HTTP/1.1 request on its own TLS connection: `request` and `inject`. | Reads the response of the `send` just before it, for its captures. | `response`: the projection of the last response. | A request within the contract of each `send` that takes it. |
| `tls` | Writes a rendered `template`. | Reads up to and including the first of `until` (1 to 8 delimiters of 1 to 256 bytes). | `relay`: which of the caller's exchanges run after the steps. | Exchanges, each matched against `relay`. |
| none (no `open`) | — | — | `template`: the output. | Its `input`, checked by the `input` schema. |

Rules for every operation:

- `open`, when present, is the first step; an operation opens one connection. Without it the
  operation has no connection and only `compute` and `return` are allowed.
- `return` is the last step, and every operation ends with one.
- On HTTPS, a `receive` follows the `send` whose response it reads; at most 8 sends.
- `compute` may appear anywhere after `open`.
- `run` needs an HTTPS connection and may appear anywhere after `open`.
- `repeat` and `if` are refused for now (see [Loops and branches](#loops-and-branches)).

New kinds of connection (WebSocket, SSH, database handshakes, a browser over CDP) fit the
same steps: each kind says what its `send`, `receive` and `return` carry, and the template
analysis stays the same. None is implemented yet.

### `open`

| Member | Meaning |
| --- | --- |
| `connection` | `https` or `tls`. |
| `destinations` | 1–32 hosts and ports. `*.example.com` matches exactly one label (`eu.example.com`, not `example.com` or `a.b.example.com`); `*.` must be followed by at least two labels, so `*.com` is refused. Hosts are lowercase labels of `a–z 0–9 -` (at most 253 bytes), and the port is not 0. The caller's request or stream names one of them. |
| `identity` | Optional client certificate for mutual TLS: two templates, handed to the transport only. |

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

`{"do": "return"}` alone returns the status only. Whatever goes back is still redacted and
searched for secrets.

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
| ssh and vpn kinds allow no connection yet. | Their protocols do not exist in the node; a TLS stream to port 22 would send a key to a server whose host key nobody checked. |
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
| `card` | cvc · number (brand and last four), expiry (year) · holder, billing | HTTPS to the owner's destinations; JSON members back |
| `login` | password, totp, session · username (email) · origin (pinned) | HTTPS to the pinned origin only; may capture `session` |
| `oauth` | client_secret, refresh_token, access_token · — · provider (pinned), client_id, scopes | HTTPS; JSON members back; captures the tokens |
| `identity` | national_id · name, birth_date, phone, email, address · — | HTTPS; JSON members back |
| `totp` | seed (≥128 bits) · account · digits, period, issuer | derivations only |
| `ssh` | password, private_key · — · host, port, host_key (pinned), user | none yet |
| `database` | password · — · engine, host, port, tls (pinned), database, user, ca | TLS to the pinned host and port; relay allowed |
| `ftp` | password · — · host, port, mode (pinned), user | TLS to the pinned host and port; relay allowed |
| `mail` | password, token · user (email) · protocol, host, port (pinned) | TLS to the pinned host and port; relay allowed |
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
  pinned host and port (`database`, `ftp`, `mail`, `queue`), with no wildcard unless the
  shape allows one; use no client certificate, relay or capture the shape does not allow;
- return no more than the shape: `status` < `json` (JSON members) < `all` (the whole body).

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
  parameter, a path parameter, the body, a client identity, a stream send, or the output of a
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
| `relay` | A stream relays the caller's sends. |
| `relay_broad` | A relay pattern matches broadly (`.*`, `.+`, a negated class). |
| `response_all` | The whole response body goes back. |
| `query_any` | A caller's query parameter takes any value. |
| `encoded_percent` | The caller's path may hold `%25`. |
| `override_params` | The caller may send method-override parameters. |
| `client_certificate` | A client certificate goes to a destination. |
| `run_unpinned` | A `run` step fetches its module without a `sha256` pin: the site can change the code that reads the secrets. |
| `wider` | Against `previous`: a new destination, method, path, header, query rule, injection, operation, caller or caller key; more of the response; a looser limit; a field made public or not guessable; the item unbound or its pins and sign-offs changed. |
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

An operation that needs the owner's approval (part 5 of `docs/design.md` section 11 runs
them) is described by the node in an `ApprovalSummary`: a random id, the node, owner, record
and generation, caller and operation, destination and origin, an amount (a decimal and an
ISO 4217 code), the item's `describe` view and at most 32 lines, created and expiring at
most five minutes apart. The caller writes no part of it. The owner's device signs an
`Approval`: the id, the SHA-256 of the summary's canonical bytes (domain
`approval-summary/v1`), the device and the time, signed under the domain `approval/v1` with
the node, owner and record. The node accepts it when the id and hash are those of the summary
it built, the device is a known device of the owner, and it was issued while the summary was
open. `approve` in the `client` crate refuses a summary of another node or one that lapsed.

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

TLS sends and identities can read `$host`, `$unix`, `$unix_ms` and `$nonce`; `compute` on a
connection reads `$unix`, `$unix_ms` and `$nonce`, and with no connection what the `return`
reads.

| Group | Functions |
| --- | --- |
| Encoding | `b64` `b64raw` `b64url` `b64urlraw` `b64decode` `b32decode` `hex` `hexdecode` `pct` `pctdecode` `json` `pem` |
| Text | `upper` `lower` `trim` `replace(text, from, to)` `json_set(object, key, value)` `json_set_number(object, key, integer)` `canonical_query` `time(unix, format)` `len` `xor(a, b)` `slice(value, start, length)` `between(value, start, end)` |
| Numbers | `add(a, b)` (signed 64-bit decimal); fixed-width encoders of a decimal number: `u8`, `be16` `be32` `be64`, `le16` `le32` `le64` |
| Random | `random(n)`: n fresh bytes (1 to 1024), new at every call |
| Hash and MAC | `md4` `md5` `sha1` `sha256` `sha384` `sha512` `sha512_256` `keccak256` `sha3_224` `sha3_256` `sha3_384` `sha3_512` `shake128(msg, length)` `shake256(msg, length)` `hmac_md5(key, msg)` `hmac_sha1` `hmac_sha256` `hmac_sha384` `hmac_sha512` `aes_cmac(key, msg)` `aes_cbc_mac(key, msg)` `pbkdf2(hash, password, salt, rounds[, length])` `pbkdf2_sha256(password, salt, rounds[, length])` `totp(seed[, digits[, period]])` |
| Key derivation | `hkdf(hash, ikm, salt, info, length)` `hkdf_expand(hash, prk, info, length)` `concat_kdf(hash, z, other_info, length)` `kbkdf_counter(hash, key, fixed_input, length)` `nfold(value, bits)` `kerberos_dk(key, constant)` |
| Signature | `ed25519_sign(key, msg)` `ed448_sign(key, msg[, context])` `p256_sign` `p256_sign_der` `p384_sign` `p521_sign` `k256_sign` `k256_sign_recoverable(key, digest32)` `ecdsa_sign_prehash(curve, key, digest)` `rsa_sign_pkcs1(hash, key, msg)` `rsa_sign_pss(hash, key, msg)` `rsa_sign_pkcs1_sha256(key, msg)` `rsa_sign_pss_sha256(key, msg)` `dsa_sign(hash, key, msg)` `dsa_sign_der(hash, key, msg)` |
| Key agreement | `ecdh(curve, peer_public[, private])` `ecdh_public(curve)` |
| Encryption | `aes_gcm_encrypt(key, nonce12, msg[, aad])` `aes_cbc_encrypt(key, iv16, msg)` `aes_cbc_hmac_encrypt(key, iv16, msg[, aad])` `aes_ccm_encrypt(key, nonce, tag_length, msg[, aad])` `aes_eax_encrypt(key, nonce16, msg[, aad])` `aes_cts_encrypt(key, iv16, msg)` `chacha20_poly1305_encrypt(key32, nonce12, msg[, aad])` `rsa_encrypt_oaep(hash, public_key, msg)` `rsa_encrypt_pkcs1(public_key, msg)` |
| Key wrapping | `aes_kw_wrap(kek, key)` `aes_kwp_wrap(kek, key)` |
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
  template computed (16 to 64 bytes) on `p256`, `p384`, `p521` or `k256`, with the RFC 6979
  nonce, `r || s`. `dsa_sign` and `dsa_sign_der` are DSA (FIPS 186-4) with `sha1`, `sha256`,
  `sha384` or `sha512` and the RFC 6979 nonce, `r || s` (each as long as q) or DER; the key is
  PKCS#8 DER.

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
`ecdsa_sign_prehash`, `dsa_sign` and `dsa_sign_der`.

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

TLS channel-binding values (`tls_exporter(label, length)`, `tls_server_end_point`) are not
template variables yet: an HTTPS `send` renders its request before the connection exists, so
the exported keying material is not known when the template is rendered. They need the
request rendered after the handshake, inside the transport; that is the next change of this
group (`docs/design.md`, Appendix A).

### The analysis

Every template is analysed before the policy is signed. Each expression has four properties:

| Property | Set by | Kept through | Removed by |
| --- | --- | --- | --- |
| *tainted*: holds a secret in reversible form | secret fields (guessable or not), secret temps, every `ecdh` result; a key derived from a tainted value (`hkdf`, `hkdf_expand`, `concat_kdf`, `kbkdf_counter`, `kerberos_dk`: rule 8); a plain hash (`md4` `md5` `sha1` `sha256` `sha384` `sha512` `sha512_256` `keccak256` `sha3_*` `shake128` `shake256`) of a tainted value with no controlled bytes in it | every function not listed as removing it, and `+`: the encodings, `slice`, `between`, `add`, the fixed-width encoders, `json_set_number`, `nfold`, the `cbor_*` functions, and encryption to a public key (`rsa_encrypt_*`: whoever holds the private key reads it) | a plain hash of a value that is also controlled; `hmac_*`, `pbkdf2`, `pbkdf2_sha256`, `totp`, the signatures and `len`; `aes_cmac` and `aes_cbc_mac` under a secret key; symmetric encryption and key wrapping, only as rule 4 says |
| *controlled*: chosen by the caller or the server | `$method` `$path` `$pathname` `$query` `$body` `$input`, captured values (temps) | everything except `ecdh`, whose result depends on a private key nobody chooses, and a key derived from a tainted value, of which the caller chooses no byte | — |
| *caller-chosen*: chosen by the caller (not only a server) | `$method` `$path` `$pathname` `$query` `$body` `$input` | everything except `ecdh` and a key derived from a tainted value | — |
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
   | `hkdf`, `hkdf_expand`, `concat_kdf`, `kbkdf_counter`, `shake128`, `shake256`, `nfold` | the length |
   | the signatures | the key |
   | `rsa_encrypt_oaep(hash, public_key, msg)` `rsa_encrypt_pkcs1(public_key, msg)` | the public key |
   | `ecdh(curve, peer_public, private)` | the peer key and the private key |
   | `cbor_int` `cbor_text` | the input |
   | `cbor_array` `cbor_map` `cbor_tag` | every argument (each is checked to be one item) |

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
   `kbkdf_counter`, `ecdsa_sign_prehash`, `dsa_sign`, `dsa_sign_der`) must be neither tainted
   nor controlled: the policy fixes the algorithm, so no caller can downgrade it.
7. The public key of `rsa_encrypt_oaep` and `rsa_encrypt_pkcs1` must not be caller-chosen: it
   comes from the policy (a literal or a field) or from a capture of the destination's
   response. A key from `$input`, `$body`, `$query` or another request variable would let the
   caller encrypt the secret to itself.
8. A key derived from a secret is a secret: the output of `hkdf`, `hkdf_expand`,
   `concat_kdf`, `kbkdf_counter` and `kerberos_dk` is tainted when any input is, and then not
   controlled, since the caller chooses no byte of it (as with `ecdh`). So a plain hash of it
   stays tainted, a derivation cannot hand it back, and it may key an encryption whose
   output then stays tainted (it is not a *secret key*: some operation may derive the same
   key and use it where its output is seen). An HMAC or a signature of it is one-way as
   usual.
9. An argument that sets the output's length or where a cut falls must not be tainted:
   `random(n)`, the length of `pbkdf2_sha256`, `pbkdf2`, `hkdf`, `hkdf_expand`, `concat_kdf`,
   `kbkdf_counter`, `shake128`, `shake256` and `nfold`, the tag length of `aes_ccm_encrypt`,
   the start and length of `slice`, the delimiters of `between`, and the text `replace` looks
   for. The length of the output, or whether the call fails, would give the secret back
   through `len`. The value being cut or searched may be a secret (`slice(key, "0", "4")`).

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
