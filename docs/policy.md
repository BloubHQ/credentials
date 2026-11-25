# Policy reference

A policy is JSON. Unknown members are refused everywhere, including next to a tag:
`{"from": "fixed", "method": "GET", "path": "/x", "junk": 1}`, `{"do": "open", "junk": 1}`
and `{"kind": "body", "junk": 1}` are errors, not the plain forms. A device signs it with
`DeviceKey::sign_policy`, which also checks every rule below; an error names the place and
the rule, for example `policy invalid at operations[0].steps[1].inject[2]: header must be a
token, not reserved, and set once`. `Policy::summary()` prints a policy as one line per
field, caller, operation and step, for the owner to read before signing; a line that starts
with `!` marks something that widens what the caller may do.

```text
Policy
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
- `repeat` and `if` are refused for now (see [Loops and branches](#loops-and-branches)).

New kinds of connection (WebSocket, SSH, database handshakes, a browser over CDP, a WASM
`run`) fit the same steps: each kind says what its `send`, `receive` and `return` carry, and
the template analysis stays the same. None is implemented yet.

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
| Hash and MAC | `md4` `md5` `sha1` `sha256` `sha384` `sha512` `sha512_256` `keccak256` `hmac_md5(key, msg)` `hmac_sha1` `hmac_sha256` `hmac_sha384` `hmac_sha512` `pbkdf2(hash, password, salt, rounds[, length])` `pbkdf2_sha256(password, salt, rounds[, length])` `totp(seed[, digits[, period]])` |
| Signature | `ed25519_sign(key, msg)` `p256_sign` `p256_sign_der` `p384_sign` `p521_sign` `k256_sign` `k256_sign_recoverable(key, digest32)` `rsa_sign_pkcs1(hash, key, msg)` `rsa_sign_pss(hash, key, msg)` `rsa_sign_pkcs1_sha256(key, msg)` `rsa_sign_pss_sha256(key, msg)` |
| Key agreement | `ecdh(curve, peer_public[, private])` `ecdh_public(curve)` |
| Encryption | `aes_gcm_encrypt(key, nonce12, msg[, aad])` `aes_cbc_encrypt(key, iv16, msg)` `chacha20_poly1305_encrypt(key32, nonce12, msg[, aad])` `rsa_encrypt_oaep(hash, public_key, msg)` `rsa_encrypt_pkcs1(public_key, msg)` |

Keys are raw bytes or PKCS#8 DER (PKCS#1 DER for RSA); use `pem(...)` to read a PEM field.
Hash names are `sha1`, `sha256`, `sha384` and `sha512`: `pbkdf2` and `rsa_sign_pkcs1` take all
four, `rsa_sign_pss` the last three (salt of the digest length), `rsa_encrypt_oaep` all four
(MGF1 with the same hash, empty label). `pbkdf2` gives the digest length by default and at most
64 bytes. AES-GCM takes 16-, 24- and 32-byte keys. RSA public keys are SubjectPublicKeyInfo or
PKCS#1 `RSAPublicKey` DER, 1024 to 8192 bits; RSA signatures with SHA-256, -384 and -512 use
ring, the SHA-1 PKCS#1 v1.5 signature and the encryptions use RustCrypto `rsa`.

`slice` counts bytes from 0 and fails when the range is outside the value. `between` fails when
a delimiter is missing; an empty `start` means the beginning, an empty `end` the end.
`json_set_number` writes the integer unquoted (`-?(0|[1-9][0-9]*)`, at most 20 characters).
`add` fails on overflow, the fixed-width encoders on a number that does not fit.

#### Key agreement

`ecdh(curve, peer_public)` is the shared secret of the peer's public key and the **ephemeral**
key of the operation on `curve` (`p256`, `p384`, `p521` or `x25519`): the x-coordinate for the
NIST curves (the peer key in SEC1 form, compressed or not), the 32 bytes of X25519 (an all-zero
result, from a low-order point, fails). `ecdh_public(curve)` is that ephemeral key's public
key: SEC1 uncompressed for the NIST curves, 32 bytes for X25519. The node makes one ephemeral
key pair per curve and operation, the first time either function asks for it, and erases it
when the operation ends; every step and template of the operation sees the same pair, the
private key never leaves the node, and the next operation has a new one. With a third
argument, `ecdh(curve, peer_public, private)` uses a static private key instead (a field: the
raw scalar or PKCS#8 DER for NIST curves, 32 raw bytes for X25519). A key agreement counts as
a signature in the budget.

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

### The analysis

Every template is analysed before the policy is signed. Each expression has four properties:

| Property | Set by | Kept through | Removed by |
| --- | --- | --- | --- |
| *tainted*: holds a secret in reversible form | secret fields (guessable or not), secret temps, every `ecdh` result; a plain hash (`md4` `md5` `sha1` `sha256` `sha384` `sha512` `sha512_256` `keccak256`) of a tainted value with no controlled bytes in it | every function not listed as removing it, and `+`: the encodings, `slice`, `between`, `add`, the fixed-width encoders, `json_set_number`, and encryption to a public key (`rsa_encrypt_*`: whoever holds the private key reads it) | a plain hash of a value that is also controlled; `hmac_*`, `pbkdf2`, `pbkdf2_sha256`, `totp`, the signatures and `len`; symmetric encryption, only as rule 4 says |
| *controlled*: chosen by the caller or the server | `$method` `$path` `$pathname` `$query` `$body` `$input`, captured values (temps) | everything except `ecdh`, whose result depends on a private key nobody chooses | — |
| *caller-chosen*: chosen by the caller (not only a server) | `$method` `$path` `$pathname` `$query` `$body` `$input` | everything except `ecdh` | — |
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
   | `aes_gcm_encrypt(key, nonce12, ...)` `aes_cbc_encrypt(key, iv16, ...)` `chacha20_poly1305_encrypt(key32, nonce12, ...)` | the key and the nonce or IV |
   | the signatures | the key |
   | `rsa_encrypt_oaep(hash, public_key, msg)` `rsa_encrypt_pkcs1(public_key, msg)` | the public key |
   | `ecdh(curve, peer_public, private)` | the peer key and the private key |

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
3. A hash of secret bytes alone is as good as the secret wherever the secret is hashed
   before use (an HMAC key longer than its block, an Ed25519 seed), so it stays tainted:
   `hex(sha256(key))` is refused as a derivation output, `hex(sha256(key + $input))` is not.
4. Encryption under a secret key hides only the key: the output is tainted when the nonce, the
   message or the AAD is tainted. A secret in the message stays readable, because another
   operation may encrypt chosen bytes under the same key and a chosen nonce and so give back
   the keystream. Under a key that is not a secret key, the output is tainted when any
   argument is.
5. The output of an operation with no connection (a derivation) may not be tainted or
   guessable. Since only `len` removes
   *guessable*, a derivation may depend on a guessable field only through `len`.
6. An argument that names a hash or a curve (`pbkdf2`, `rsa_sign_pkcs1`, `rsa_sign_pss`,
   `rsa_encrypt_oaep`, `ecdh`, `ecdh_public`) must be neither tainted nor controlled: the
   policy fixes the algorithm, so no caller can downgrade it.
7. The public key of `rsa_encrypt_oaep` and `rsa_encrypt_pkcs1` must not be caller-chosen: it
   comes from the policy (a literal or a field) or from a capture of the destination's
   response. A key from `$input`, `$body`, `$query` or another request variable would let the
   caller encrypt the secret to itself.

A template that breaks rule 1, 2, 6 or 7 is refused wherever it appears; rule 5 applies to the
`return` of an operation with no connection. A computed name carries the properties of its
template, so the rules hold across steps exactly as they do inside one template.

A short tainted value in a request (a byte cut by `slice`, a `u8` of a secret) is shorter
than the 4 bytes the reflection search needs; the rules above keep its position fixed by the
policy, so a caller cannot move it across the secret.

### Budgets

One operation may render at most 128 MiB in all, 1,000,000 PBKDF2 rounds and 32 signatures
and key agreements together.
Exceeding one is a `Budget` error before anything is logged or sent.
