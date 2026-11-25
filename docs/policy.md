# Policy reference

A policy is JSON. Unknown members are refused everywhere, including next to a tag:
`{"from": "caller", "path": "/x"}`, `{"from": "all", "junk": 1}` and
`{"kind": "body", "junk": 1}` are errors, not the plain forms. A device signs it with
`DeviceKey::sign_policy`, which also checks every rule below; an error names the place and
the rule, for example `policy invalid at operations[0].steps[1].inject[2]: header must be a
token, not reserved, and set once`. `Policy::summary()` prints a policy as one line per
field, caller and operation, for the owner to read before signing.

```text
Policy
├── fields:     [FieldSpec]          1–32
├── callers:    [Caller]             1–32
└── operations: [Operation]          1–16
    ├── http    → steps: [Step]      1–8
    │             ├── request: caller | fixed
    │             ├── inject:  [Injection]  ≤16
    │             └── capture: [Capture]    ≤16
    ├── stream  → script: [Exchange] 1–32
    └── derive  → template
```

Names (fields, callers, operations, temporaries, path parameters) are tokens: 1 to 64 of
`A–Z a–z 0–9 - _`.

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
request (or stream exchanges, or derivation input), the time and a random 16-byte nonce. A
node accepts it within ±5 minutes of its clock, once. `limit` (optional) allows `count` calls
(1 to 1,000,000) per `window_ms` for this caller on this record. The caller name is written
to each log entry.

## Operations

### `http`

```json
{"kind": "http", "name": "call",
 "destinations": [{"host": "*.api.example.com", "port": 443}],
 "methods": ["GET", "POST"],
 "paths": ["/v1/"],
 "caller_headers": ["Accept", "Content-Type"],
 "identity": {"cert": "{{cert}}", "key": "{{key}}"},
 "steps": [ ... ]}
```

| Member | Meaning |
| --- | --- |
| `destinations` | 1–32 hosts and ports. `*.example.com` matches exactly one label (`eu.example.com`, not `example.com` or `a.b.example.com`); `*.` must be followed by at least two labels, so `*.com` is refused. Hosts are lowercase labels of `a–z 0–9 -` (at most 253 bytes), and the port is not 0. |
| `methods` | Methods the caller may use. Required exactly when a step sends the caller's request. `GET HEAD POST PUT PATCH DELETE OPTIONS PROPFIND REPORT MKCOL COPY MOVE`. |
| `paths` | 1–32 path prefixes the caller may use, matched at a segment boundary (`/v1/` allows `/v1/repos`, not `/v10`). A prefix starts with `/` and holds no query (`?`) and no dot segment. Required exactly when a step sends the caller's request. |
| `caller_headers` | Headers the caller may set (none by default), each a token. A header an injection sets cannot also be a caller header. |
| `identity` | Optional client certificate for mutual TLS: two templates, handed to the transport only. |
| `steps` | 1–8 steps, sent in order. Only the last response goes back to the caller. |

A caller's path must start with `/` and may not hold `.`/`..` segments, `%2e`, `%2f`,
`%5c` or `\`. Nobody can set `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`,
`Upgrade`, `TE`, `Trailer`, `Expect`, `Accept-Encoding`, `Range`, `If-Range`, `Keep-Alive` or
the method-override headers; the engine sends `Accept-Encoding: identity` and
`Connection: close`.

#### Steps

```json
{"request": {"from": "fixed", "method": "POST", "path": "/oauth/token",
             "destination": {"host": "auth.example.com", "port": 443}},
 "inject": [ ... ],
 "capture": [ ... ]}
```

`request` is `{"from": "caller"}` (the default) or `{"from": "fixed", ...}`. A fixed request
needs a `destination` unless the operation has exactly one concrete destination. A caller
request takes no other member.

#### Injections

| `target` | Effect |
| --- | --- |
| `{"kind": "header", "name": "Authorization"}` | Sets a header (once). |
| `{"kind": "query", "name": "signature"}` | Appends a query parameter (the value is percent-encoded). The name must be a token. |
| `{"kind": "path_param", "name": "token"}` | Replaces `{token}` in the path, which must hold it exactly once. |
| `{"kind": "body"}` | Sets the body (at most one per step). |

#### Captures

```json
{"source": {"from": "json", "pointer": "/access_token"},
 "into": {"kind": "field", "name": "access_token"},
 "optional": false}
```

| `source` | Reads |
| --- | --- |
| `{"from": "status"}` | The status code. |
| `{"from": "header", "name": "X-Request-Id"}` | A response header. |
| `{"from": "header_param", "name": "WWW-Authenticate", "param": "nonce", "scheme": "Digest"}` | A parameter of an authentication challenge. |
| `{"from": "cookie", "name": "session"}` | A `Set-Cookie` value. |
| `{"from": "json", "pointer": "/data/token"}` | A JSON pointer (RFC 6901). Strings come unescaped, numbers as written. |
| `{"from": "between", "start": "token=", "end": "&"}` | The bytes between two delimiters. |
| `{"from": "all"}` | The whole body. |

| `into` | Effect |
| --- | --- |
| `{"kind": "field", "name": "..."}` | Replaces a **secret** field, from a **fixed** request or a stream script only. The node logs an `update` and returns a new record one generation later, even if a later step fails. A captured value that holds another secret field is refused. |
| `{"kind": "temp", "name": "...", "secret": true}` | A temporary value later steps of the same operation may read (a session cookie, a challenge nonce). At most 1 MiB of temporaries per operation. |

A captured value is at most 64 KiB. Captured secrets are replaced by `[redacted]` in the
response before the caller sees it.

### `stream`

```json
{"kind": "stream", "name": "imap",
 "destinations": [{"host": "imap.example.com", "port": 993}],
 "script": [
   {"kind": "expect", "until": ["\r\n"]},
   {"kind": "send", "template": "a1 LOGIN {{user}} {{password}}\r\n"},
   {"kind": "expect", "until": ["a1 OK", "a1 NO"],
    "capture": [{"source": {"from": "between", "start": "[", "end": "]"},
                 "into": {"kind": "temp", "name": "caps", "secret": false}}]}
 ]}
```

The script holds 1 to 32 entries (`send` or `expect`); each `expect` reads until one of 1 to 8
delimiters, each 1 to 256 bytes. The script runs on one TLS connection, then the caller's exchanges (at most 64, each a send
and the delimiters to read until) run on it. Every read is redacted and searched before it is
returned; an error stops the exchanges and is returned next to the reads that completed.
Streams capture with `between` and `all` only.

### `derive`

```json
{"kind": "derive", "name": "sign", "template": "{{ k256_sign_recoverable(key, keccak256($input)) }}"}
```

The output of the template goes back to the caller. `$input` is the caller's input (at most
1 MiB). A template whose output could hand a secret back is refused when the policy is
signed.

## Templates

`{{ ... }}` holds one expression: a name, a `$variable`, a `"string"` (escapes `\n \r \t \0 \" \\`),
a function call, or several joined with `+`. Text outside `{{ }}` is copied, so JSON bodies
with nested braces work. A template is at most 8 KiB, 512 nodes and 24 levels deep.

| Variable | Value | Where |
| --- | --- | --- |
| `$method` `$host` `$path` `$pathname` `$query` `$body` | The request being built | HTTP |
| `$unix` `$unix_ms` | The node's clock | everywhere |
| `$nonce` | 32 random hex characters | everywhere |
| `$boundary` | A random multipart boundary | HTTP |
| `$input` | The caller's input | derive |

Stream scripts and identities can read `$host`, `$unix`, `$unix_ms` and `$nonce`.

| Group | Functions |
| --- | --- |
| Encoding | `b64` `b64raw` `b64url` `b64urlraw` `b64decode` `b32decode` `hex` `hexdecode` `pct` `pctdecode` `json` `pem` |
| Text | `upper` `lower` `trim` `replace(text, from, to)` `json_set(object, key, value)` `canonical_query` `time(unix, format)` `len` `be16` `be32` `xor(a, b)` |
| Hash and MAC | `md5` `sha1` `sha256` `sha512` `keccak256` `hmac_sha1(key, msg)` `hmac_sha256` `hmac_sha512` `pbkdf2_sha256(password, salt, rounds[, length])` `totp(seed[, digits[, period]])` |
| Signature | `ed25519_sign(key, msg)` `p256_sign` `p256_sign_der` `p384_sign` `k256_sign` `k256_sign_recoverable(key, digest32)` `rsa_sign_pkcs1_sha256` `rsa_sign_pss_sha256` |
| Encryption | `aes_gcm_encrypt(key, nonce12, msg[, aad])` `aes_cbc_encrypt(key, iv16, msg)` |

Keys are raw bytes or PKCS#8 DER (PKCS#1 DER for RSA); use `pem(...)` to read a PEM field.

### The analysis

Every template is analysed before the policy is signed. Each expression has four properties:

| Property | Set by | Kept through | Removed by |
| --- | --- | --- | --- |
| *tainted*: holds a secret in reversible form | secret fields (guessable or not), secret temps; a plain hash (`md5` `sha1` `sha256` `sha512` `keccak256`) of a tainted value with no controlled bytes in it | every function not listed as removing it, and `+` | a plain hash of a value that is also controlled; `hmac_*`, `pbkdf2_sha256`, `totp`, the signatures and `len`; encryption, only as rule 4 says |
| *controlled*: chosen by the caller or the server | `$method` `$path` `$pathname` `$query` `$body` `$input`, captured values (temps) | everything | — |
| *secret key*: a strong secret nobody else knows, usable as a key | a secret field that is not guessable | `b64decode` `b32decode` `hexdecode` `pem` `trim` of it | everything else, including hashes, MACs and `+`: a hash or MAC of a key is a new value some operation may hand back |
| *guessable*: a guess can be checked against it | guessable fields | every function except `len`, and `+` | `len` |

An argument is *mixed* when it is both tainted and controlled (a secret and chosen bytes in one
value).

Rules:

1. A mixed value may not reach a sensitive argument, where failing or not, or the result,
   would tell the caller something about the secret:

   | Function | Sensitive arguments |
   | --- | --- |
   | `b64decode` `b32decode` `hexdecode` `pctdecode` `pem` `canonical_query` `be16` `be32` | the input |
   | `time(unix, format)` | both |
   | `totp(seed, digits, period)` | `digits` and `period` |
   | `pbkdf2_sha256(password, salt, rounds, length)` | `rounds` and `length` |
   | `aes_gcm_encrypt(key, nonce12, ...)` `aes_cbc_encrypt(key, iv16, ...)` | the key and the nonce or IV |
   | the signatures | the key |

   A tainted value in one sensitive argument of `time`, `totp` or `pbkdf2_sha256` and a
   controlled value in another are refused too: `time(secret, $input)` lets the caller pick
   which digits of the secret come out.
2. A tainted and a controlled value may not meet anywhere in `replace` or `xor`. In
   `json_set(object, key, value)`, a tainted object or key may not meet a controlled value in
   any argument (the value itself is only escaped and appended).
3. A hash of secret bytes alone is as good as the secret wherever the secret is hashed
   before use (an HMAC key longer than its block, an Ed25519 seed), so it stays tainted:
   `hex(sha256(key))` is refused as a derivation output, `hex(sha256(key + $input))` is not.
4. Encryption under a secret key hides only the key: the output is tainted when the nonce, the
   message or the AAD is tainted. A secret in the message stays readable, because another
   operation may encrypt chosen bytes under the same key and a chosen nonce and so give back
   the keystream. Under a key that is not a secret key, the output is tainted when any
   argument is.
5. A derivation's output may not be tainted or guessable. Since only `len` removes
   *guessable*, a derivation may depend on a guessable field only through `len`.

A template that breaks rule 1 or 2 is refused wherever it appears; rule 5 applies to
`derive` operations.

### Budgets

One operation may render at most 128 MiB in all, 1,000,000 PBKDF2 rounds and 32 signatures.
Exceeding one is a `Budget` error before anything is logged or sent.
