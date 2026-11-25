# credentials

[![ci](https://github.com/BloubHQ/credentials/actions/workflows/ci.yml/badge.svg)](https://github.com/BloubHQ/credentials/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A vault engine that lets applications and AI agents **use** a credential without ever
**seeing** it. The owner's device decides, in a signed policy, exactly where a secret may go
and in what form. A node holds the secret only while the owner allows it, writes a
tamper-evident log entry **before** every use, and hands the caller back a response that has
been checked for the secret.

```text
caller:  "GET https://api.github.com/user"            (no token)
node:    log entry confirmed  ->  adds "Authorization: Bearer ghp_..."  ->  TLS  ->  GitHub
caller:  200 OK {"login": "octo"}                     (token removed or response dropped)
```

The engine knows no kind of credential. API keys, OAuth refresh, AWS SigV4, HTTP Digest, JWT
signing, TOTP, IMAP logins, mutual TLS and Ethereum signatures are all policy data, not code.

> **Status: 0.x, not audited.** The engine is tested and has been reviewed internally, but it has not had
> an external security audit and its formats may change. Read the
> [threat model](docs/threat-model.md) before you trust it with production secrets.

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Policies](#policies)
- [Records, generations and rollback](#records-generations-and-rollback)
- [The log](#the-log)
- [Running a node](#running-a-node)
- [What it guarantees](#what-it-guarantees)
- [Measurements](#measurements)
- [What it does not do](#what-it-does-not-do)
- [Crates](#crates) · [Development](#development) · [Security](#security) · [License](#license)

## How it works

```mermaid
flowchart LR
    subgraph device["Owner's device"]
        DK["device key<br/>(signs)"]
        UK["user key<br/>(encrypts)"]
    end
    subgraph node["Node (meant to run in a TEE)"]
        ENG["engine"]
    end
    APP["Caller<br/>app or agent<br/>(caller key)"]
    STORE[("Record store<br/>ciphertext only")]
    LOG[("Log sink")]
    API["Destination<br/>api.example.com"]

    device -- "record: fields encrypted,<br/>policy signed" --> STORE
    device -- "grant sealed to the node (HPKE),<br/>signed, with pins" --> ENG
    STORE -. "record" .-> APP
    APP -- "signed call + record" --> ENG
    ENG -- "1. entry (confirmed first)" --> LOG
    ENG -- "2. TLS request carrying the secret" --> API
    API -- "response" --> ENG
    ENG -- "3. response without the secret" --> APP
```

There are four parties and four kinds of key:

| Party | Key | What it does |
| --- | --- | --- |
| Owner's device | `DeviceKey` (Ed25519) | Signs policies, grants, pins, revocations and other devices |
| Owner | `UserKey` (256-bit) | Encrypts records (a key per record via HKDF); a node holds it only during a grant |
| Caller | `CallerKey` (Ed25519) | Signs each call; the policy lists which caller may run which operation |
| Node | `NodeKey` (Ed25519) | Signs the log; an X25519 key derived from it opens sealed grants |

One call, in order. Every check before the log entry leaves no trace; nothing leaves the node
without a confirmed entry:

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant N as Node
    participant L as Log sink
    participant D as Destination
    C->>N: record + operation + request + Authorization
    N->>N: grant in force? record pinned and not stale?<br/>policy signed by a known device?
    N->>N: caller listed for the operation? signature,<br/>±5 min, one-time nonce, rate limit
    N->>N: request within the operation (host, method,<br/>path prefix, headers); decrypt; render within budget
    N->>L: entry (seq, prev hash, owner chain, caller, sealed detail)
    L-->>N: confirmed
    N->>D: TLS request with the injected secret
    D-->>N: response
    N->>N: parse (framing, size), capture values,<br/>redact captured secrets, search for any secret
    N->>L: done entry (status)
    N-->>C: parsed response, or an error if a secret reflected
```

## Quick start

```sh
git clone https://github.com/BloubHQ/credentials && cd credentials
cargo test --workspace
GITHUB_TOKEN=ghp_... cargo run -p transport --example github_user
```

The [`github_user`](crates/transport/examples/github_user.rs) example runs every part in one
process: the device seals a token into a record, signs a policy that allows only
`GET https://api.github.com/user`, and grants a node; an application signs a call; the node
logs, injects the token, sends the request over TLS and returns the response. In code:

```rust
// On the owner's device.
let record = Record::seal(&user_key, "github", "me", device.sign_policy(policy)?, &values)?;
let grant = device.grant(&user_key, &node.identity(), GrantTerms {
    owner: "me".into(),
    expires_ms: now + 600_000,
    issued_ms: now,
    pins: vec![RecordPin { record_id: "github".into(), generation: record.generation }],
})?;

// On the node.
node.grant(&grant)?;

// In the application: it holds the record (ciphertext) and its caller key, never the token.
let auth = app.authorize("example", &node.public_key(), &record, "github",
                         &Payload::Http(Some(&request)), now)?;
let response = node.http(&record, "github", &auth, Some(&request), &mut transport).result?;
```

## Policies

A policy names the **fields** of a record, the **callers** who may use it, and the
**operations** they may run. The device signs it; the signature and the encryption of the
record both bind it, so nobody can change where a value goes without the owner. The full
reference is in [docs/policy.md](docs/policy.md).

```json
{
  "fields": [
    {"name": "client_id", "secret": false},
    {"name": "client_secret", "secret": true},
    {"name": "refresh_token", "secret": true},
    {"name": "access_token", "secret": true, "optional": true}
  ],
  "callers": [
    {"name": "billing-agent", "key": "<caller public key>",
     "operations": ["refresh", "call"], "limit": {"count": 100, "window_ms": 60000}}
  ],
  "operations": [
    {"kind": "http", "name": "refresh",
     "destinations": [{"host": "auth.example.com", "port": 443}],
     "steps": [{
       "request": {"from": "fixed", "method": "POST", "path": "/oauth/token"},
       "inject": [{"target": {"kind": "body"},
                   "template": "grant_type=refresh_token&refresh_token={{pct(refresh_token)}}&client_id={{pct(client_id)}}&client_secret={{pct(client_secret)}}"}],
       "capture": [{"source": {"from": "json", "pointer": "/access_token"},
                    "into": {"kind": "field", "name": "access_token"}}]
     }]},
    {"kind": "http", "name": "call",
     "destinations": [{"host": "*.api.example.com", "port": 443}],
     "methods": ["GET", "POST"], "paths": ["/v1/"], "caller_headers": ["Accept"],
     "steps": [{"inject": [{"target": {"kind": "header", "name": "Authorization"},
                            "template": "Bearer {{access_token}}"}]}]}
  ]
}
```

| Operation | What it does |
| --- | --- |
| `http` | 1 to 8 steps. Each sends the caller's request or a request the policy fixes, injects values, and captures values from the response into a field (a new record generation) or a temporary value for later steps. Only the last response goes back. |
| `stream` | A send/expect script on one TLS connection (IMAP, SMTP, line protocols), then the caller's exchanges on the authenticated connection. |
| `derive` | A template's output goes back to the caller: signatures, HMACs, TOTP codes, JWTs. |

Values go in through **templates**: `{{ hex(hmac_sha256(secret, $query)) }}`. The language
has names, variables, string literals, function calls and `+`; no branches or loops. Before a
policy is signed, every template is analysed:

- **Taint.** A value that holds a secret in reversible form is *tainted*. Encodings keep taint;
  hashes, MACs, signatures and `len` remove it; encryption removes it only under a secret key.
  A derivation whose output is tainted is refused.
- **Oracles.** A secret and a value the caller or server chooses may not meet where the result
  reveals the secret piece by piece: in `replace`, `xor`, the key of `json_set`, a decoder,
  a number or a key argument. `len(replace(key, $input, ""))` is refused.
- **Guessable fields.** Fields marked `guessable` (PINs, passwords) may not reach a derivation
  output that a guess can be checked against (a hash or signature of them), unless a keyed
  MAC or encryption under a strong secret key hides them.
- **Budgets.** One operation may render at most 128 MiB, 1,000,000 PBKDF2 rounds and 32
  signatures.

| Credential | Policy |
| --- | --- |
| Bearer token, cookie, API key | one header template |
| Telegram bot | `path_param` `{{token}}` in `/bot{token}/getMe` |
| Exchange HMAC signature | query `signature` = `{{ hex(hmac_sha256(secret, $query)) }}` |
| AWS SigV4 | two header templates (`time`, `canonical_query`, nested `hmac_sha256`); a test reproduces the official vector |
| HTTP Digest | step 1 captures `realm`/`nonce` with `header_param`; step 2 answers with `md5`; RFC 2617 vector |
| OAuth refresh | `fixed` POST, `json` capture into a field: the node returns a new record |
| Session login | `fixed` POST /login, `cookie` capture into a temp, `Cookie` on the caller's request |
| JWT RS256 | derive `b64urlraw(header) + "." + b64urlraw($input) + "." + b64urlraw(rsa_sign_pkcs1_sha256(pem(key), …))` |
| Ethereum | derive `{{ k256_sign_recoverable(key, keccak256($input)) }}` |
| IMAP | stream: expect greeting, send `a1 LOGIN {{user}} {{password}}`, expect, relay |
| TOTP | derive `{{ totp(b32decode(seed)) }}` |
| Mutual TLS | `"identity": {"cert": "{{cert}}", "key": "{{key}}"}` |

## Records, generations and rollback

A record is the fields, encrypted with ChaCha20-Poly1305 under a key derived from the user
key and the record id, with the id, owner, **generation** and signed policy in the associated
data. Every re-seal adds one to the generation.

```mermaid
flowchart LR
    S["seal on the device<br/>generation 1"] --> P1["pin 1<br/>(in the grant)"]
    P1 --> R["node captures a new token<br/>generation 2"]
    R --> W["device rewraps with a<br/>narrower policy: generation 3"]
    W --> P3["pin 3"]
    P3 -. "an operator replays generation 1 or 2" .-> X["RecordStale: refused"]
```

A node refuses a record unless the owner pinned it (in a grant or with `DeviceKey::pin`), and
refuses any generation older than the newest it saw or the owner pinned. Because the grant
carries the pins, even a fresh node that never saw the newer record refuses the old one.

## The log

Each entry is signed by the node and chained twice: to the entry before it, and to the
previous entry of the same owner. An owner can check its own entries without anyone else's,
and a signed checkpoint (`SignedHead`) fixes the head so a cut tail shows.

```mermaid
flowchart LR
    E0["#0 grant<br/>alice"] --> E1["#1 use<br/>alice/github"] --> E2["#2 grant<br/>bob"] --> E3["#3 done<br/>alice/github"] --> E4["#4 derive<br/>bob/eth"]
    E0 -. "owner_prev" .-> E1 -. "owner_prev" .-> E3
    E2 -. "owner_prev" .-> E4
    E4 --- H["SignedHead<br/>seq 4, hash, time"]
```

Entries show who used which record, when, by which caller and for which operation. **Where**
the value went and what was sent (host, path, body hash) is sealed to the owner's user key:
the log store cannot read it, the owner can (`log::open_detail`, or
`verify --owner alice --user-key key.txt`). A node never acts without a confirmed entry: the
transport functions take a `Confirmed` that only `Log::commit` can make, after the sink
returned `Ok`. If the sink fails, the log halts until it is reconciled.

```sh
verify log.jsonl <node-public-key>                          # the whole chain
verify log.jsonl <node-public-key> --head head.json         # must end at a signed checkpoint
verify log.jsonl <node-public-key> --owner alice            # one owner's chain
verify log.jsonl <node-public-key> --owner alice --user-key key.txt   # with the details
```

## Running a node

- **Transport.** `transport::TlsTransport` (rustls with the ring provider, Mozilla roots,
  client certificates, connect/read/total deadlines, size limits). The certificate of the
  destination is what binds a connection to the host the owner signed; DNS is not trusted.
- **Zeroizing allocator.** Install one in the binary that runs a node, so the buffers of
  dependencies the engine cannot reach (TLS records, parsed RSA keys) are erased when freed:

  ```rust
  #[global_allocator]
  static ALLOCATOR: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
      zeroizing_alloc::ZeroAlloc(std::alloc::System);
  ```

  Measured: RSA key copies left in freed memory per signature go from 1 to 0, for 3–12% more
  time (table below).
- **Attestation.** Run the node in a TEE (SGX, TDX, SEV-SNP, Nitro). Put
  `NodeIdentity::report_data()` (SHA-512 over the log key and the seal key) into the quote's
  report data; owners check the quote and that value before they seal a grant. Quote
  verification is platform-specific and not in this repository.
- **Keys and restarts.** Keep `NodeKey::to_bytes()` sealed to the enclave. After a restart,
  `Node::restore(key, sink, clock, entries)` continues the chain and brings back record
  floors, known devices and the last grant times; owners grant again.
- **Concurrency.** Every method takes `&self`; share one node between threads. Transport I/O
  runs outside the node's lock.

## What it guarantees

- A secret leaves the engine only as bytes of one request to a destination the owner signed,
  through the `Transport`, after a confirmed log entry.
- `Secret` values cannot be printed, cloned or serialized, and are erased on drop. Code
  outside the crate cannot read them (`compile_fail` doc tests).
- Only a caller the policy lists, with a fresh one-time signature over this exact call, within
  its rate limit, can run an operation.
- Grants open only on the node they were sealed to, only from a device the node knows for the
  owner (first use is trusted), and cannot be replayed. Revocations need a known device.
- Records cannot be rolled back past a pin or a generation the node saw.
- Templates are analysed before signing; derivations cannot hand back a secret, an oracle on
  a secret, or a check for guesses of a guessable field.
- Responses are parsed strictly (framing, encodings, sizes); captured secrets are redacted;
  a response that still holds any secret in a known form is dropped.
- The log is append-only, signed, chained per node and per owner, and checkable offline.
- No `unsafe`, no `unwrap`/`expect`/`panic`/indexing in the engine (enforced by lints).

## Measurements

Release builds on one machine. The attack cases are the probes of the internal review, run
against the earlier code (`79a21c1`) and the current code; memory is the peak measured by an
instrumented allocator.

| Case | Before | Now |
| --- | --- | --- |
| 64 KiB captured token + 8 MiB response (redaction and search) | 63.88 s | 0.08–0.10 s |
| 16 KiB token + 4 MiB response | 6.34 s | 0.07 s |
| Template concatenation ×401 on 1 MiB input | accepted, 803 MiB | `Budget` error, 129 MiB |
| PBKDF2 1,000,000 rounds ×127 | 12.70 s | `Budget` error after 0.09 s |
| 64 MiB response | passed through after 1.81 s | refused after 0.02 s |
| 16 MiB JSON array with a pointer capture | 400 MiB | 64 MiB |
| 16 MiB of headers | 192 MiB | 0 MiB (refused at 64 KiB) |
| 16 MiB body captured into 16 temps | 768 MiB | 32 MiB (refused at 64 KiB) |
| Freed blocks still holding a secret (json capture, `b64decode`, `json`, `replace`, `json_set`) | 1, 8, 1, 1, 1 | 0, 0, 0, 0, 0 |
| Freed blocks still holding an RSA private key, per signature | 1 | 1 (0 with the zeroizing allocator) |
| Freed blocks still holding a P-384 private key | 0 | 0 |

| Throughput (with the instrumented allocator) | System allocator | Zeroizing allocator |
| --- | --- | --- |
| 2,000 HMAC derivations | 0.29–0.30 s | 0.31 s |
| 200 RSA-2048 signatures | 0.129–0.130 s | 0.130–0.136 s |
| 1,000 HTTP calls with 64 KiB responses | 0.329 s | 0.338–0.369 s |

RustCrypto `rsa` 0.10 was also measured as a replacement for ring: it left 11 freed blocks
holding the prime `p` per signature (temporaries while it parses and checks the key), so ring
stays.

## What it does not do

These are limits of the design, not missing code. The [threat model](docs/threat-model.md)
explains each.

- **No TEE in this repository.** The node is an ordinary process here; attestation is a
  platform integration (see [Running a node](#running-a-node)). Without a TEE, whoever runs the
  node can read its memory.
- **Reflection search finds known encodings only**: raw, base64 (both alphabets), percent,
  JSON and hex, and escaped JSON strings. A server that splits, compresses in its own way or
  encrypts a secret it echoes is not caught. Secret fields of 4 to 7 bytes are searched raw
  only, and their bytes appearing by chance drop the response.
- **Responses are buffered** (16 MiB at most), because the search needs the whole response.
- **A value the server sends for capture is the server's.** If a server hands back a key and
  the policy uses it as a key, the server knows that key.
- **Low-entropy secrets** not marked `guessable` are treated as strong keys.
- **First use is trusted**: the first grant for an owner on a node decides its devices. An
  owner who loses every device starts a new owner name.
- **Stream sessions** end with the call. SSH, database wire protocols, gRPC and WebSocket
  framing work only as far as a send/expect script can go.
- **Browser logins, push 2FA and hardware keys** need a person or a device and cannot be
  delegated.

## Crates

| Crate | |
| --- | --- |
| [`engine`](crates/engine) | Secrets, policies, templates, records, grants, callers, the log, responses, the node |
| [`transport`](crates/transport) | TLS transport (rustls), and an end-to-end example |
| [`verify`](crates/verify) | Command-line verifier of node logs |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Minimum Rust: 1.87. CI also runs `cargo audit`, `cargo deny`, an MSRV build and a
reproducible-build check. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
