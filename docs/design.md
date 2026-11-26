# Design: from a credential engine to the vault of an agent service

Status: proposal. This document says what this repository must implement so that an AI agent
can act for its owner on any site or service without ever holding the owner's secrets, and how.
It is the plan of record; each part lands as its own pull request, with its tests, threat-model
rows and measurements.

## 0. Goals

1. **Free and custom everywhere; no rebuild for a new feature.** The node is still rebuilt
   for security fixes, dependency updates and its own maintenance, but never to support a new
   site, item kind, policy, template, flow or protocol: those are data or signed modules, and
   an owner (or an agent, with the owner's signature) can describe anything the node's
   primitives can express. The one exception is a cryptographic primitive the node lacks, so
   the release ships every primitive of the standard registries up front (section 8d).
2. **Security at least Pickle's.** Secrets never reach the agent, the model provider, the
   service's servers or the parent instance; values are masked; risky actions wait for the
   owner; the node is attested and reproducible. Freedom never lowers this: whatever is
   custom is signed by the owner, checked by the taint analysis and confined by the node's
   default deny.

## 1. Scope

This repository is the **vault**: the node that runs in an AWS Nitro Enclave, the formats it
accepts, the libraries owners and callers use to talk to it, and the build that makes its
measurements public. The agent, its conversations, its model provider and the service's own
servers live elsewhere; they are callers, and the vault treats them as untrusted.

| In this repository | Outside (agent and service) |
| --- | --- |
| Node in the enclave, attestation, reproducible EIF, signed log | The agent, its memory, its prompts |
| Typed items and their policies | Drafting a policy for a new site |
| Sessions, one-time-code challenges, owner approvals: formats and checks | Approval cards, push notifications, app screens |
| The fill step of a browser task: the node drives the browser for the moment secrets enter it | The browser controller the agent uses (click, read, navigate), the Kernel account |
| Protocol tunnels on the node, `credentials tunnel` on the caller's machine | Agent tools that use a tunnel |
| Reflection filtering, default deny, hand-over between nodes | Deployment infrastructure |
| `client` crate: verify a node, grant, summarize and sign policies, approve, back up keys | Keychain / Block Store glue, UI |

### What is protected, from whom

Secrets (passwords, card numbers and CVCs, OAuth tokens, private keys, TOTP seeds, session
cookies, one-time codes) must stay out of reach of:

- the agent and the model provider, including when the agent is prompt-injected;
- the service's own servers and staff, and the operator of the parent instance;
- the browser controller, except for the fields a fill puts into the page of the site the owner
  approved.

They are visible, by necessity, to: the owner's device; the node; the destination itself; and,
for browser fills, the cloud browser (Kernel) and the site's own page. Section 9 lists every
value against every place.

## 2. Architecture: three layers

Security does not come from limiting what the node can compute. It comes from two things:
where a value derived from a secret may go, and who wrote the code that touches the secret.
The node is built on those two axes, in three layers.

| Layer | What | How it changes |
| --- | --- | --- |
| **1. Primitive library** | every cryptographic family of the standards (Appendices A, B), encodings, and protocol codecs: TLS, HTTP/1.1, HTTP/2, HTTP/3, WebSocket, SSH, SASL, database handshakes, mail, EAP, Kerberos | the only compiled part; maintenance releases |
| **2. Policy IR** | one step language for every operation: open a connection, send, receive, capture, compute, wait for a challenge or approval, relay; bounded loops and branches; a request and response contract on every send and receive (section 2a); exact static taint analysis | data; an agent drafts it, the owner signs the summary |
| **3. Trusted code sandbox** | WebAssembly (a JavaScript engine runs inside it as a module) that may compute on secret bytes, only when the code comes from the destination's own origin (hash pinned) or from a reviewed library signed in a release; its output goes only to that destination | data; no release |

One rule joins them: **what an agent writes reaches secrets only as analysable data (layer 2);
arbitrary code (layer 3) reaches secrets only when it was written by a party already trusted
with them.**

Today's operation kinds (`http`, `stream`, `derive`) and the planned ones (`socket`,
`session`, `fill`, `vend`, `verify`, `run`, tunnels) all become step sequences over
connection kinds of layer 1. Typed items, templates for known sites and approval flows are
data on top. A typed item is a record whose fields and policy follow a schema, so an agent asks
for "the card item, at this merchant" instead of writing a policy.

## 2a. Request and response contracts

The signed policy bounds what goes out and what comes back, not only where it goes. Measured
in the engine on 2026-11-25 (tests in the pull request that fixes them), each of these let a
caller choose what the owner's policy should have fixed:

| Gap | Contract that closes it |
| --- | --- |
| `derive` signs any caller input: a caller-chosen 1000 ETH transfer was signed with the owner's key | input schema per format (JSON, RLP, EIP-712, raw): fixed members, allowed values, numeric bounds, node-set times; spending limits and approvals (section 8b) apply to signatures |
| query cannot be pinned, and the whole response is returned: an example STS policy signed `GetSessionToken` for 36 hours and handed the new secret key to the caller | `query` allow-list per name (fixed or allowed values, unknown and repeated names refused); response projection: only the declared status, headers and JSON members return to the caller |
| a caller query parameter placed before the injected one shadows it | injected names may not appear in the caller's query |
| `..;`, `%252e%252e`, `..%3b` pass the path prefix check | segment check after stripping `;` parameters and after one more decoding; `%25` refused in strict mode |
| `_method=DELETE` overrides the method through a parameter | reserved parameter names refused by default, as the override headers already are |
| a path placeholder lands where the caller puts it, also in its query | placeholders only as whole path segments; `paths` as templates matched exactly |
| after a stream login, caller commands are relayed unchecked (`RCPT TO` anyone) | allowed caller send patterns per stream (linear regular expressions) |
| JWT `exp` came from the caller | `add` (merged in the primitives pull request) and numeric members, so times are node-set |

Body schemas use the same form as input schemas: JSON pointer to fixed value, allowed values
or numeric bounds; form and multipart bodies are parsed and checked the same way.

## 3. Typed items## 3. Typed items

Each kind fixes its field names, their **disclosure level**, validation and default policies.

| Disclosure | The caller sees | Examples |
| --- | --- | --- |
| `secret` | nothing; the value only goes where the signed policy sends it | password, card number, CVC, token, key |
| `masked` | a fixed projection | card brand and last four, `j***@gmail.com` |
| `public` | the value | name on card, shipping address, when the owner allows it |

| Kind | Fields (disclosure) | Node checks |
| --- | --- | --- |
| `card` | number (secret, masked: brand+last4), expiry (masked), cvc (secret), holder (public), billing (public) | Luhn, expiry in the future, CVC length per brand |
| `login` | origin (public), username (masked), password (secret), totp seed (secret, optional), session (secret, optional) | origin is an exact scheme+host |
| `oauth` | provider, client id (public), client secret, refresh/access token (secret), scopes (public) | refresh captures re-seal the new token |
| `identity` | name, birth date, phone, email, address (each public or masked as the owner sets); national id (secret) | per-field release to listed origins only |
| `totp` | seed (secret), digits, period | derive only |
| `ssh` | host, port, host key (public, pinned), user (public), password or private key (secret) | host key must be pinned |
| `database` | engine, host, port, database, user (public), password (secret), TLS mode and CA pin | TLS required unless the owner signs it off |
| `ftp` | host, mode (FTPS explicit/implicit, SFTP goes to `ssh`), user, password | plain FTP only when signed off, and even then no operation (section 7c) |
| `mail` | IMAP/SMTP/POP3 host, user, app password or OAuth | |
| `queue` | MQTT, AMQP, Kafka, NATS, STOMP, XMPP host; user or client id (public); password, SASL secret, NATS nkey seed or client key (secret) | TLS required unless signed off |
| `vpn` | WireGuard peer (endpoint, public key), private key (secret); or IPsec/IKEv2 identity and PSK or key | endpoint pinned |
| `api` | free-form fields with a hand-written policy (today's records) | as today |

**Implementation.** `engine::item` holds the schemas as data. The reviewed kinds ship in
`items.json` (compiled in, so in PCR2); an owner can add **custom kinds** without a release: a
kind schema (fields, disclosure levels, validation patterns, policy shape) signed by the
owner's device, under the same checks as a policy. A typed record is an ordinary record whose policy is generated from the schema and
the owner's choices, then signed by the owner like any policy. The node re-derives the policy
from the schema and refuses a typed record whose signed policy differs, so a typed item cannot
smuggle extra destinations. Masked projections are computed by the node and returned by a new
`describe` call that never returns `secret` fields.

## 4. Policies written by an agent

Agents meet sites no one listed. They draft policies; the owner decides.

1. The agent drafts a policy (JSON Schema published from `engine::policy`, so drafts validate
   before they reach the owner).
2. `client::summarize(policy)` produces what the approval screen shows: for each secret, where it
   can go (scheme, host, port, method, path), in what form (header, body, query, TLS identity,
   derived output), and **risk flags**: a destination not under the item's origin, a wildcard,
   plain HTTP, a destination first seen, a derive output that is not one-way, a policy wider
   than the previous one for the same item.
3. The owner's device signs. Nothing else can make a policy valid. A changed policy shows only
   the difference.
4. Default deny stays: a destination, method, path or caller header not in the policy is refused.

Known sites ship as **reviewed templates** in `items.json` (Pickle's fixed providers, but as
data the owner still signs); unknown sites use agent drafts with the flags above.

## 5. Sessions, challenges, approvals

### Sessions

A session is a secret the node obtained (cookies, a bearer token from a login, an authenticated
protocol connection). It is stored as a field of the item, sealed like any other, with an
expiry and a **renewal rule**: re-login with the stored password (the node does it), or ask
the owner (sites behind JavaScript or CAPTCHA: the owner logs in once on the device, the app
seals the resulting cookies into the item).

### Challenges (one-time codes)

When a step needs a code the node cannot compute:

1. The node parks the operation: its temps stay in enclave memory under a challenge id, for at
   most 5 minutes; the caller gets `challenge {id, kind: sms|email|app|3ds, hint}`.
2. The code arrives in one of two ways: the owner's app sends it signed by a device key
   (`client::answer_challenge`), or the node reads it itself from a `mail` item of the owner
   under a policy that allows exactly that (sender and pattern pinned).
3. The node resumes. The code never passes through the agent.

A challenge of kind `external` carries no code: the site waits for the owner to approve in
another company's app (KakaoTalk, a bank's app push). The node keeps the parked operation,
polls the site's status endpoint as the policy describes, and resumes when the site reports
the approval, or fails at the deadline. The owner's own app only shows what is pending.

Proofs only the owner's phone can make (Apple Pay, Google Pay, app attestation tokens) are not
challenges: there is no value the node could receive. A task that needs one runs on the
owner's device, and the node is not involved.

**Implementation (part 5, done).** A step `await {challenge}` in HTTPS operations and
operations with no connection; parked operations in the node's memory (8 per owner, 256 and
128 MiB in all, at most five minutes, dropped on revoke and restart); `engine::session` for
the device's sealed, signed answer. Where the design left a choice, the more secure one was
taken:

- `await` is refused on TLS: a parked operation would hold an open connection to the site.
- A resume is accepted only from the caller that started the operation, on the same record
  and operation; every other case gets the same `parked_unknown` as an unknown id, so ids
  cannot be probed.
- An external challenge is polled only when the caller resumes (no background requests the
  owner cannot see), and the poll is a fixed request of the signed policy.
- Reading the code from a `mail` item is not done: it needs a mail connection kind (part 6).

### Approvals

An item or policy can require the owner's approval per use: payments always, plus whatever
the owner marks. The node returns `approval_required {id, summary}`; the summary is built by
the node (merchant origin, amount, currency, item masked view), and the owner's device signs
`approve(id, summary hash)`. The log records the approval.

Done in part 5. The node asks before it sends anything (not between steps), so nothing
reaches the site before the owner approved. Every use of a `card` waits, whatever the
limits say. Amounts come only from a required, bounded query parameter or JSON input member
(or the policy); a body contract is next. A payment within the owner's limits is counted
when the node decides to send it, under the same lock as the check, even if the request then
fails: counting early can only make the owner approve sooner, never let a split payment
through.

## 6. Browser fills (card and login on JavaScript pages)

The agent works in a cloud browser (Kernel). Secrets enter that browser only through the node,
only on the approved origin, and only while the agent is detached.

1. The agent's controller brings the page to the form and calls the node:
   `fill {item, field map, expected origin}` with the CDP endpoint and its token.
2. The node connects to the browser over TLS from inside the enclave, and:
   - detaches the agent: the controller hands over the session (Kernel live view off, the
     controller's CDP client paused); the node refuses to fill if another client is attached;
   - checks the top-level origin and the form's `action` / the fetch target the page will use,
     against the item's origin;
   - removes listeners the agent could have planted: the fill runs in a fresh isolated world,
     and the node refuses when the page has scripts injected through CDP since the last
     navigation (it tracks `Page.addScriptToEvaluateOnNewDocument` and `Runtime.evaluate`
     calls of the session it took over);
   - types the values with `Input.insertText`, submits, waits for navigation;
   - blanks the fields it filled if the page is still there, and returns only
     `{outcome, final origin}`.
3. Approval (payments) happens before step 2; 3-D Secure becomes a challenge (section 5).
4. The controller must mask: screenshots and DOM reads it hands to the model never contain the
   filled values. That is outside this repository; the node helps by returning the selectors
   it filled.

What this cannot stop: the site's own page sees the values (as it would for a person), and
Kernel, which runs the browser, can read its memory. Section 9 states both; Kernel's PCI DSS
status must be confirmed before cards go live.

**Implementation.** Done as the `browser` connection kind and the `fill` member of `send`
(`docs/policy.md`, Browser fills), with the CDP client in `engine::cdp` and
`engine::node` over the existing transport (`Transport::exchange_streamed`, as a WebSocket),
so the transport crate did not change. Choices made where this section left them open,
each the more secure one:

- **The node connects; the caller never relays CDP.** CDP carries the typed value in the
  clear inside its WebSocket, so a caller relay would read it, and could answer for the
  browser. The endpoint is a destination of the signed policy, reached over TLS; the caller
  chooses at most the handshake request within its contract (which session).
- **Values are set on the element found, not typed into the focus.** `Input.insertText`
  goes to whatever has the focus when it arrives, which the page can move (into a
  cross-origin frame, too); the node calls a fixed function on the element it resolved, in
  an isolated world, which checks `location.origin` and `location.ancestorOrigins` in the
  same task that sets the value.
- **The submit is required and the fields are blanked** when the page stays, so the values
  do not wait in the page for the controller to read them.
- **A frame is used only when the policy names its origin**, and only as a direct child of
  the top frame; the page and frame origins are `https` and concrete (no `*.`).
- **A page another client is attached to is refused**, as is a second tab at the origin.

Not done here: the node cannot tell scripts an earlier client injected (it does not see
that session); `navigate` reloads the page at a fixed path instead. The item kinds `card`
and `login` do not take browser operations yet.

## 7. Protocol tunnels

The node authenticates to the server with the secret, then relays bytes. Callers keep their
tools: `credentials tunnel --item prod-db --listen 127.0.0.1:5432` opens a local port; `psql`,
`ssh`, `mysql`, FileZilla connect to it unchanged.

```
client tool -> credentials tunnel -> (signed call, TLS) -> node: authenticate, then relay -> server
```

| Protocol | Node-side work |
| --- | --- |
| SSH, SFTP, SCP | SSH client (`russh`); host key pinned in the item; caller gets exec / shell / sftp channels |
| PostgreSQL | startup + SCRAM-SHA-256 / MD5 / cleartext over TLS, then relay |
| MySQL, MariaDB | handshake + `caching_sha2_password` / `mysql_native_password`, then relay |
| MongoDB | SCRAM-SHA-256 in OP_MSG, then relay |
| Redis | `AUTH` / `HELLO`, then relay |
| MSSQL | TDS login7 (SQL auth; NTLM later in the same module) |
| FTP, FTPS | control channel `USER`/`PASS`, `AUTH TLS`, PASV data connections relayed |
| SMTP, IMAP, POP3 | text auth (`stream`, exists) + STARTTLS |
| LDAP | simple bind over LDAPS / StartTLS |
| SMB | NTLMv2 session setup |
| Telnet | text login (`stream`) |
| MQTT | CONNECT with username/password or TLS client certificate (also over WebSocket) |
| AMQP 0-9-1 (RabbitMQ) | SASL PLAIN / AMQPLAIN / EXTERNAL |
| Kafka | SASL PLAIN, SCRAM-SHA-256/512, OAUTHBEARER, or mTLS |
| NATS | token, user/password, or nkey: the node signs the server nonce with the seed |
| STOMP | CONNECT login/passcode |
| XMPP | SASL SCRAM-SHA-1/256, PLAIN |
| Kerberos | AS-REQ with the password-derived key, then service tickets (for SMB, LDAP, HTTP Negotiate) |
| RADIUS | Access-Request with the shared secret (UDP, below) |
| RDP, VNC | last: RDP NLA (CredSSP) and VNC auth |

Every module: TLS (or SSH) ends inside the enclave; a fuzz target for its parser; the
credential never written into the relayed stream after authentication; a log entry per
session with start, end and byte counts (contents only if the policy asks for it).

**Implementation.** crate `tunnel` (protocol modules, behind one `Authenticator` trait),
`engine` operation kind `session`, the caller side in `cli` (`credentials tunnel`), the
relay over the existing vsock egress.

## 7a. WebSocket, streamed responses, long connections

| Case | Node-side work |
| --- | --- |
| WebSocket, credential at the handshake | headers, cookie or query injected into the upgrade request (as for HTTP) |
| WebSocket, credential in the first message | a template for the first frame (Discord `IDENTIFY`, exchange `login`), then relay |
| WebSocket, every message signed | a template applied to each outgoing frame the policy matches (exchange orders: HMAC over the frame, a nonce or time in it); frames that do not match a declared shape are refused |
| GraphQL subscriptions, JSON-RPC over WebSocket | as above |
| Server-sent events, chunked and streamed responses (LLM APIs, long downloads) | the node forwards the body as it arrives instead of buffering it |
| gRPC streaming | over HTTP/2 (section 8), frames forwarded both ways |

Reflection scrubbing on a stream keeps the last `n - 1` bytes of each chunk back, where `n` is
the longest encoded form of any secret, so a secret split across two chunks or frames is still
caught. On a TLS stream the caller's exchanges end at the caller's delimiters, which would make
read boundaries an oracle on an echoed secret; there the reader (`reflection::delimit`) skips
any match that a secret's form overlaps, looking ahead as far as one could reach, and keeps the
bytes read ahead for the next read. Streams have their own limits apart from the 10-second request deadline of plain calls:
an idle timeout, a total duration, byte counts and a cap on open streams per caller, owner and
node; each stream writes one log entry when it opens and one when it closes.

**Implementation.** `tungstenite`-style framing in `transport` (no async runtime; the server is
synchronous), operation kind `socket` with `handshake`, `first`, `each` templates and declared
frame shapes; streamed bodies through a `Sink`-like writer in `server`; the caller side opens a
WebSocket to the node through `credentials host`.

## 7b. UDP

The enclave reaches the network only through TCP connections the host relays (vsock port
5001). UDP needs a second relay: datagrams framed over vsock, the host sending them to the one
`host:port` the node asked for and returning replies from that address only.

| Use | Node-side work |
| --- | --- |
| HTTP/3 (QUIC) | `quinn`-style QUIC client in `transport`; only for destinations that refuse HTTP/2 |
| WireGuard | handshake and transport keys in the enclave (`boringtun`-style), the caller gets a tunnel to the peer's network; the private key never leaves |
| IPsec / IKEv2 | IKEv2 with PSK or certificate; later than WireGuard |
| SIP, RTP (calls) | SIP digest authentication; media relayed |
| RADIUS, DNS over UDP | request authenticators and TSIG signatures computed by the node |

**Implementation (part 9).** A `udp` connection kind (`docs/policy.md`, UDP) for request and
response protocols that protect their own messages with a MAC: each `send` is one datagram,
each `receive` one datagram, the destination fixed by the policy, the reads searched like every
stream read, one log entry per operation with the hash of the caller's sends. Since nothing
encrypts a datagram, a `send` template on `udp` may not be tainted: secrets reach a datagram
only through one-way functions (RADIUS Message-Authenticator, TSIG, STUN MESSAGE-INTEGRITY,
EAP-MD5 over a captured challenge). Protocols that put a secret in reversible form into a
datagram (RADIUS PAP, User-Password hidden by MD5 of the shared secret and a node-chosen
authenticator; CHAP with a node-chosen challenge) are refused at signing: the host of an
enclave reads every datagram. No protocol module: the families are generic.

The enclave egress for datagrams: the node opens a vsock link to the same port 5001 and sends
`DATAGRAM host:port\n` instead of `CONNECT host:port\n`; the host checks
`udp/host:port` against its `--allow` list (a TCP entry does not allow datagrams; an empty
list allows everything, as for TCP), opens a UDP socket connected to the first address of the
name (the kernel drops datagrams from any other address), answers `OK`, and relays frames
(two-byte big-endian length, 1 to 65,507 bytes) both ways until the link closes or 130 s
pass with no datagram (`relay::datagram`, `host`). On the node, `TlsTransport::datagrams`
takes a `RelayDatagramConnector` in the enclave and a plain UDP socket elsewhere
(`transport::udp`): a read waits at most 10 s, sending the last datagram again after 1, 2 and
4 s. The Linux paths of `host` and `enclave` were not compiled on the machine that wrote them
(no Linux target installed); the same functions run in `crates/relay/tests/datagram.rs` over a
local TCP link.

DTLS is not offered. The maintained synchronous candidate, `dimpl` 0.8/0.9 (Sans-IO, DTLS 1.2
and 1.3, `forbid(unsafe_code)`), depends with its `rust-crypto` feature on the previous
RustCrypto generation (`p256` 0.13, `aes-gcm` 0.10, `sha2` 0.10, `hmac` 0.12) next to the 0.14 /
0.11 generation the engine uses, and leaves certificate validation to the caller; its size in
`credentials.exe` was not measured. The HTTP/3, WireGuard, IPsec and SIP rows above stay
protocol modules of later parts.

## 7c. Protocol connections (part 6, second half)

Done: `ssh`, `postgres`, `smtp`, `imap` and `redis` as connection kinds (`docs/policy.md`,
Protocol connections), each a protocol family in `engine::proto`, never a site's. Choices the
design left open, and the more secure option taken:

- **SSH is own code on ring, chosen by measurement.** A minimal client binary with russh 0.54
  (ring backend; its default aws-lc backend does not build without NASM) was 1,777,664 bytes
  with 172 crates, needed tokio and an older RustCrypto generation (sha2 0.10, p256 0.13,
  ed25519-dalek 2, rsa 0.9) next to the engine's, and carries `sha1` and `cbc`. ssh-rs 0.5.0
  was 1,173,504 bytes with 93 crates and synchronous, but has no AES-GCM and no
  keyboard-interactive, and offers `ssh-rsa`, `diffie-hellman-group1/14-sha1`, CBC and
  `hmac-sha1`. The engine's client (`proto/ssh.rs`, 1,679 lines) uses ring for curve25519,
  ECDH P-256/P-384, AES-GCM, ChaCha20-Poly1305 (`chacha20_poly1305_openssh`), Ed25519, ECDSA
  and RSA, and the `p521` crate already in the tree for P-521; it adds no crate. All five
  clients together add 460,800 bytes to the release `credentials.exe` on Windows
  (11,116,032 before, 11,576,832 after).
- **Algorithms:** key exchange `curve25519-sha256`, `ecdh-sha2-nistp256/384/521` and strict
  KEX (Terrapin); ciphers `aes256-gcm`, `aes128-gcm`, and `chacha20-poly1305` only under
  strict KEX; host keys only of the pinned types, RSA only as `rsa-sha2-256/512`. SHA-1, CBC,
  CTR with a MAC, DSA and finite-field groups are never offered. A rekey is refused: the node's
  connections are short and bounded by their limits.
- **SSH host keys are pinned in the signed policy** and checked before any credential is
  sent; there is no trust on first use.
- **PostgreSQL takes SCRAM-SHA-256 only** (no MD5 or cleartext even over TLS) with 4096 to
  1,000,000 iterations, and verifies the server signature before it accepts
  `AuthenticationOk`. Channel binding (`SCRAM-SHA-256-PLUS`) is not used: TLS already verifies
  the certificate of the destination's host, which is what binding adds against a relay. No
  SASLprep: the password is used as its bytes (equal for ASCII passwords).
- **SMTP and IMAP use the mechanism the policy names or none.** The policy, not the server,
  picks; a server that does not offer it is refused before any credential is sent.
- **STARTTLS before anything else**, and bytes the server sent after its go-ahead fail the
  call (the CVE-2011-0411 class).
- **Parameters are never spliced into a command**: bound (PostgreSQL), one bulk string
  (Redis), one POSIX single-quoted word (SSH), a quoted string with CR, LF and NUL refused
  (IMAP). Mail with a bare CR or LF is refused (SMTP smuggling), and data is dot-stuffed.
- **Results are searched twice**: as the server sent the values (raw cells, bulk strings) and
  as the JSON that goes back, then across results.
- **A protocol connection counts as an open connection** (caller 4, owner 16, node 256) and
  logs a `use` and a `closed` entry. The transport's total deadline (120 s by default) also
  bounds it, as it bounds a WebSocket.
- **Reading a code from a mail item** (section 5, Challenges): an IMAP operation reads the
  message with a fixed command and captures the code into a temp or field; it never goes back.

Measured on this host (Windows, release, `cargo test --workspace`): tests 397
before, 470 after; the protocol tests run against servers in the test process (an
SSH server on RustCrypto AES-GCM, ed25519-dalek and p256, a SCRAM server on the RustCrypto
`pbkdf2` and `hmac`), with no network.

Then: `mysql`, `mqtt` (3.1.1 and 5) and `amqp` (0-9-1) as connection kinds, SFTP and local
port forwarding over SSH, and the `ssh` and `mail` typed kinds. Each is own synchronous code
over the engine's `Io` and ring (`proto/mysql.rs` 873 lines, `mqtt.rs` 651, `amqp.rs` 569,
`sftp.rs` 365); no crate was added, so there was no crate size to compare against. Choices
left open, and the more secure option taken:

- **MySQL: TLS before anything, `caching_sha2_password` only.** A greeting without
  `CLIENT_SSL`, or bytes after it before the handshake, is refused before the node writes
  anything. One auth switch, and only to `caching_sha2_password`; `mysql_native_password`
  (SHA-1, replayable from a captured exchange), cleartext and other plugins are refused. Full
  authentication sends the password only over the verified TLS, never with the server's RSA
  key (which the node could not authenticate). `CLIENT_LOCAL_FILES`, multi-statements and
  multi-results are never offered, and a `LOCAL INFILE` request fails the call. Every command
  is a prepared statement with each parameter bound as a string, closed after use.
- **MQTT: TLS from the first byte, QoS 0 and 1 only**, no retain, will or topic alias; clean
  sessions, and a random client id (`credentials-` and 96 random bits) unless the policy fixes
  one, so two calls never take over each other's session. A topic or filter of the caller
  never holds `+` or `#`; only the policy may subscribe with wildcards. A message the broker
  sends on a topic no subscription matches, at QoS 2 or with an alias, fails the call. A
  caller's `subscribe` collects within `max_messages` and `wait_ms` and unsubscribes; a
  policy's stays for a live relay, which hands back each message as a text part after the
  reflection search of that message whole, and takes no frames from the caller.
- **AMQP: `PLAIN` only, over TLS**, and `connection.secure` (a challenge the node did not
  choose) is refused. The node uses one channel, heartbeats off, frames of at most 128 KiB.
  Publishes are mandatory and confirmed, so a message no queue takes is an error, not a silent
  loss. The exchange, routing key and queue are always templates of the policy.
- **SFTP follows no symbolic link.** A path is absolute, with no empty, `.` or `..` segment,
  backslash or NUL (`sftp::normalize`), checked when signing, before the log and before
  sending. Before an open the server's `REALPATH` must return the path itself (its directory,
  for a write) and `LSTAT` a regular file (or nothing, for a write). Following links within the
  pattern was the other option; refusing them is simpler to reason about.
- **Forwarding goes only to a literal `host:port` of the policy**, one per streaming call, and
  that relay holds only forward rules. Its destination is flagged in the summary. What it
  exposes is in the threat model.
- **A caller value can go through a policy template** (`pattern` and `template` with
  `$input`): the pattern checks the value, and the template fixes the rest, so an SFTP path or
  a payload keeps its fixed prefix.
- **Typed `ssh` and `mail` sign in only with their own fields.** Each `login` member must be
  exactly `{{field}}` of the field the kind names; an SSH policy pins exactly the item's host
  key, as a whole key (a fingerprint passes the field's check, but the node compares keys).
  Mail routes SMTP and IMAP each to its own pinned server, so `host` and `port` became
  `smtp_host`, `smtp_port`, `imap_host` and `imap_port` (required).

Measured on this host (Windows, `cargo test --workspace --locked --no-fail-fast`): tests
498 before, 553 after, 0 failed; the release `credentials.exe` 12,044,288
bytes before, 12,329,984 after (+285,696). The new tests run against a MySQL, MQTT, AMQP and SFTP server
written in the test process, and the SSH test server now does P-384 (SHA-384) and P-521
(SHA-512) key exchange, RSA host keys (`rsa-sha2-256/512`, keys generated with the `rsa`
crate in the test), and verifies ECDSA P-256/P-384, RSA PKCS#1 and OpenSSH-format client
keys, all generated in the tests.

Then: `pop3` and `ftp` (over TLS only) as connection kinds, and SFTP `list`, `stat`,
`rename`, `delete`, `mkdir` and `rmdir` (`proto/pop3.rs`, `proto/ftp.rs`, `proto/sftp.rs`;
`docs/policy.md`, Protocol connections). No crate was added (`md5`, for APOP, was already in
the tree). Choices, and the more secure option taken:

- **No credential over plain FTP or POP3, for any address.** The rule allows plaintext only
  where the owner's policy allows it for a private address the way other kinds do; no kind
  allows that today, so neither do these: `tls` is `implicit` or `starttls` only, and the
  `ftp` kind's `plain` mode, even signed off, allows no operation. A plain mode can be added
  the day a kind has the private-address sign-off, not before.
- **FTP data connections are passive, to the same address, over resumed TLS.** Active mode
  (`PORT`, `EPRT`) would have the server connect to the node; it is never sent. `EPSV` gives
  only a port; a `PASV` address must equal the address the control connection reached (the
  transport's `peer_ip`), and the transport connects to that exact address
  (`Connector::connect_again`), so a reply naming another host (FTP bounce, SSRF into the
  node's network) is refused before anything connects, and DNS is not asked again. Ports
  below 1024 are refused. The data connection uses the control connection's TLS client
  configuration, so rustls resumes the session (RFC 4217 section 10: servers may require
  that reuse), and verifies the same name. `PROT P` is required before any data connection
  opens.
- **The end of an FTP data connection must be a TLS `close_notify`.** For the other kinds a
  cut is still an end the engine's framing checks; for FTP the end of the connection is the
  framing, so a cut (a truncation attack) fails the transfer.
- **Replies are scrubbed of the sign-in.** A server may echo the user name or password
  (`530 Login incorrect for hunter2`); the values the sign-in used, raw and in base64, are
  replaced by `[redacted]` in every reply text that goes back (`proto::io::Scrub`, values of 4
  bytes or more, as the reflection search). The reflection search still fails a call whose
  result holds a secret in any other form, such as a message body.
- **APOP is allowed and flagged.** It never sends the password, but MD5 over a server-chosen
  timestamp lets the server or a reader of the exchange test guesses offline; the summary
  flags `weak_mechanism`. `USER`/`PASS` is flagged `password_to_server`, like `PLAIN`.
- **Paths and numbers carry no command.** An FTP path is absolute UTF-8 of at most 4096 bytes
  with no control byte, DEL or `0xFF` and no `.`/`..` segment; a POP3 parameter is 1 to 10
  digits; verbs are the policy's.
- **Bounds:** FTP replies of 256 lines of 4 KiB, listing lines of 8 KiB and 10,000 entries,
  files within the connection's byte limit; POP3 status lines of 4 KiB and message lines of
  64 KiB; SFTP listings of 10,000 entries. A protocol line that arrives whole is now held to
  the line bound too (before, one longer than the bound passed when its end was buffered).
- **SFTP management follows no link either.** `stat` takes no link; `delete` takes a regular
  file, `rmdir` a directory, `rename` a file or directory to a name that does not exist (no
  overwrite); a listing shows links as `link`.

Measured on this host (Windows, `cargo test --workspace --locked --no-fail-fast`): tests
659 before, TESTS_AFTER after, 0 failed; the release `credentials.exe` 12,968,448 bytes
before, SIZE_AFTER after (SIZE_DELTA). The new tests run against an FTP and a POP3 server
written in the test process (data connections as pipes through the test transport) and the
SFTP test server's new requests; a transport test checks against local TLS servers that the
data connection reaches the control connection's address and resumes its session
(`HandshakeKind::Resumed`), and that a cut without `close_notify` is an error. Not measured:
real FTP and POP3 servers.

Left for later:

- Tunnels as an IR relay step; SSH agent forwarding. (Remote forwarding, `tcpip-forward`, is
  done: see below.)
- FTP over plain TCP for a private address, once a kind has that sign-off; FTP `REST`
  (resumed transfers), `APPE`, `SITE`, `MDTM`; POP3 `PIPELINING`.
- Typed protocol connections for the `database` and `queue` kinds (they still allow none:
  their `engine` or `protocol` field would choose the connection, which the kind's shape
  cannot express yet), and the `vpn` kind.
- A race on the SFTP server between the `REALPATH`/`LSTAT` check and the open, open to whoever
  can change the server's files in between; SFTP v3 has no flag that refuses links on open.
- A live MQTT relay searches each message whole, but not a secret split across two messages;
  the stream search of SSH spans frames, the message search does not.
- MQTT 5 properties beyond the maximum packet size (user properties, response topics), MQTT
  over WebSocket, and AMQP consumers (`basic.consume`) as a live relay. (AMQP 1.0 is done:
  see below.)

- MySQL `COM_QUERY` text results, compression and the server's RSA key exchange (refused on
  purpose; listed so it stays a decision).
- The transport's `open_plain` and `open_starttls` over a real socket, and real servers of
  each kind, are not exercised by a test; the fuzz target was checked to build, not run (it
  needs nightly and libFuzzer).

### SSH remote forwarding and AMQP 1.0

The two protocol rows left above, done (`docs/policy.md`, Protocol connections).

- **Remote forwarding** (`channel: "tcpip-forward"`, RFC 4254 section 7.1). The bind is a
  literal `address:port` of the signed policy, never 0 and never the caller's. Where the
  forwarded connection goes was the open choice: a socket the node would open to a local
  target the policy names, or the call itself. The node takes the second, the more secure
  one: it opens no socket and no listener, so the caller's stream is the local end, and
  nothing on the node's side becomes reachable from the server. The client takes one
  `forwarded-tcpip` channel per call, only after the server agreed to the forward and only for
  exactly its address and port, while no other channel is open or waiting; every other open is
  refused, and more than 16 refusals end the connection (a server cannot spin the node). The
  accepted channel takes a live slot of its own (4 per caller, 16 per owner, 256 per node) and
  is refused as a resource shortage when the slots are full; a hand-over refuses a waiting one
  and ends an open one; the forward is cancelled at the end. A wildcard bind (`*`, `0.0.0.0`,
  `::`) needs `wildcard_bind: true` and is flagged; every remote forward is flagged
  `remote_forward`.
- **AMQP 1.0** (`connection: "amqp1"`, its own client `proto::amqp1`, next to 0-9-1). The type
  system codec is bounded per decode (16 deep, 16,384 values, descriptors a `ulong` or a symbol
  of at most 256 bytes: an array repeats its descriptor for each element, so a long one would
  multiply into memory). TLS is the only mode: implicit, or the AMQP TLS header; a plain mode
  for a private address was left out, as for every other kind, since no kind has that sign-off
  yet. SASL takes `PLAIN`, `EXTERNAL` (the open's client certificate), `SCRAM-SHA-256` (the
  PostgreSQL SCRAM with a user name; the broker must prove the password) and `XOAUTH2`. One
  connection (64 KiB frames, channel-max 0), one session, one link at a time (handle-max 0).
  `send` and `receive` take the address from the policy; the settle mode is the policy's, and a
  broker that changes it is refused rather than followed (the caller's guarantee, such as at
  most once for `settled`, is the policy's, not the broker's). Text in a broker's error is
  scrubbed of the user name and the secret.

Measured on this host (Windows, `cargo test --workspace --locked --no-fail-fast`): tests
MEASURE_BEFORE before, MEASURE_AFTER after, 0 failed. The new tests run against an AMQP 1.0
broker and the SSH test server's remote forwarding, both in the test process (the broker
encodes with the engine's codec); the fuzz targets `amqp1_frames` and `protocol_servers` were
checked to build (clippy), not run. Not measured: real SSH servers forwarding remotely, real
AMQP 1.0 brokers, the release size (CI measures it).

## 8. Transport and engine gaps

| Gap | Change |
| --- | --- |
| Values in HTML (CSRF tokens, hidden inputs) | capture source `html {selector}` and `regex {pattern}` (linear-time `regex` crate, size limits) |
| Sites that encrypt the password in JavaScript | `rsa_encrypt_pkcs1`, `rsa_encrypt_oaep`; the public key must come from the policy or from the destination's response, never from the caller |
| Missing algorithms | `sha384`, `hmac_sha384`, `pbkdf2_sha1`, `md4`, `hmac_md5`, `aes_ecb`, `des` (for VNC), `ed25519` already |
| HTTP/2, gRPC | `h2` in `transport`, ALPN; gRPC framing for injected metadata |
| Reflection | every response path (HTTP bodies, headers, errors, stream bytes, WebSocket frames, datagrams, CDP results) scrubbed of every secret value and its common encodings before it leaves |
| Tokens obtained by the node | always re-sealed into the item, never returned (exists for OAuth capture; extended to sessions) |

## 8a. Further schemes possible in principle

| Scheme | Where it is used | Change |
| --- | --- | --- |
| OAuth 1.0a | older APIs (X v1.1, Garmin, some e-commerce) | HMAC-SHA1 / RSA-SHA1 over the normalized parameter string; `canonical_query` gains the OAuth normalization |
| OAuth 2.0 authorization code + PKCE, device code | first connection of an account | the consent runs on the owner's device (or the device-code page), the app seals the tokens; the node only refreshes |
| DPoP, HTTP Message Signatures (RFC 9421), Hawk | newer APIs, banks | per-request proof JWT or signature base built by template; `htm`, `htu`, `jti` from the request and the node's nonce |
| AWS SigV4A | multi-region AWS | ECDSA P-256 with the key derived from the secret (new derivation function) |
| NTLM and Negotiate over HTTP | corporate intranets, SharePoint, Exchange | NTLMv2 (MD4, HMAC-MD5) and Kerberos (section 7) for `WWW-Authenticate: NTLM / Negotiate` |
| SAML and OIDC single sign-on | enterprise logins | multi-step HTTP with `html` capture of `SAMLResponse` / form posts; `private_key_jwt` client authentication by derive |
| SRP-6a | Apple ID, Proton, 1Password-style logins | big-integer SRP client functions; the password never leaves |
| Payload encryption: JWE, SEED, ARIA | Korean PG and bank APIs, government APIs | `jwe_encrypt` (RSA-OAEP / ECDH-ES + AES-GCM), SEED and ARIA ciphers (KISA) |
| Korean certificates (공동인증서, NPKI) | tax, bank and government APIs | item `certificate`: `signCert.der` + `signPri.key` + its password; the node decrypts the key (SEED-CBC with PBKDF) and makes CMS/PKCS#7 signatures; sites that require their own browser plug-in stay out |
| Software passkeys | passkey-only sites | the node registers a passkey of its own with the site (owner approves), keeps the private key and answers WebAuthn assertions, through the CDP virtual authenticator or directly |
| HOTP, Steam Guard, other OTP variants | games, older 2FA | counter-based `hotp` (counter stored in the item), Steam's alphabet |
| SMS codes without the owner | sites that only send SMS | a phone number the node controls (an SMS provider account as an item); the node reads the code itself |
| OpenPGP | signing, decrypting mail and files | item `pgp`; sign and decrypt by derive, the private key stays |
| ssh-agent | `git`, `ssh`, `scp` with the caller's own tools | the node answers the ssh-agent protocol through `credentials tunnel --agent`, signing challenges without handing over the key |
| Schnorr (BIP-340), EIP-712, Solana | Bitcoin Taproot, typed Ethereum signatures | `secp256k1_schnorr_sign`; EIP-712 by templates over `keccak256` |
| Incoming webhooks | Stripe, GitHub, Slack callbacks to the service | operation `verify`: the node checks a signature over the caller's payload and returns one bit |
| Decrypting what a service sent | encrypted API responses, PGP mail | derive `decrypt` whose output is the plaintext of the data, never the key |
| Secrets made inside the node | new site passwords, rotated API keys, SSH keys | `generate` (random password to a site's rules, key pairs): the value is sealed into the item and never shown; rotation flows change a site's password with the old one and keep only the new |
| Egress through a proxy | sites that block data-centre addresses, sessions bound to the owner's network | upstream HTTP CONNECT or SOCKS5 (with proxy credentials as secrets), including a relay on the owner's own network |

## 8b. Owner controls and credential vending

| Scheme | Where it is used | Change |
| --- | --- | --- |
| Spending limits (done in part 5) | real cards, exchange orders, transfers | per item, merchant, day and month limits kept by the node; above them an approval (section 5); the day and month are rolling 24 hours and 30 days, so a payment cannot be split across a calendar boundary |
| Short-lived credentials handed to the caller (done in part 11) | `aws`, `gcloud`, `kubectl`, GitHub Apps, databases with IAM tokens | operation `vend`: the node mints a scoped, short-lived credential from the long-lived secret (STS AssumeRole with a session policy, a GCP downscoped token, a GitHub installation token, an RDS IAM token) and returns only that; the owner's policy sets scope and lifetime |
| SASL XOAUTH2 / OAUTHBEARER | Gmail, Outlook over IMAP and SMTP | the mail item takes an OAuth token instead of a password |
| ACME, JWS in general | certificates (Let's Encrypt), any JWS API | account key JWS by derive |
| Kubernetes | API servers | client certificates and bearer tokens over HTTPS; `exec` credentials through `vend` |
| SNMPv3 | network devices | USM (HMAC, AES) over the UDP relay |
| Delegation (done in part 11) | family members, a colleague's agent | an owner grants another owner's callers a narrower policy on an item; revocable, logged on both sides |
| Emergency access (done in part 11) | when the owner is gone | a delegate whose access opens after a waiting period the owner can cancel from a device |

## 8c. Flows no list names

Control flow lives in the policy IR (layer 2): bounded loops, branches on captured values,
binary framing through the codecs, retries on a server nonce. Agent-written flows therefore
stay analysable, and the earlier idea of agent-written WebAssembly over secret handles is
dropped: it would duplicate the IR with a weaker analysis.

Code that must compute on secret bytes is layer 3 and is never written by an agent or an
owner: even with the output confined to the site, such code could encode the secret in a field
the site echoes back (a nickname, a search term) under a transform the reflection filter
cannot recognise.

## 8e. Running the site's own code

Some logins encrypt or package the password in the site's JavaScript or WebAssembly before the
API call (an RSA key and session key fetched first, a fingerprint blob, a custom cipher). Three
ways, in order of preference:

1. **Express it**: when the steps map onto node functions (fetch the key, `rsa_encrypt_*` over
   a length-prefixed concatenation, captures), it is an ordinary policy.
2. **Values without secrets stay outside**: a part that does not depend on a secret (a device
   fingerprint, a proof-of-work) can be computed by the caller or the browser and passed in as
   an input; it gives the caller nothing it did not have.
3. **Site code in the node**: the node fetches the script or module **from the site's own
   origin** (the URL and, optionally, a hash pinned in the signed policy), runs it in a sandbox
   (the WebAssembly sandbox of layer 3, a JavaScript engine running inside it, with no I/O,
   fuel and memory limits, and only the browser APIs the policy lists, emulated), passes it the
   secret, and treats its whole output as **tainted**: it can only go into the request to that
   same site, never back to the caller. The site already receives the secret, so running its
   own code on it gives it nothing new; the caller still sees nothing.

Measured example (Naver login page, `login.js?v=20260918`, read 2026-11-25): the password
goes in `eccpw`. The page fetches `/login/dynamicEcKey/<dynamicKey>` (`sessionKey,serverKey`),
makes an ephemeral P-256 key, hashes the ECDH x-coordinate's hex string with SHA-256 into an
AES-256-CBC key, and encrypts `len·sessionKey·len·id·len·pw` under a random IV; the form sends
`ciphertext,iv,ephemeralPublicKey,sessionKey`. That is case 1 once the generic families
of section 8d are in (ECDH on every standard curve, fixed-width integer encoders, random bytes);
no function is ever added for one site. The anti-bot `wtoken` comes from a
separate captcha script whose callback receives no credentials, and the page empties the id
and password fields before calling it: case 2. `bvsd` is sent empty by this page version.

Limits: code that needs a real browser environment (DOM, canvas, timing, the owner's network)
cannot be emulated faithfully and goes through a browser fill (section 6); a site whose code
changes on every load needs the hash left unpinned, which the approval screen flags.

**Implementation.** this is layer 3: IR step `run {module, entry, inputs}`; one WebAssembly
runtime in the node, and a JavaScript engine compiled to WebAssembly as a reviewed module, so
there is one sandbox to audit. Runtime and engine are chosen by measured size, speed and audit
surface in their pull request: the runtime is wasmi 1.1.0, an interpreter (measurements and
the JavaScript plan in `docs/sandbox.md`; the step in `docs/policy.md`, `run`).

## 8d. Primitives shipped up front

Functions are never added for a site. They are added as whole families (every curve, every
hash width, every integer width) taken from standards, so that what one site needs is already
there for the next.

Primitives are the one part that needs a release, so the first release that adds a group
adds all of it, taken from the registries (IANA JOSE, COSE, SASL, SSH, TLS signature schemes,
HTTP authentication schemes) rather than from site-by-site demand: every hash, MAC, KDF,
signature, key agreement, key wrap and cipher those registries list and that is not
deprecated, plus the national ciphers (SEED, ARIA) and big-integer arithmetic for SRP. The
audit of the registries against this document is Appendix A, entry by entry.

## 9. Who sees what

| Value | Owner device | Node | Destination | Kernel / site page | Service servers | Agent / model |
| --- | --- | --- | --- | --- | --- | --- |
| Password, token, key | yes | yes | yes | only for a fill | no | no |
| Card number, CVC | yes | yes | PSP / merchant | yes (fill) | no | masked only |
| One-time code | yes | yes | yes | if typed into a page | no | no |
| Session cookie | after device login | yes | yes | yes (browser task) | no | no |
| Identity fields | yes | yes | listed origins | when filled | per disclosure | per disclosure |
| Results of calls (mail text, pages) | | yes | | | yes | yes |

## 10. Node continuity

A Nitro node has no sealed storage; a new release is a new node. Releases hand over:

1. The release workflow signs a **successor statement** (from release X to the measurements of
   release Y) with Sigstore keyless signing tied to this repository's workflow, logged in
   Rekor. The signer identity is compiled into the EIF.
2. The old node checks the new node's attestation (the `attest` crate, inside the enclave),
   that its PCRs match a successor statement, and that it is not older; then re-seals grants,
   devices, floors and items to the new node's key and writes a hand-over entry. The new node's
   log starts with that entry's hash, so `credentials verify` checks one chain across nodes.
3. Owners opt in per grant (`allow_successor`), on by default for releases signed as above.
4. If the old node is gone (crash), owners' apps re-grant after verifying the new node:
   `client` does it on the next app start, with the owner's approval policy.

The design admits several nodes; one runs at first (cost). With several, an owner grants to
each, or a node hands its grants to a peer of the same release.

As built (part 10):

- **Statement**: `successor.json` (`{"type": ".../successor/v1", "from": <measurements of X>,
  "to": <measurements of Y>}`) and `successor.sigstore.json` (a Sigstore bundle v0.3 of a
  `hashedrekord` entry), published with release Y. `crates/continuity` verifies it offline:
  the certificate chain to a pinned Fulcio root at the time Rekor integrated the entry, the
  signer (SAN `https://github.com/BloubHQ/credentials/.github/workflows/release.yml@refs/tags/<Y>`,
  issuer `https://token.actions.githubusercontent.com`, runner `github-hosted`, repository and
  ref extensions), the signature, the log entry, the signed entry timestamp and the inclusion
  proof up to a checkpoint signed by a pinned Rekor key. Both log proofs are required (the more
  secure choice: either alone would let one compromised key vouch). No maintained pure-Rust
  verifier of the current RustCrypto generation existed, so the checks are written out and
  fuzzed. Not checked: the certificate's SCTs (a residual risk in `docs/threat-model.md`).
  The trust root is `crates/continuity/trust/trusted_root.json`, compared with Sigstore's TUF
  repository by the release workflow; it is empty in the source until it is committed, and an
  empty root refuses every statement.
- **Order**: releases are Semantic Versions; `to` must be newer than `from` (a statement that
  is not is refused as a downgrade before its signature is read), `from` must be the old node's
  compiled release (`CREDENTIALS_RELEASE`, set by `build/build.sh`), and the new node's PCRs
  must be the statement's `to` measurements and nothing else.
- **Protocol** (`continuity::protocol`): four messages, relayed by the host over vsock port
  5003 of each enclave (`credentials hand-over --from-cid --to-cid`): a challenge with a nonce
  from the old node; the new node's attestation over it, bound to its identity, and its own
  nonce; the old node's attestation and the package; the take-over. Each node attests to the
  other (mutual); nonces are used once, within five minutes. The package is a sealed message,
  not a TLS session: HPKE (X25519, HKDF-SHA256, ChaCha20-Poly1305) to the new node's seal key,
  with the hand-over header as additional data, inside a hand-over entry signed by the old
  node. The host sees ciphertext only.
- **What moves**: for every owner, devices, retired devices, the issue time of the last grant,
  record floors and spending limits (the protective state, always); the user key only for
  grants with `allow_successor` that have not expired. Records stay sealed under the user key
  and move with it; the floors keep a host from serving older copies to the new node.
- **Log**: the old node's last entry is `HandOver` (successor identity, release, statement
  and package hashes, counts); the new node's first is `Continue` (prev = that entry's hash),
  then one `Carry` per owner. `ChainVerifier` switches keys at the hand-over and refuses any
  further entry of the old key (a fork); `credentials verify <old> <key> --next <new>` checks
  one chain. The old node refuses every act once it has handed over.
- **Crash path**: `client::verify_successor` checks a newer node against the statement of the
  release the owner granted to, then `client::regrant` grants under the owner's
  `SuccessorPolicy` (`Automatic`, `AskOwner`, `Never`).
- **Keys on a new phone**: `client::wrap_keys` (format `credentials-key-backup/v1`,
  XChaCha20-Poly1305 under a random backup key the app keeps in iCloud Keychain or Google
  Block Store; no passphrase mode, as a memorable passphrase is guessable offline from the
  blob), and a 6-digit device transfer over SPAKE2 (RustCrypto `spake2`) with HMAC key
  confirmation, three wrong codes per code and five minutes per transfer.

## 11. Order

| # | Part | Depends on |
| --- | --- | --- |
| 1 | Primitive families, `html`/`regex` captures (done in the primitives pull request) | |
| 2 | Policy IR: one step language replacing `http`/`stream`/`derive`, with the contracts of section 2a, response projection and the path fixes; existing policies converted by a tool | 1 |
| 3 | Typed items, disclosure levels, `describe`, custom kinds (done: `docs/policy.md`, Typed items) | 2 |
| 4 | Policy JSON Schema, `client::summarize` with risk flags, approval format (done: `docs/policy.md`; the approval runtime is part 5) | 2, 3 |
| 5 | Sessions, challenges, approvals, spending limits (done: `docs/policy.md`, Operations that wait; codes read from a `mail` item, `await` on TLS and amounts from body contracts are next) | 2 |
| 6 | Connection kinds in layer 1: HTTP/2, WebSocket, streamed responses (first half done: `docs/policy.md`, HTTP versions and gRPC, WebSocket; own synchronous HTTP/2 client and HPACK, one thread per open connection, the Nitro host relay unchanged), then SSH, databases, FTP, mail, queues (second half done but for the rows left in section 7c: SSH with SFTP and local forwarding, PostgreSQL, MySQL, SMTP, IMAP, Redis, MQTT 3.1.1 and 5, AMQP 0-9-1, and the `ssh` and `mail` typed kinds; then POP3, FTP over TLS and SFTP management; then SSH remote forwarding and AMQP 1.0; tunnels as an IR relay step next) | 2 |
| 7 | Trusted code sandbox (layer 3): WebAssembly runtime, JavaScript module, origin-pinned site code (done: `run` step, `crates/sandbox`, wasmi 1.1.0 chosen by measurement; JavaScript measured with boa in the sandbox, its shipping plan in `docs/sandbox.md`) | 2 |
| 8 | Browser fills over CDP (done: the `browser` connection and `fill`, `engine::cdp`, `docs/policy.md` Browser fills; tested against an in-process fake CDP endpoint, never a real browser; typed `card` and `login` items with browser operations, and detaching the agent's controller, are next) | 4, 5 |
| 9 | Remaining primitive families (Appendices A, B), UDP relay and its protocols (done: HPKE, TurboSHAKE, KangarooTwelve, ML-DSA, SM2, brainpool ECDSA, `tls_exporter` in TLS sends, the `udp` connection and the datagram relay; `docs/policy.md` and section 7b; the rows still open and why are listed under Appendix A, Part 9) | 1 |
| 10 | Node hand-over; key backup and device transfer in `client` (done: `crates/continuity`, `Node::hand_over`/`take_over`, `credentials hand-over`, `credentials verify --next`, `client` continuity, backup and transfer; real Nitro hardware and the real Sigstore root are not exercised by the tests, and the compiled Sigstore trust root is empty until it is committed, so nodes refuse every statement until then) | 3 |
| 11 | Section 8a and 8b schemes as IR policies and reviewed modules (started: section 8b delegation, emergency access and credential vending done, `docs/policy.md` Vending, Delegation and emergency access; the status of every row is below) | 6, 7 |

**Part 11, row by row.** Done before part 11 started:

- Spending limits (8b): `crates/engine/src/limits.rs`, `node/waits.rs` (`set_limits`, the
  gate before a payment).
- SASL XOAUTH2 (8b): `policy/proto.rs` (`mechanism: xoauth2`, `login.token`),
  `proto/imap.rs`, `proto/smtp.rs`. OAUTHBEARER (RFC 7628) is not done.
- Kubernetes client certificates and bearer tokens (8b): `open.identity` (`render_identity`
  in `node.rs`) and header injections over HTTPS.
- OAuth 2.0 refresh by the node (8a): the `oauth` kind in `items.json`, a fixed refresh
  request that captures the tokens; the consent itself runs on the owner's device by design.

Done in part 11 (tests in `crates/engine/tests/owner_controls.rs`, fuzz target
`owner_controls`):

- Delegation (8b): `engine::delegation`, `node/delegate.rs`, `POST /delegate` and
  `/delegation/change`, `client::delegate`, `change_delegation`, `sign_delegated_call`. A
  delegated policy is checked against the record's policy by the summary diff, so a new
  operation kind or field in the policy needs no new delegation code.
- Emergency access (8b): a delegation with a waiting period (1 hour to 90 days) that the
  delegate's first call starts and a device of the owner cancels; it works while the owner
  holds no grant, because the delegation carries the record key sealed to the node.
- Short-lived credentials handed to the caller (8b, and the Kubernetes `exec` credential):
  `Operation.vend` (`policy/vend.rs`). STS, downscoped tokens, installation tokens and IAM
  database tokens are each a fixed HTTPS request or a signing derivation of the policy; the
  node bounds what goes back by the expiry it reads, not by knowing the service. A
  `kubectl` `exec` plugin that prints what the node vended is the caller's own code.

Shown by tests with no new engine code (tests in `crates/engine/tests/schemes.rs`; the
policies are the operations of `docs/policy.md`, Worked examples, which the tests read from
that file). Every policy signs with the template analysis unchanged; two refusals are
measured where a scheme would need the rules loosened.

| Scheme | Result | Tests | Checked against | Caveat, or the missing generic capability |
| --- | --- | --- | --- | --- |
| DPoP (RFC 9449), `ath`, server nonce | works with caveat | `dpop_token_refresh_and_resource_request`, `dpop_retry_needs_a_server_nonce`, `dpop_ath_before_the_nonce_is_refused` | 4 ES256 proofs verified by ring (the JWK derived by `hpke_public("p256", key)`); `jti`, `htm`, `htu`, `iat`, `nonce`, `ath`; the refreshed token sealed and used by the next proof | The retry on `use_dpop_nonce` is unconditional: a server that sends no nonce fails the call after one request (measured); a conditional retry needs IR `if`. `ath` is tainted (hash of a secret alone), so it must be the last `json_set` member: before the controlled `nonce` it is refused by rule 2 (measured). No RFC example is deterministic. |
| HTTP Message Signatures (RFC 9421) | works with caveat | `http_message_signatures_four_algorithms`, `http_message_signatures_rfc9421_vectors` | Appendix B.2.6 (Ed25519) byte for byte; 8 signatures (ed25519, ecdsa-p256-sha256, rsa-pss-sha512, hmac-sha256, each on a POST with query and body and a GET) verified over a base rebuilt from the wire (ring, `rsa`, `hmac`), with `content-digest` (RFC 9530) | Closed by the request components (next table): a header the caller sets is covered with `$header`, `@authority` is `$authority` with any port, `@query-param` is `$query_param`, and B.2.5 (HMAC) is reproduced. Response signatures untested. |
| Hawk | works with caveat | `hawk_header_verifies`, `hawk_specification_examples` | The specification's two request examples: 2 MACs and the payload hash byte for byte (its fixed nonce in place of `$nonce`); 2 requests verified by a recomputed MAC | Closed by `$port` and `$header("content-type")` (next table). Checking the server's `Server-Authorization` is not done (untested). |
| ACME (RFC 8555) | works as-is | `acme_jws_with_jwk_kid_and_chained_nonces` | 5 flattened JWS verified by ring: `jwk` on new-account, `kid` (found by `onlyReturnExisting`, one extra request per call) on new-order and on a POST-as-GET, each with the nonce of the response before it, `url` from the request | Retrying on `badNonce` needs IR `if`. |
| JWS in general | works as-is | `jws_rfc7515_and_rfc8037_vectors` | RFC 7515 appendix A.1 (HS256) and RFC 8037 appendix A.4 (EdDSA): 2 whole compact serializations byte for byte | Closed by `ed25519_public`, `ed448_public`, `ecdsa_public` and `rsa_public` (next table). |
| JWE (RFC 7516): RSA-OAEP-256 + A256GCM, ECDH-ES+A128KW + A128GCM, `dir` + A256GCM | works with caveat | `jwe_rsa_oaep_256_a256gcm`, `jwe_ecdh_es_a128kw_a128gcm`, `jwe_ecdh_es_rfc7518_appendix_c`, `jwe_dir_a256gcm_over_the_callers_body`, `jwe_of_caller_bytes_and_a_secret_is_refused` | 6 JWEs decrypted by the test (`rsa` OAEP, `p256` ECDH, Concat KDF over `sha2`, `aes-kw`, `aes-gcm`), fresh content keys, IVs and ephemeral keys each call; RFC 7518 appendix C: the content opens under the published key `VqqN6vgjbSBcIijNcacQGg` | A plaintext that mixes the caller's bytes with a secret: `slice` still cannot separate ciphertext and tag (rule 2, measured); `aead_ciphertext` and `aead_tag` do (next table). Decrypting a JWE response is the `decrypt` row. |
| `private_key_jwt`, `client_secret_jwt` (RFC 7523) | works as-is | `client_assertions_private_key_jwt_and_client_secret_jwt` | RS256 verified by ring, HS256 by `hmac`; claims `iss`, `sub`, `aud`, `jti`, `iat`, `exp`; the access token sealed, only its type and lifetime returned | |
| SAML login through forms (`html` capture) | works with caveat | `saml_login_through_forms` | Redirect parameters, CSRF token and cookie, `SAMLResponse` (with an entity) and `RelayState` reach the right hosts unchanged; the session cookie sealed | `regex` reads bodies only, so the `Location` parameters are cut with `between`, in the order the service provider writes them. An OpenID Connect form login is the same steps (untested). |
| SAML messages signed by a service provider | works as-is (after DEFLATE and XML canonicalization, below) | `saml_redirect_binding_rsa_sha256_verifies`, `saml_redirect_binding_ecdsa_p256_verifies`, `saml_post_binding_enveloped_signature_verifies` (`schemes_xml.rs`) | See the table of DEFLATE and XML canonicalization below | Was: not shown, since the HTTP-Redirect binding needs DEFLATE (RFC 1951) and the POST binding XML signatures over Exclusive XML Canonicalization. Reading and checking the identity provider's signed Response is not done. |

The gaps of that table that are generic template capabilities were then added, each as a
family (tests in `crates/engine/tests/schemes_more.rs`, which reads its policies from
`docs/policy.md`, Request components, AEAD parts and public keys):

- **Request components**: `$header("name")` (a caller header the `send`'s contract lists,
  combined as RFC 9110 section 5.3 says), `$query_param("name")` (RFC 9421 `@query-param`),
  `$port`, `$scheme`, `$authority` and `$target_uri`. The name is a literal, so the analysis
  knows each component a template reads; values are controlled and caller-chosen like `$body`,
  and no rule changed.
- **AEAD parts**: `aead_ciphertext(...)` and `aead_tag(...)` around an AEAD call written in
  place (AES-GCM, ChaCha20-Poly1305, AES-CBC-HMAC, AES-CCM, AES-EAX; the engine has no
  XChaCha, AES-GCM-SIV or OCB function to split). Chosen over a `slice` at `len - 16` allowed
  when the length is public: the problem is not the length but who chooses where the cut falls
  relative to the secret. With `secret + $input`, a suffix of fixed length is a piece of the
  secret of a size the caller picks, and a plain hash of a mixed value is untainted, so it
  would be guessed a byte at a time. A cut that only an AEAD call can feed falls where the
  algorithm puts the tag, and each part covers the whole message, so each part keeps exactly
  the properties of the encryption and rule 2 and rule 9 stay as they were.
- **Public keys**: `ed25519_public`, `ed448_public`, `ecdsa_public(curve, key)` (P-256,
  P-384, P-521, secp256k1, brainpool P-256 and P-384, SM2) and `rsa_public(form, key)` (`n`,
  `e`, `spki`, `pkcs1`), one-way like `hpke_public`.

| Scheme | Result | Tests | Checked against |
| --- | --- | --- | --- |
| HTTP Message Signatures over the caller's headers | works as-is | `rfc9421_b26_and_b25_cover_the_callers_headers`, `signed_call_headers_verifies`, `query_param_follows_rfc9421_section_2_2_8` | RFC 9421 B.2.6 (Ed25519) and B.2.5 (HMAC-SHA256) byte for byte with `date` and `content-type` sent by the caller; 2 signatures over `@method`, `@target-uri`, `@authority` (port 8443), `@query-param`, two caller headers (one with whitespace around it, one absent) and `content-digest` verified by ring over a base rebuilt from the wire; 4 of the 5 values of section 2.2.8 (its fifth name cannot be listed in a contract, which takes visible ASCII names) |
| Hawk over the caller's content type and port | works as-is | `hawk_specification_examples_with_the_callers_content_type_and_port`, `hawk_call_headers_verifies` | The specification's POST hash and MAC and its GET MAC byte for byte, the content type sent by the caller as `Text/Plain; charset=utf-8` (normalized by the template), the port from `$port`; 2 requests verified by a recomputed MAC |
| JWE of the caller's bytes and a secret | works as-is | `jwe_of_caller_bytes_and_a_secret_opens`, `jwe_rfc7516_vectors_split_by_aead_parts`, `aead_parts_of_every_family` | 2 JWEs (RSA-OAEP-256, A256GCM) opened by `rsa` and `aes-gcm` with the card number inside the caller's JSON; RFC 7516 A.3 (A128KW, A128CBC-HS256) whole compact form and A.1 content (A256GCM) byte for byte; 30 splits over 10 parameter sets of the 5 families, AES-GCM against `aes-gcm`'s detached output |
| JWS with the JWK of its own key | works as-is | `jws_with_the_jwk_of_its_own_ed25519_key`, `jws_with_the_jwk_of_its_own_rsa_key`, `public_keys_match_published_key_pairs`, `public_keys_verify_signatures_on_every_curve` | `x` equals RFC 8037 A.2; EdDSA and RS256 verified by ring from the header's JWK alone; public keys equal RFC 8032 (Ed25519, Ed448), RFC 9421 B.1.4, RFC 6979 A.2.5 and A.2.6 and the secp256k1 generator; P-521, brainpool and SM2 verify the engine's signatures (`p521`, `ecdsa`, `sm2` verifiers) |

Attacks measured with them: a header outside the contract, the same header twice (in one
case or two), a folded value, a bare line feed, a NUL and a non-ASCII byte are refused before
anything is sent (10 requests, none sent); a template reading a header or parameter the
contract does not list, any in a fixed request, a `compute` step or a derivation is refused at
signing; a caller header meeting a secret in `slice`, `between`, a decoder, `random`, an
encryption key or a hash name is refused by rules 2, 1, 7 and 6; `aead_ciphertext` and
`aead_tag` refuse anything but an AEAD call in place (10 forms); their parts keep the
encryption's taint (5 derivations refused as tainted, one of them over a guessable field; 3
signed), a part of a mixed message cannot be cut or decoded, and rule 9 still refuses a cut, a
CCM tag length or a `random` length that depends on a secret.


The two families that row found missing were then added (tests in
`crates/engine/tests/schemes_xml.rs`, which reads its policies from `docs/policy.md`,
Compression and XML, and `crates/engine/src/primitives/xml/tests.rs`):

- **DEFLATE**: `deflate`, `inflate`, `zlib_deflate`, `zlib_inflate`, `gzip_deflate`,
  `gzip_inflate` over `miniz_oxide` 0.9.1 (pure Rust, `forbid(unsafe_code)`). An inflation
  writes into one buffer sized before it starts, at most 1 MiB and the budget left, and is
  refused past it; anything after the stream, a second gzip member, a preset dictionary and a
  wrong checksum are refused. A new rule of the analysis, rule 10, refuses compressing a
  tainted value: a compressed length depends on how the input repeats itself (CRIME, BREACH),
  and since `len` removes the taint and a request's size is seen on the wire, tracking the
  length as a new property was rejected in favour of the refusal; no scheme measured needs to
  compress a secret.
- **XML canonicalization**: `xml_c14n(algorithm, document[, inclusive_prefixes])` for
  Canonical XML 1.0 and 1.1 and Exclusive XML Canonicalization 1.0, with and without comments
  (the W3C identifiers name them), and `xml_escape`. The tokenizer is `quick-xml` 0.42 (pure
  Rust, `forbid(unsafe_code)`, MSRV 1.86, no default features), which keeps prefixes as
  written; namespace resolution, attribute normalization and the well-formedness checks it
  leaves out are the engine's. No DTD (so no XXE and no entity expansion), 1 MiB, 64 levels,
  65,536 nodes, 8 MiB of canonical form and the budget left. A secret and a chosen value may
  not meet in `xml_c14n` (rule 2). No element selection (XPath, by ID): a signing policy
  builds each signed element, and under the exclusive form an element canonicalized alone is
  the same as in place; selection would only be needed to check a document someone else
  signed, which is not done.

| Scheme or check | Result | Tests | Checked against |
| --- | --- | --- | --- |
| Inflation of what zlib writes | works as-is | `inflate_reads_what_zlib_writes_and_refuses_the_rest` | 41 streams of the zlib library (zlib-ng 1.3.1 through Python): raw at levels 0, 1, 6 and 9, fixed Huffman and Huffman only, zlib, zlib with a small window, gzip, gzip with every optional header field, of 4 inputs, and 1 MiB of zeros at the cap; 19 refused: damaged, wrong Adler-32, CRC-32, length and header CRC, a preset dictionary, trailing bytes, two members, a reserved flag, 3 bombs of 4 MiB and 1 MiB plus one byte |
| DEFLATE the engine writes | works as-is | `deflate_writes_streams_an_independent_decoder_reads` | A DEFLATE decoder written in the test (not `miniz_oxide`) reads every raw, zlib and gzip stream of 4 inputs, with the RFC 1950 header and Adler-32 and the RFC 1952 header, CRC-32 and length checked; the CRC-32 and Adler-32 of the test match their check values |
| Canonical XML 1.0, Exclusive XML Canonicalization 1.0 (with and without comments, prefix lists) | works as-is | `matches_libxml2_on_every_fixture`, `specification_examples`, `exclusive_specification_example`, `prefix_lists_and_algorithms` | 73 canonical forms of libxml2 2.11.9 (lxml 6.1.1) over 17 documents (C14N 1.0 sections 3.1 to 3.4 and 3.6 without their DTDs; namespaces declared, redeclared, undone and unused; CR LF, CDATA and references, attribute escapes and order, comments and PIs, SAML, `xsi:type` with a prefix list, SOAP, non-ASCII names) byte for byte, each its own canonical form; the lines of the specification that do not depend on a DTD; the subtree example of Exclusive XML Canonicalization section 2.2 in both contexts under both forms (libxml2 leaves out the inherited `xml:space`; the specification and the engine keep it) |
| Canonical XML 1.1 | works with caveat | the same | Equal to 1.0 on the 34 whole-document cases of the fixture, as the specification says; on a subtree it inherits `xml:lang` and `xml:space`; the `xml:base` fix-up of a subtree is not implemented and is refused. No 1.1 output of another implementation was compared (unmeasured) |
| SAML HTTP-Redirect binding, RSA-SHA256 and ECDSA P-256 | works as-is | `saml_redirect_binding_rsa_sha256_verifies`, `saml_redirect_binding_ecdsa_p256_verifies` | 3 query signatures over `SAMLRequest`, `RelayState` and `SigAlg` as sent, verified by `rsa` and ring; the message inflated by the decoder of the test equals the AuthnRequest; a fresh ID per call; a changed parameter fails |
| SAML HTTP-POST binding, enveloped XML signature | works as-is | `saml_post_binding_enveloped_signature_verifies` | The reference digest equals the SHA-256 of the exclusive canonical form written out by hand (namespace moved to its user, attributes sorted, empty elements expanded, `&` escaped by `xml_escape`); the RSA-SHA256 signature verified by `rsa` over the canonical `SignedInfo` written out by hand, and not over the text as sent |
| WS-Security: UsernameToken digest, X.509 BinarySecurityToken signature | works as-is | `ws_security_username_token_digest`, `ws_security_binary_security_token_signature_verifies` | The digest recomputed from the nonce and time sent (no new function needed); two references (the timestamp, the caller's body written unsorted) against canonical forms written out by hand, the signature verified by `rsa`, the token the record's certificate; 3 hostile bodies refused before sending |
| What these tests send, checked outside Rust | works as-is | `CREDENTIALS_INTEROP_DIR=<dir>` with `schemes_xml`, then `crates/engine/tests/fixtures/xml/interop/check.py` | 21 of 21: Python's zlib (zlib-ng 1.3.1) reads the 12 raw, zlib and gzip streams of 4 inputs exactly to their end and the 2 `SAMLRequest` values; OpenSSL 3 verifies both HTTP-Redirect signatures (RSA-SHA256, ECDSA P-256) and both `SignedInfo` signatures over libxml2's exclusive canonical form; libxml2 recomputes the 3 reference digests from the documents as sent (the enveloped signature removed). Not run in CI; a full XML-DSig validator (xmlsec, Java) was not run (unmeasured) |

Attacks measured with them: rule 10 refuses 9 policies that compress a secret; a mixed input
to `inflate`, `gzip_inflate` and `xml_escape` (rule 1), a mixed `xml_c14n` and a secret beside
a chosen prefix list (rule 2), a chosen algorithm (rule 6), a tainted prefix list (rule 9) and
a canonical or escaped secret handed back (rule 5) are refused at signing; bombs, DTDs,
external entities, entity expansion, deep nesting, too many nodes and an amplified canonical
form are refused at rendering (`hostile_documents_are_refused_in_templates`,
`inflation_counts_against_the_budget`, `dtds_and_entities_are_refused`, `limits_are_enforced`,
`malformed_documents_are_refused`). Fuzz targets `inflate_stream` and `xml_c14n` (a canonical
form must be its own) type-check; libFuzzer was not run on this Windows host (unmeasured).

SRP-6a and OpenPGP were then added as families (tests in
`crates/engine/tests/schemes_srp_pgp.rs`, which reads its policies from `docs/policy.md`,
SRP-6a and OpenPGP, and `crates/engine/src/primitives/srp.rs`):

- **SRP-6a**: `srp_public`, `srp_x`, `srp_u`, `srp_premaster`, `srp_m1`, `srp_verify`, one
  function per client step of RFC 2945 and RFC 5054, over the seven groups of RFC 5054
  appendix A named by the policy. Chosen over generic modular arithmetic in templates: the
  exponent `a + u * x` mixes a secret with a captured value, which `add` already refuses
  (rule 2), and a premaster secret built from separate operations would have no single place
  that keeps it tainted and uncontrolled the way `ecdh` is. The big integers are
  `crypto-bigint` 0.7.11 (`BoxedUint`, `BoxedMontyForm`), already in the build through `rsa`:
  constant-time Montgomery multiplication and exponentiation over the whole precision, which
  the group and the input lengths fix. Rule 11 is new: the private value is the node's (a
  `random` or a field), `B` and the proofs come from the destination.
- **OpenPGP framing**: `pgp_packet`, `pgp_subpacket`, `pgp_mpi`, `pgp_armor` (RFC 9580). The
  signature itself is template text over the existing signature functions, so a version, an
  algorithm or a subpacket needs no code. `pgp_mpi` refuses a tainted input (rule 10: its
  length tells the leading zeros).

| Scheme or check | Result | Tests | Checked against |
| --- | --- | --- | --- |
| SRP-6a computations | works as-is | `rfc5054_appendix_b`, `groups_are_safe_primes`, `refuses_degenerate_values` | RFC 5054 appendix B byte for byte: `k`, `x`, `v`, `A`, `u` and the premaster secret (SHA-1, 1024-bit group); the seven groups of appendix A are safe primes (`crypto-primes`), the four largest derived from the RFC 3526 primes in another crate's source and checked the same way; degenerate inputs refused (`B` of zero, `N`, `N + 1`, longer than `N`; empty or overlong private value or `x`; unknown group or hash; a wrong or short `M2`) |
| SRP-6a login in two requests (`srp-login`) | works as-is | `srp_login_against_an_independent_server`, `srp_login_refuses_a_wrong_password_an_impostor_and_bad_server_values` | A server written on `num-bigint` (2048-bit group, SHA-256) that keeps only the verifier: 3 logins, each `M1` equal to the server's and each `A` fresh; the server's `M2` checked by `srp_verify` before the session is returned; a wrong password gets no session; an impostor that accepts any `M1` gets nothing back; 4 bad `B` values fail before `M1` is sent |
| OpenPGP v4 detached signature, RSA (algorithm 1), SHA-256 | works as-is | `openpgp_detached_signatures_verify` | Parsed from the armor (CRC-24 checked) by a reader written in the test; the v4 fingerprint and key ID against a key packet built in the test; the hashed data rebuilt from RFC 9580 section 5.2.4 and verified by `rsa`; GnuPG 2.4.9 by hand: "Good signature", and "BAD signature" on other data |
| OpenPGP v4 detached signature, EdDSALegacy (algorithm 22) | works as-is | the same | ring over the digest (RFC 9580 section 5.2.3.4), `r` and `s` read as two MPIs; GnuPG 2.4.9 by hand: "Good signature", and "BAD signature" on other data |
| OpenPGP v6 detached signature, Ed25519 (algorithm 27) with a salt | works with caveat | the same | The v6 fingerprint, four-octet subpacket lengths, a fresh 16-octet salt per call and the 64-octet signature verified by ring over the salted digest; no other implementation checked it (GnuPG 2.4.9 refuses version 6 packets; no RFC 9580 implementation is installed; unmeasured) |
| OpenPGP framing | works as-is | `openpgp_framing_follows_rfc9580` | The one-, two- and five-octet lengths at 0, 1, 191, 192, 8383, 8384 and 10,000 bytes, the critical bit, MPIs of zero and with leading zeros, against an encoder written in the test |

Attacks measured with them: rule 11 refuses a caller-chosen private value (3 policies), a
caller-chosen `B` and a caller-chosen `M2`; rule 6 refuses a chosen group or hash in 4
functions and a chosen armor label or checksum; rule 1 refuses a mixed value in `srp_u` and
in a packet type; rule 5 refuses handing back `x`, the premaster secret, the session key and
an `M1` over values the policy fixes, and a framed or armored secret (3); an `M1` over a
chosen salt signs with a strong password and is refused with a guessable one; rule 10 refuses
`pgp_mpi` of a secret, `len` of it included. No new parser, so no new fuzz target; timing of
the arithmetic was not measured on hardware.

Not done; each needs a primitive or a feature, not a site name: OAuth 1.0a normalization in
`canonical_query`; SigV4A key derivation; NTLM and Negotiate (connection-bound: each HTTPS
send opens its own connection today, so the handshake and the request would need one
connection); SEED and ARIA; Korean certificates (SEED-CBC key
decryption and CMS signatures); software passkeys; HOTP and the Steam alphabet; SMS codes
without the owner (reading a code from another record, like the `mail` item of part 5);
ssh-agent (`credentials tunnel --agent`); BIP-340 Schnorr; incoming webhook
`verify`; `decrypt`; `generate` and rotation; egress through a proxy; SNMPv3 (RFC 3414 key
localization and AES-CFB over the UDP relay); OAUTHBEARER; checking a signed SAML Response
(element selection by ID and XML signature verification). Found by the table above and done:
the request components, the AEAD parts, the public keys, DEFLATE and XML canonicalization,
SRP-6a and OpenPGP framing (text and cleartext signatures, encrypted messages and key
generation are not done). IR `repeat` and `if` run on HTTPS and derivations, with tests on values no
secret influences, static request bounds and the other limits of `docs/policy.md` (Loops and
branches; `engine::policy::flow`), so the nonce retries the table marks as unconditional can now
be conditional.

Since then, three of these were done with standard families (`docs/policy.md`, Parameter
lists, derived EC keys and binary messages): `sorted_params` (the RFC 5849 normalization;
`canonical_query` keeps SigV4's), `kbkdf_ec_key` (SP 800-108 counter mode with FIPS 186-5
A.2.2 rejection sampling), and `utf16le`, `utf16be`, `uint_be`, `uint_le` with the existing
`md4` (now flagged weak) for NTLMv2. NTLM is connection-bound, so its policy writes HTTP/1.1
itself on one `tls` connection and relays the caller's requests after the handshake.

| Scheme or check | Result | Tests | Checked against |
| --- | --- | --- | --- |
| OAuth 1.0a normalization and HMAC-SHA1 | works as-is | `oauth1_rfc5849_vectors`, `oauth1_hmac_sha1_signs_the_callers_query_and_form_body` | RFC 5849 section 1.2 (the signature `MdpQcU8iPSUjWoN/UDMsK2sui9I=`) and section 3.4.1.1 (the base string, byte for byte); two signed requests with a query and a form body holding `+`, `%2B`, UTF-8 and reserved characters, the base string rebuilt from the wire by a normalizer written in the test and the MAC recomputed with `hmac` |
| OAuth 1.0a RSA-SHA1 and PLAINTEXT | works as-is | `oauth1_rsa_sha1_and_plaintext` | The RSA-SHA1 signature verified by the `rsa` crate over the rebuilt base string; PLAINTEXT equal to the encoded secrets |
| SigV4A key derivation and signature | works with caveat | `sigv4a_key_derivation_and_signature_verify` | The key equals one derived in the test with `hmac` and byte arithmetic (SP 800-108 counter mode, `c <= n - 2`, `d = c + 1`); its public key (by `p256`) verifies the DER signatures of two requests with ring over a string to sign rebuilt from the wire. Caveat: no published SigV4A vector was at hand, so the check is the specification written twice, not a vendor's output |
| `kbkdf_ec_key` rejection sampling | works as-is | `the_boundary_of_the_test`, `a_refused_candidate_moves_to_the_next_number` (unit) | `n - 1`, `n` and all ones refused, `n - 2` and zero accepted; the counter moves on after a refusal and gives up after 254 |
| NTLMv2 (MS-NLMP) | works as-is | `ntlmv2_ms_nlmp_vectors` | MS-NLMP section 4.2.4: NTOWFv2, the LMv2 response, NTProofStr and the session base key, byte for byte |
| NTLM over HTTP on one connection | works with caveat | `ntlmv2_over_one_tls_connection_verifies` | NEGOTIATE, a CHALLENGE built in the test, AUTHENTICATE: NTProofStr recomputed with `md4` and `hmac`, the server's timestamp in the blob, `MsvAvFlags` with the MIC bit, the MIC over the three messages; then a relayed request; a second call has a fresh client challenge. Caveats: HTTP/1.1 written by the policy (no chunked 401 bodies: a body is left for the next read); `upper` is ASCII only; no key exchange (RC4 `KEY_EXCH` is not offered, so no signing or sealing after authentication) |
| Kerberos `Negotiate` (SPNEGO) over HTTP | not done | — | Needs the AP exchange and SPNEGO framing, not only primitives |
| SP 800-108 feedback and double-pipeline modes | not done | — | No published vector at hand to check them against |

Attacks measured with them: `sorted_params` with a secret beside chosen pairs, or mixed into
one list, is refused (rule 2), and a sorted secret handed back (rule 5); `kbkdf_ec_key`
handed back, or a hash of it (rule 5), and with a chosen curve or hash (rule 6), are
refused; NTOWFv2 of a guessable password handed back (rule 5, guessable), `md4(utf16le)` of a
mixed value (rule 1) and `uint_le` of a secret (rule 9) are refused; the summary flags
`weak_mechanism` for the `ntlm-http` policy and not for `oauth1-hmac-sha1`; a form body with a
lone `%` fails before sending, and a CHALLENGE without a timestamp or not in base64 fails before
AUTHENTICATE is written.

Each part adds its rows to `docs/threat-model.md`, fuzz targets for any new parser, and
measured results in its pull request.

## 12. Out of reach by principle

A node in a data centre cannot touch devices near the owner: Bluetooth, NFC, USB security
keys, smart cards, serial ports. Credentials bound to them (passkeys in a phone's secure
element, hardware OTP tokens) go through the owner's device each time: an approval or a
challenge, never a stored secret. The same holds for proofs that only the owner's phone can
make: app attestation tokens (Play Integrity, App Attest), Apple Pay and Google Pay, and
approvals inside another company's app (KakaoTalk, a bank's app push).

## 13. Open questions

- PCI DSS scope of storing card numbers in the node, and Kernel's PCI status.
- Korean card issuers: none was found with a public one-time virtual card API; cards stay real
  numbers until one is.
- Legal limits on processing national ID numbers (주민등록번호) for identity items.
- Which sites bind sessions to the client IP, so that a session made on the owner's device
  fails from the node.
- Delegations across a hand-over. A delegation carries the record key sealed to one node, so
  a hand-over (section 10) does not carry it: the owner delegates again on the successor.
  Emergency access therefore assumes the owner's node outlives the owner by the waiting
  period; carrying delegations would mean resealing their keys to the successor in the
  package, which is possible but widens what a hand-over moves. Left closed for now, the
  more secure choice.
- Delegations and requests of emergency access are restored from the log, like spending
  limits. A node restarted from a cut log without `restore_anchored` can bring back a
  revoked delegation or forget a cancellation; the anchor is the defence, as for limits.
- Covering the caller's own header fields in a signature (RFC 9421, Hawk's content type):
  settled as `$header("name")`, only for headers the `send`'s contract lists, caller-chosen
  like `$body` (section 11). Still open: the path parameters a policy fills are not in `$path`
  or `$pathname`, which are read before they are filled, so a signature cannot cover a
  path that holds one.
- Nonce retries (DPoP `use_dpop_nonce`, ACME `badNonce`) are written unconditionally until IR
  `if` runs; until then a policy fits only servers that always ask for a nonce first.
- SRP variants. The functions follow RFC 5054: `u` and `k` over values padded to `N`, `M1`
  as RFC 2945 writes it, groups by name only. A service that pads differently, or sends its
  own modulus (a per-user `N`, signed or not), is not served: a modulus from the destination
  would need a check that it is a safe prime of sufficient size before any secret is raised
  to it, which is costly and was left out. The server side (computing `B`, checking `M1`)
  is not offered: the node is a client.
- OpenPGP version 6 output was checked only by the test's own reader and ring; a second
  RFC 9580 implementation should verify it before a policy relies on it.
- Vending checks the expiry the service states. A service that states a shorter expiry than
  it honours is out of the node's reach; the owner's scope in the fixed request is the
  other bound.

## Appendix A. Gaps found against the IANA registries (2026-11)

Checked entry by entry against IANA: HTTP authentication schemes, SASL, JOSE, COSE, SSH, TLS
SignatureScheme and ClientCertificateType, RADIUS, OAuth parameters, WebAuthn. Entries the
registry marks deprecated, obsolete or prohibited (37) are left out.

| Of 617 entries | Count |
| --- | --- |
| Work today | 94 |
| Planned in sections 3-8c | 85 |
| Missing, possible in principle (rows below) | 197 |
| Not a vault's concern (server side, no secret) | 235 |
| Impossible in principle (hardware attestation formats, device-bound extension) | 6 |

Not yet checked: IANA EAP method types, Kerberos encryption types, GSS-API mechanisms, SSH key
exchange, cipher and MAC names, OpenSSH certificate formats.

### Template language (structure, not cryptography)

| Change | Needed by |
| --- | --- |
| `slice(v, start, len)` and `between(v, start, end)` on values, captures from temps | COSE HMAC 256/64; GCM tag split (A*GCMKW, compact JWE); A*CBC-HS* key split; SCRAM over HTTP, IMAP and SMTP |
| Decimal arithmetic `add(a, b)` and numeric members in `json_set` | `exp`/`nbf` set by the node: JWT bearer grant, `client_secret_jwt`, `private_key_jwt`, VAPID, SAML `NotOnOrAfter` (today the caller passes claims and the policy cannot bound `exp`) |
| CBOR encoding | every COSE structure, WebAuthn attestation objects, COSE key thumbprints, OpenID4VP mdoc |
| TLS channel binding variables: `tls_exporter(label, len)`, `tls_server_end_point` | SCRAM-*-PLUS, GS2-KRB5-PLUS, EAP-AES128-PLUS, SXOVER-PLUS, HTTP `Concealed` |
| Bounded iteration `hash_chain(alg, seed, n)` | SASL `OTP` and its six-word encoding |
| Length-framed `expect` in `stream` | RadSec, EAP inside RADIUS, binary SASL carriers |
| Retry on a server nonce (one conditional step) | DPoP `use_dpop_nonce` |

### Signatures

| Function | Needed by |
| --- | --- |
| `rsa_sign_pkcs1(hash, key, msg)` for SHA-1/256/384/512 | JOSE and COSE RS384/RS512, ssh-agent `rsa-sha2-512` and `ssh-rsa`, TLS legacy schemes |
| `rsa_sign_pss(hash, …)` for SHA-384/512 | JOSE and COSE PS384/PS512 |
| `p521_sign` | ES512, ESP512, `ecdsa-sha2-nistp521`, TLS `ecdsa_secp521r1_sha512` |
| `ed448_sign` | JOSE, COSE, `ssh-ed448`, TLS `ed448` |
| `brainpool_sign` (P256r1, P320r1, P384r1, P512r1) | COSE ESB*, TLS brainpool schemes |
| `mldsa_sign` (44, 65, 87) | JOSE, COSE, key type `AKP`, TLS, SSH ML-DSA and composites |
| `slhdsa_sign` | TLS SLH-DSA |
| `hss_lms_sign`, its counter re-sealed into the item on each use | COSE HSS-LMS |
| `dsa_sign`; ECDSA with SHA-1 | `ssh-dss`, TLS `dss_sign`, `ecdsa_sha1`, SASL ISO 9798 |
| Prehashed ECDSA | SASL ECDSA-NIST256P-CHALLENGE |
| National: SM2/SM3, GOST R 34.10-2012, BIGN | TLS schemes and client certificate types |
| Identity-based: ECCSI, ISO IBS1/IBS2, Chinese IBS; WalnutDSA | TLS, COSE |

mTLS reaches these only through a custom `rustls::sign::SigningKey` in `transport` backed by
`engine` primitives, since ring has no P-521, Ed448, brainpool or post-quantum keys.

### Key agreement, KDFs, key wrapping, ciphers

| Function | Needed by |
| --- | --- |
| `ecdh(curve, priv, peer)` for P-256, P-384, P-521, X25519, X448 | JOSE ECDH-ES*, COSE ECDH-ES/SS, HPKE, SASL ECDH-X25519-CHALLENGE |
| `concat_kdf` (SP 800-56A) | JOSE and COSE ECDH-ES |
| `hkdf(hash, …)` for SHA-256/384/512, and the AES-CBC-MAC variant | COSE direct+HKDF, ECDH+HKDF, HPKE |
| `hpke_seal` (RFC 9180, all DHKEM and AEAD suites) | JOSE HPKE-0..7 and HPKE-*-KE |
| `aes_kw_wrap` (RFC 3394) | JOSE and COSE A*KW, ECDH-ES+A*KW, PBES2 |
| `pbkdf2(hash, …)` for SHA-1/256/384/512 | SCRAM-SHA-1, PBES2-HS* |
| AES-192 keys in `aes_gcm_encrypt` | A192GCM, A192GCMKW |
| `aes_cbc_hmac_encrypt` (RFC 7518 5.2) | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 |
| `aes_ccm_encrypt`, `aes_cbc_mac` | COSE AES-CCM-*, AES-MAC |
| `chacha20_poly1305_encrypt` (the crate is already in the engine) | COSE, HPKE |
| `rsa_encrypt_oaep(hash, …)` for SHA-1/256/384/512 | JOSE RSA-OAEP*, COSE RSAES-OAEP |

### Hashes

`sha512_256`, `sha3_*`, `shake128`, `shake256`, `turboshake128/256`, `kt128/256`: COSE hash
algorithms, HTTP Digest `SHA-512-256`, ML-DSA and SLH-DSA.

### Protocol modules and flows

| Change | Needed by |
| --- | --- |
| HTTP `Mutual` (RFC 8120, ISO 11770-4 KAM3 PAKE) | HTTP `Mutual` and its 4 algorithms |
| Privacy Pass client (blind RSA, VOPRF P-384), tokens sealed into the item | HTTP `PrivateToken` |
| HTTP `Concealed` (RFC 9729) | needs `tls_exporter` |
| HTTP SCRAM (RFC 7804) | `SCRAM-SHA-1`, `SCRAM-SHA-256` schemes |
| SSH `keyboard-interactive` (prompts to fields, OTP to `await`), `hostbased`, `gssapi-with-mic`, `gssapi-keyex`, X.509 keys (RFC 6187) | SSH beyond russh's defaults |
| GSS-EAP (RFC 7055); EAP-MD5, MSCHAPv2, EAP-TLS, PEAP, TTLS inside RADIUS; ARAP | SASL EAP-AES128, RADIUS EAP-Message |
| ISO 9798 SASL (RFC 3163); SASL over Diameter; SASL OTP | SASL 9798-*, SXOVER-PLUS, OTP |
| Novell NMAS | blocked: no public specification found |
| SD-JWT key binding, mdoc DeviceAuth | OpenID4VP `vp_token` |
| ACE PoP (CoAP, OSCORE, COSE) | OAuth token type `PoP` |
| SAML assertions signed by the node (XML-DSig, exclusive c14n) | SAML bearer grant and client assertion |
| Software passkey extensions: `hmac-secret`, `credBlob`, `largeBlob`, `payment` | WebAuthn extensions |

### Order inside section 8d

1. `slice`/`between`, `add`, `pbkdf2(hash)`: JWE assembly, SCRAM and node-set `exp`.
2. Hash-parameterized RSA, P-521, HKDF, ECDH, AES key wrap, Concat KDF: most of JOSE and COSE.
3. CBOR and channel binding.
4. Post-quantum and national signature schemes last.

Status: groups 1 and 2 are in, with SHA-3/SHAKE, Ed448, prehashed ECDSA, DSA, X448, AES-CCM,
EAX, CMAC, CBC-MAC, CTS, SP 800-108 counter mode and Kerberos n-fold/DK, and the CBOR of
group 3 (`docs/policy.md`). Part 9 added HPKE, TurboSHAKE, KangarooTwelve, ML-DSA, SM2,
brainpool ECDSA and `tls_exporter` (below).

### Part 9

The counts above moved by the entries these rows name, not by a fresh pass over the
registries: JOSE `HPKE-0` to `HPKE-7` (8; every suite is a KEM, KDF and AEAD of
`hpke_seal`), JOSE and COSE `ML-DSA-44`, `-65`, `-87` (6), COSE `ESB256` and `ESB384` (2), and
SASL `SCRAM-SHA-1-PLUS` and `SCRAM-SHA-256-PLUS` over a TLS stream with the RFC 9266
binding (2): 18 from missing to working. `HPKE-*-KE`, COSE HPKE and the COSE hash
entries of TurboSHAKE and KangarooTwelve have their functions now but were not recounted
entry by entry (unmeasured).

Each row of Appendices A and B that names a standard family, and where it stands:

| Row | Status |
| --- | --- |
| `hpke_seal` (RFC 9180) | Done: `hpke_seal`, `hpke_open`, `hpke_export`, `hpke_receiver_export`, `hpke_public`, `hpke_derive_key`; the five DHKEMs, three KDFs, three AEADs and export-only, the four modes; RFC 9180 vectors (128 suites, 384 encryptions, 384 exports) |
| `turboshake128/256`, `kt128/256` | Done; RFC 9861 vectors (25 TurboSHAKE, 21 KangarooTwelve) |
| TLS channel binding `tls_exporter` | Done in the `send` of a TLS stream (TLS 1.3 only: rustls does not report the extended master secret of TLS 1.2). Not in an HTTPS request, which is rendered before its connection exists: HTTP `Concealed` stays missing |
| `tls_server_end_point` | Not done: RFC 5929 hashes the server certificate with the hash of its signature algorithm, which needs an X.509 parser in `transport` that it does not have |
| tls-unique (RFC 5929) | Not offered: rustls exposes no Finished message, it is undefined for TLS 1.3, and RFC 9266 replaces it |
| `mldsa_sign` (44, 65, 87) | Done as a template function (JOSE, COSE, key type `AKP` from `mldsa_public`); LAMPS key generation examples. TLS and SSH use need a signer inside `transport` and russh, not a template function |
| `brainpool_sign` | P256r1 and P384r1 done through `ecdsa_sign_prehash` (`bp256`, `bp384`). P320r1 and P512r1 not: RustCrypto has no crate for them (the only `bp512` crate on crates.io, `bp512-nestler` 0.2.1, is a single-author implementation outside RustCrypto) |
| `slhdsa_sign` | Not done: only a release candidate exists (`slh-dsa` 0.2.0-rc.5) |
| `hss_lms_sign` | Not done: stateful; its counter must be re-sealed into the record on each use with rollback protection, which is a record change, not a template function (and `lms-signature` is 0.1.0-rc.2) |
| `dsa_sign`; ECDSA with SHA-1 | Done before part 9 (`dsa_sign`; `ecdsa_sign_prehash` over a SHA-1 digest) |
| National: SM2/SM3 | `sm2_sign` done (TLS `sm2sig_sm3` needs a signer in `transport`); GOST R 34.10-2012: no RustCrypto signature crate; BIGN: `bign256` 0.13.1 is of the previous RustCrypto generation (`elliptic-curve` 0.13) |
| Identity-based (ECCSI, ISO IBS, Chinese IBS), WalnutDSA | Not done: no Rust crate found (`cargo search eccsi`: none) |
| `hash_chain`, length-framed `expect`, retry on a server nonce | Not primitive families: changes to the step language (loops are refused until run; part 2) |
| SSH key exchange, ciphers and MACs (Appendix B) | Transport of russh, not template functions (section 7) |
| MSCHAPv2 (`des`) inside RADIUS | Not done: its response is DES under a key cut from the password hash, tainted by rule 4, and a datagram may not carry a tainted value, so the policy would be refused anyway |
| Camellia CTS, CMAC and feedback-mode KDF | Not done: needed only by Kerberos etypes 25 and 26, whose AS exchange (section 7) does not exist yet |
| PKINIT, SPAKE2 pre-authentication, SRP, EAP-pwd, EAP-EKE | Protocol modules with their own state machines (Appendix B), not families |

## Appendix B. Gaps found against further registries (2026-11)

Checked entry by entry: IANA EAP Method Types; Kerberos encryption, checksum and
pre-authentication types; GSS-API mechanism codes under 1.3.6.1.5.5 (IANA SMI numbers) plus
the Kerberos V5 mechanism (RFC 4121); GSSAPI/Kerberos/SASL service names; SSH key exchange,
encryption, MAC and compression names and the SSH agent registries (RFC 9987); the names in
OpenSSH's PROTOCOL, PROTOCOL.agent, PROTOCOL.u2f, PROTOCOL.key and PROTOCOL.sshsig, with
draft-miller-ssh-cert-06 for certificate types. SSH transport is judged against russh 0.65.4
and ssh-key 0.7.0-rc.12: a name russh implements counts as planned (section 7). Entries marked
deprecated, obsolete, historic or MUST NOT (25) are left out, as are reserved rows.

| Of 343 entries | Count |
| --- | --- |
| Work today | 0 |
| Planned (sections 7, 8a, through russh) | 64 |
| Missing, possible in principle (rows below) | 177 |
| Not a vault's concern (no client secret, or keys that only the owner's device may add) | 36 |
| Impossible in principle (SIM/USIM, hardware tokens, smart cards, hardware attestation) | 10 |
| Unverified: no public specification obtained | 56 |

Unverified: EAP types 7-12, 14-17, 22, 24, 26-28, 30, 31, 33-42, 44, 45 (only a person's name
as reference); Kerberos etype 65, checksums 9, 10, 14; pre-authentication types 6-10, 20,
102, 103, 106-108, 131, 132, 145, 146, 152, 153, 166; GSS IDUP mechanisms (PIM, MIM, p7im,
meim) and the service name `rcmd`.

### SSH transport beyond russh 0.65.4

| Change | Needed by |
| --- | --- |
| Key exchange: X448, sntrup761, ML-KEM 512/768/1024 alone and with P-256/P-384, RSA key transport, ECMQV, ECDH on further curves | `curve448-sha512`, `sntrup761x25519-sha512`, `mlkem*`, `rsa2048-sha256`, `ecmqv-sha2`, `ecdh-sha2-*` |
| GSS-API key exchange on the section 7 Kerberos module | `gss-*` key exchanges, auth `gssapi-keyex` |
| IANA names for AEAD ciphers russh knows only as `@openssh.com` names | `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM`, `chacha20-poly1305` |
| Legacy block ciphers, CBC and CTR | `blowfish`, `twofish*`, `serpent*`, `idea`, `cast128`, `3des-ctr` |
| MACs | `hmac-sha1-96`, `hmac-md5`, `hmac-md5-96`, `umac-64@openssh.com` |
| Certificate names of draft-miller-ssh-cert-06 as aliases; Ed448 | `*-cert` names, `ssh-ed448-cert` |
| Host-bound public key authentication | `publickey-hostbound-v00@openssh.com` |
| Security-key types answered by a software FIDO authenticator in the node (counter re-sealed on each use); hardware-enrolled keys and `ssh-sk-attest-*` stay out of reach | `sk-ecdsa-sha2-nistp256@openssh.com`, `sk-ssh-ed25519@openssh.com`, their certificates, `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` |
| OpenSSH private key files in the `ssh` item | `openssh-key-v1` with `bcrypt` KDF |
| SSHSIG signatures as a derive output | `git` commit signing, `ssh-keygen -Y sign` |

### ssh-agent (section 8a)

| Change | Needed by |
| --- | --- |
| Agent lock with a passphrase | `SSH_AGENTC_LOCK`, `SSH_AGENTC_UNLOCK` |
| Extension messages | `SSH_AGENTC_EXTENSION`, `query` |
| The node checks the host signature in `session-bind@openssh.com` against the item's policy | `session-bind@openssh.com` |
| `rsa_sign_pkcs1(sha512)` | `SSH_AGENT_RSA_SHA2_512` |

Adding keys through the agent (`ADD_IDENTITY`, constraints, `REMOVE_*`,
`restrict-destination-v00@openssh.com`) stays refused: keys enter only through items the owner
signs. Smart-card messages are out of reach.

### EAP peer

Carriers: RADIUS, IKEv2, GSS-EAP. The node plays the supplicant.

| Change | Needed by |
| --- | --- |
| EAP peer state machine, length-framed `expect` | Identity, Notification, Nak, Expanded Type, GTC |
| Listed primitives | MD5-Challenge; OTP (`hash_chain`); MSCHAPv2 (`md4`, `des`) |
| rustls over EAP framing; TLS key export | EAP-TLS, EAP-TTLS, PEAP, EAP-FAST, TEAP |
| `aes_cmac`, `aes_eax` | EAP-PSK |
| Method KDFs over AES-CMAC, HMAC, AES-CBC, DH | EAP-GPSK, EAP-SAKE, EAP-PAX, EAP-POTP |
| PAKE: elliptic-curve point arithmetic, DH with an encrypted exponent, IKEv2 `prf+`, SRP | EAP-pwd, EAP-EKE, SRP-SHA1 |
| The IKEv2 module as a method | EAP-IKEv2 |
| EDHOC over COSE and CBOR | EAP-EDHOC |

### Kerberos beyond the password AS exchange of section 7

Section 7's Kerberos needs the first two rows before it works at all.

| Change | Needed by |
| --- | --- |
| `aes_cts`, RFC 3961 n-fold and DK, `pbkdf2(sha1)` | etypes 17, 18; checksums 15, 16 |
| SP 800-108 counter-mode KDF over HMAC-SHA2 | etypes 19, 20; checksums 19, 20 |
| Camellia CTS, CMAC, feedback-mode KDF | etypes 25, 26; checksums 17, 18 |
| PKINIT client: CMS SignedData, `rsa_decrypt_*` whose result never leaves, 3DES and RC2 content decryption, DH/ECDH | etypes 9-15; PKINIT pre-authentication and typed data |
| FAST armor, KRB-FX-CF2, encrypted challenge | PA 133-138 |
| SPAKE2 over edwards25519, P-256, P-384, P-521 | PA 151 |
| OTP pre-authentication, SAM with S/Key | PA 141, 142, 144; 12, 13, 21, 23, 30, 31 |
| Referrals | PA 25, 149 |
| Microsoft PAC request and S4U2self | PA 128, 129, 130 |
| PKU2U | PA 148 |

### GSS-API and GS2

| Change | Needed by |
| --- | --- |
| GS2 framing (RFC 5801) and SASL GSSAPI (RFC 4752) on Kerberos V5; channel binding for `-PLUS` | imap, pop, smtp, xmpp, ftp, nntp, sieve, acap, beep, mupdate, sacred, nfs |
| A Kerberos-backed authenticator for russh's `gssapi-with-mic` | SSH host service |
| IAKERB | 1.3.6.1.5.5.10 |
| SPKM-1/2/3, LIPKEY | 1.3.6.1.5.5.1.1-3, 1.3.6.1.5.5.9 |
| SAML20 and OPENID20 as GSS mechanisms | 1.3.6.1.5.5.17, 1.3.6.1.5.5.16 |

### Corrections to Appendix A

- russh 0.65.4 already has client `keyboard-interactive` and `gssapi-with-mic`; the row "SSH
  beyond russh's defaults" narrows to `hostbased`, `gssapi-keyex` and X.509 keys.
- SASL `ECDH-X25519-CHALLENGE` also needs `hkdf(sha256)` (atheme's reference implementation).
- SSH `gssapi` and `external-keyx` are names RFC 4462 section 8 reserves, not methods.
