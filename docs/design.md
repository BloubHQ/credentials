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
| `ftp` | host, mode (FTPS explicit/implicit, SFTP goes to `ssh`), user, password | plain FTP only when signed off |
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

**Implementation.** `engine::session` (parked operations, bounded count per owner and in
total, expiry) and a new step kind `await {challenge}` in `Operation::Http` and `Stream`.

### Approvals

An item or policy can require the owner's approval per use: payments always, plus whatever
the owner marks. The node returns `approval_required {id, summary}`; the summary is built by
the node (merchant origin, amount, currency, item masked view), and the owner's device signs
`approve(id, summary hash)`. The log records the approval.

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

**Implementation.** `transport::cdp` (a minimal CDP client over the existing TLS
`Connector`), `engine` operation kind `fill`, item kinds `card` and `login`.

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
caught. Streams have their own limits apart from the 10-second request deadline of plain calls:
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

**Implementation.** a `datagram` channel next to the egress relay in `relay` and `host`
(allow-listed like TCP), and the protocol modules above in `tunnel`.

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
| Spending limits | real cards, exchange orders, transfers | per item, merchant, day and month limits kept by the node; above them an approval (section 5) |
| Short-lived credentials handed to the caller | `aws`, `gcloud`, `kubectl`, GitHub Apps, databases with IAM tokens | operation `vend`: the node mints a scoped, short-lived credential from the long-lived secret (STS AssumeRole with a session policy, a GCP downscoped token, a GitHub installation token, an RDS IAM token) and returns only that; the owner's policy sets scope and lifetime |
| SASL XOAUTH2 / OAUTHBEARER | Gmail, Outlook over IMAP and SMTP | the mail item takes an OAuth token instead of a password |
| ACME, JWS in general | certificates (Let's Encrypt), any JWS API | account key JWS by derive |
| Kubernetes | API servers | client certificates and bearer tokens over HTTPS; `exec` credentials through `vend` |
| SNMPv3 | network devices | USM (HMAC, AES) over the UDP relay |
| Delegation | family members, a colleague's agent | an owner grants another owner's callers a narrower policy on an item; revocable, logged on both sides |
| Emergency access | when the owner is gone | a delegate whose access opens after a waiting period the owner can cancel from a device |

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
surface in their pull request.

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

## 11. Order

| # | Part | Depends on |
| --- | --- | --- |
| 1 | Primitive families, `html`/`regex` captures (done in the primitives pull request) | |
| 2 | Policy IR: one step language replacing `http`/`stream`/`derive`, with the contracts of section 2a, response projection and the path fixes; existing policies converted by a tool | 1 |
| 3 | Typed items, disclosure levels, `describe`, custom kinds | 2 |
| 4 | Policy JSON Schema, `client::summarize` with risk flags, approval format | 2, 3 |
| 5 | Sessions, challenges, approvals, spending limits | 2 |
| 6 | Connection kinds in layer 1: HTTP/2, WebSocket, streamed responses, then SSH, databases, FTP, mail, queues; tunnels as an IR relay step | 2 |
| 7 | Trusted code sandbox (layer 3): WebAssembly runtime, JavaScript module, origin-pinned site code | 2 |
| 8 | Browser fills over CDP | 4, 5 |
| 9 | Remaining primitive families (Appendices A, B), UDP relay and its protocols | 1 |
| 10 | Node hand-over; key backup and device transfer in `client` | 3 |
| 11 | Section 8a and 8b schemes as IR policies and reviewed modules | 6, 7 |

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

## Appendix A. Gaps found against the IANA registries (2026-11)

Checked entry by entry against IANA: HTTP authentication schemes, SASL, JOSE, COSE, SSH, TLS
SignatureScheme and ClientCertificateType, RADIUS, OAuth parameters, WebAuthn. Entries the
registry marks deprecated, obsolete or prohibited (37) are left out.

| Of 617 entries | Count |
| --- | --- |
| Work today | 76 |
| Planned in sections 3-8c | 85 |
| Missing, possible in principle (rows below) | 215 |
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
