# Threat model

What the engine protects, against whom, under which assumptions, and what is left.

## Assets

1. **Secret field values**: tokens, passwords, private keys, seeds.
2. **The user key** of each owner, which decrypts all of that owner's records.
3. **The integrity of the log**: a true account of every use.
4. **Owner privacy**: where secrets were used and with what.

## Parties and what each may try

| Party | Trusted for | May try to |
| --- | --- | --- |
| Owner's device | Everything about its owner | — |
| Node code in an attested TEE | Following this engine | — |
| Node operator (host, OS, network, storage) | Availability only | Read memory outside the TEE; replay or reorder grants, records and calls; drop or edit the log; point DNS elsewhere; start fresh nodes |
| Caller (app or AI agent) | Nothing beyond its policy entry | Extract the secret through requests, inputs and responses; exceed its limits; replay calls; act as another caller |
| Destination server | Receiving the secret it is meant to receive | Echo the secret back to the caller; hand back values that act as keys; send oversized or malformed responses |
| Log store | Keeping entries | Read them; drop, cut or edit them |
| Server of a web page that runs the `client` package | Serving the code the owner expects | Serve other code that reads the owner's keys, or grants to a node of its choosing; swap the measurements list |

## Assumptions

- **A1.** In deployment, the node runs inside a TEE whose attestation the owner checks, and
  the quote carries `NodeIdentity::report_data()`. The repository integrates AWS Nitro
  Enclaves (`crates/enclave`, `credentials host`): the NSM attestation document carries it as
  `user_data`, with the owner's nonce, and the owner checks it (`attest`, `credentials attest`, `credentials grant --attestation`):
  the chain to AWS Nitro Enclaves Root-G1, the nonce, `user_data`, and PCR0, PCR1 and PCR2
  against the published measurements of a reproducible release. Outside a TEE, the operator can read node
  memory and every guarantee that relies on the node keeping a secret falls away; the log,
  signatures and policy checks still bind an honest node.
- **A2.** The owner's device and its keys are not compromised. On the device, this includes the
  code that holds the keys: the owner's app (with the `client` crate), the `credentials` CLI,
  or a web page (see *Grants from a web page* under Residual risks).
- **A3.** The standard primitives hold: Ed25519, X25519/HPKE (RFC 9180), ChaCha20-Poly1305,
  SHA-2, HMAC, TLS with WebPKI.
- **A4.** The destination is the service the owner meant; the engine guarantees the secret
  goes to that host over TLS, not what the service then does with it.

## What stops each attack

| Attack | Defence | Where |
| --- | --- | --- |
| Operator changes where a value goes | Policy signed by a device and bound into the record's AEAD | `policy`, `record` |
| Operator swaps in an older record (narrower policy undone, revoked token back) | Generations in the AEAD; node floors; pins in grants and `Node::pin`; unpinned records refused | `record`, `node` |
| Operator impersonates a node: hands the owner an identity whose seal key it holds outside the enclave | The grant is sealed only after the attestation document verifies (chain to the pinned AWS Nitro root at the document's time, ES384 signature, the owner's fresh nonce) and its `user_data` equals `report_data()` of that identity; a document of another node, or replayed from an earlier request, is refused. In the `client` crate a grant takes only a `VerifiedNode`, which only the attestation check makes, from a nonce the app drew itself, used once, within five minutes | `attest`, `cli`, `client` |
| Operator runs the node in a debug enclave, whose memory the host can read | A document with PCR0, PCR1 and PCR2 all zero is refused even when the owner lists zero measurements | `attest` |
| Operator runs an old or unknown release (a build with a known flaw, or its own build) | PCR0–2 must equal one entry of the owner's `measurements.json`; the owner drops a release from the list to refuse it | `attest` |
| Operator reads a grant in transit | HPKE to the node's seal key; the key is bound to the attested identity | `grant` |
| Operator replays a stored grant after a revocation | Issue time within ±5 min and newer than the owner's last grant, revocation or device change (restored from the log); after a restart, nothing issued before the node started is accepted | `node` |
| Operator restarts the node with a cut log to forget revocations, devices and floors | Grants and calls made before the restart are refused, so stored ones cannot be replayed; `Node::restore_anchored` refuses a log shorter than the last checkpoint the platform kept out of the operator's reach | `node` |
| Operator replays a caller's authorization after a restart (the nonce cache is in memory) | Authorizations dated before the node started are refused | `node` |
| Operator grants its own key under an owner's name | Once an owner has a device, a grant must come from a device the node knows for the owner; the user key alone does not make a device known | `node` |
| Operator revokes to deny service | Revocations need a known device's signature | `grant`, `node` |
| A lost or sold device keeps acting for the owner | Another known device retires it (`DeviceKey::retire`); a retired device cannot come back by granting, even under a fresh device key with the same user key; only a new endorsement adds a device. Endorsements name the node and an issue time, so they cannot be replayed elsewhere or later | `keys`, `node` |
| Operator acts without a log entry | Transport calls need a `Confirmed`, made only after the sink confirmed | `log`, `egress` |
| Operator edits, reorders or cuts the log | Signed chain per node and per owner; signed checkpoints; `credentials verify` | `log`, `verify` |
| Log store reads where secrets were used | Use details sealed to the owner's user key | `log` |
| Operator points DNS at its own server | TLS certificate checked for the signed host | `transport` |
| Nitro host reads or changes the egress of an enclave node | TLS ends inside the enclave; the host relays only ciphertext to the `host:port` the node asked for, after the node checked it against the signed policy | `transport`, `relay` |
| Nitro host confirms a log entry it did not store, or drops one | Entries are signed and chained inside the enclave; a dropped or edited entry breaks `credentials verify`. A host that lies about storing can only lose the log, not forge it | `log`, `relay`, `verify` |
| Nitro host serves an attestation of other code, or of a debug-mode enclave | The document is signed by the NSM (AWS Nitro root); its PCRs must equal the published measurements, which are never zero for a production enclave; the nonce makes it fresh and `user_data` binds it to the identity granted to | `enclave` |
| Nitro host builds a different image and claims a release | The EIF build is reproducible (`build/reproduce.sh`): anyone can rebuild a tag and compare PCR0, PCR1 and PCR2 with the release | `build` |
| Caller not in the policy, or replaying a call | Per-call Ed25519 signature over node, record generation, operation, request digest, time, nonce; nonce cache | `caller`, `node` |
| Anyone probes whether an owner has a grant or which record generation is current | Grant, pin and generation errors are given only after the policy and the caller's signature verify | `node` |
| Anyone creates owners to grow the node's state | Owners are trusted on first use, so their number is capped (`MAX_OWNERS`) | `node` |
| Caller floods | Per-caller rate limit; at most 100,000 calls per caller and owner in the 5-minute replay window, authorizations at most 60 s ahead of the clock, so no caller fills the shared replay cache; render budgets; size limits on input, request, response, captures | `node`, `template`, `response` |
| Caller sends a request outside the operation | Host (one-label wildcards), method, path templates matched exactly, header allowlist, request-smuggling headers refused | `request`, `policy` |
| Caller reaches another path through a dot segment the server resolves (`..;/`, `%2e%2e`, `%252e%252e`, `..%3b`) | Each segment is checked as sent, with its `;` parameters stripped, after one decoding and after a second decoding (also stripped); `%2e`, `%2f`, `%5c` and `\` are refused; `%25` is refused unless the contract sets `encoded_percent` (strict by default). Measured on the four paths of the audit proof: none is sent | `policy::contract` |
| Caller adds query parameters the owner did not mean (another action, scope or limit for the same signature) | A caller may send only the query parameters its contract lists, each once, with values within `equals`, `one_of`, `pattern` or decimal `min`/`max`; anything else is refused before the log | `policy::contract` |
| Caller shadows a query parameter the policy injects (first-wins servers read the caller's) | A name the `send` injects is refused in the caller's query, whatever its case or encoding, and a contract may not list it | `policy::contract`, `policy` |
| Caller turns an allowed POST into a DELETE with `_method` (or a similar name) in the query or the body | The method-override names are refused in the query, form fields, top-level JSON members and multipart parts unless the contract sets `override_params`; a contract may not list them without it | `policy::contract` |
| Caller places a path parameter where a secret leaves with it (in its query, inside a segment) | A placeholder is a whole segment of a path template the owner signed; anywhere else it is refused in the policy and in the request | `policy::contract` |
| Caller has a derivation sign content the owner did not mean (a transfer of its choosing) | An operation that reads `$input` declares an input schema (raw, JSON or RLP); JSON and RLP schemas are closed, bound members and items by fixed values, allowed values, decimal bounds and node-set times, and refuse duplicate JSON keys and non-canonical RLP; the checked input is what the templates read | `policy::input` |
| Server returns values the caller should not get (temporary credentials minted by the request) | An HTTPS operation returns the status and only the headers and JSON members its `return` lists; converted policies return the status only | `response`, `policy` |
| Caller runs its own commands on a stream after the policy's login | A TLS operation relays a caller's exchange only when every send matches one of the patterns its `return` lists, whole; without them no exchange runs; checked before the log and the connection | `node`, `policy` |
| A value moved between steps escapes the analysis | A `compute` name has exactly the properties of its template, so every rule holds across steps; loops and branches are refused until the analysis covers them | `template`, `policy` |
| Caller builds an oracle in a derivation | Taint and oracle analysis at signing time. Encryption under a secret key hides only the key: another operation of the same policy could encrypt chosen bytes under it and a chosen nonce, so a secret in the message, nonce or data stays tainted. A hash or MAC of a secret is not a secret key, since some operation may hand it back; a plain hash of a secret alone stays tainted (it is the key of a long HMAC key or an Ed25519 seed); a secret and a chosen value may not meet across the number arguments of `time`, `totp` and `pbkdf2_sha256` | `template`, `policy` |
| Caller steers which part of a secret comes out of a cut or a number (`slice(key, $input, "1")`, `between(key, $input, "")`, `add(key, $input)`, `u8(key + $input)`) | A secret and a chosen value may not meet in `slice`, `between`, `add` or `json_set_number`, nor mixed in a fixed-width encoder; a captured secret temp counts as chosen, so it is not cut. Cuts and numbers keep the taint, so a derivation cannot hand one back | `template` |
| Caller downgrades the algorithm (`pbkdf2($input, ...)`, `rsa_sign_pkcs1($input, ...)`, `ecdh($input, ...)`) | Hash and curve names must be neither tainted nor controlled: the signed policy fixes them | `template` |
| Caller makes the node encrypt a secret to a public key the caller holds | The key of `rsa_encrypt_oaep` / `rsa_encrypt_pkcs1` may not be caller-chosen (request variables, `$input`): only a literal, a field or a capture of the destination's response; the ciphertext of a secret stays tainted | `template` |
| Caller obtains a key agreement secret, or a key derived from it, to read what the node encrypted under it | Every `ecdh` result is tainted and not controlled, so a plain hash of it stays tainted and a derivation cannot hand it back; ephemeral private keys are made per operation and curve inside the node, never rendered, and erased with the operation | `template`, `primitives` |
| Caller derives a key from a secret (`hkdf`, `hkdf_expand`, `concat_kdf`, `kbkdf_counter`, `kerberos_dk`) and reads it, or a plain hash of it | A key derived from a tainted value is tainted and not controlled (the caller chooses no byte of it), so a plain hash of it stays tainted and a derivation cannot hand it back; it is not a secret key, so what it encrypts stays tainted; hash names are fixed by the policy | `template` |
| Caller reads a secret back out of a length (`len(shake256($input, key))`, `len(hkdf(..., key))`) | A length argument of the second group of families (KDFs, SHAKE, `nfold`, the CCM tag) may not be tainted | `template` |
| Caller decrypts a block-cipher MAC (`aes_cmac`, `aes_cbc_mac`) under a known key to read a one-block secret, or wraps a secret under a known KEK | Block-cipher MACs drop the taint only under a secret key; key wrapping and the AES modes follow the encryption rule (a secret wrapped or encrypted stays tainted; under a key that is not a secret key, everything does) | `template` |
| Caller uses CBOR checks as an oracle (`cbor_array(key + $input)`, `cbor_map` with a secret key next to a chosen key) | The arguments of `cbor_array`, `cbor_map`, `cbor_tag`, `cbor_int` and `cbor_text` may not mix a secret with chosen bytes; in `cbor_map` a secret key may not meet a chosen key (their order and equality compare them); CBOR keeps the taint | `template` |
| Server sends a page or text that makes an `html` or `regex` capture slow or large | `regex` crate (finite automata, no backtracking) with 256-byte patterns, a 256 KiB program and a 1 MiB cache; `html5gum` tokenizer with one compound selector, no tree and no combinators; both read at most 2 MiB and capture at most 64 KiB; fuzz targets `html_capture` and `regex_capture` | `extract` |
| Caller brute-forces a PIN through a hash, MAC, signature or encryption | A derivation may depend on a `guessable` field only through `len` (a keyed MAC does not help: another operation could compute it on chosen input) | `template` |
| Server echoes the secret | Captured secrets redacted; reflection search over raw, base64, percent, JSON, hex and decoded JSON strings; the response is dropped on a hit | `reflection`, `node` |
| Server hides the echo in framing (chunks, encodings, ranges, folded headers) | Strict parsing: chunked joined, `Content-Encoding` other than identity, `206`, `Content-Range`, folded headers and duplicate lengths refused; `Accept-Encoding: identity` sent | `response`, `request` |
| Server moves one secret into another field | A captured value holding another secret field is refused | `node` |
| A device signs (by mistake, or under an attacker's control) a typed policy wider than its kind: a card number to a wildcard host, a whole response body, a login sent off its origin | The node re-derives the shape from the kind on every signature check and refuses the policy: connections, destinations (the pinned origin or host and port), wildcards, client certificates, captures, relays and the response projection; secret and masked fields stay secret and guessable ones guessable | `item`, `policy` |
| Caller reads a secret field of an item through `describe` | `describe` returns only public fields the policy keeps public and the masked projection the node computes; secret fields are never read into the answer; it needs a signed call of a listed caller and is logged before the answer | `item`, `node` |
| Operator or attacker binds a typed record to a kind of its own | A custom kind verifies only under a known device of the owner, and cannot take a reviewed kind's name; reviewed kinds are compiled into the release the owner attested | `item`, `policy` |
| A record holds a value that defeats its kind (another origin than the pin, a card number that is not one, an expired card) | Values are checked when sealed and on every use with the node's clock; a pinned field must equal the pin the policy signed | `item`, `record`, `node` |
| An ssh or VPN key goes to a server nobody authenticated | An `ssh` connection requires pinned host keys (below); typed items allow no protocol connection yet, and the ssh and vpn kinds none until their typed rules are reviewed; the ssh kind's host key is a required, checked pin | `item`, `policy` |
| Owner signs a new version without seeing what it widens | `summarize` against the previous version flags every new destination, method, path, header, query rule, injection, operation, caller and key, more of the response, looser limits, fields made public, and changed item bindings; anything it cannot rank counts as wider | `policy::summary` |
| Node shows the owner one summary and acts on another, or a caller replays an approval | An approval signs the SHA-256 of the canonical summary the node built, its random id, the node, owner and record, within a window of at most five minutes; the node keeps that summary with the waiting operation, takes an approval only over exactly it, once, and the id is spent when the operation goes on | `approval`, `node` |
| Caller answers a challenge itself (a code it guessed, phished or relayed) | A code reaches the node only as `SealedAnswer`: signed by a known device of the owner over the node, owner, id and code hash, sealed to the node with HPKE; the call that resumes carries only the id; the code must match the policy's pattern and is taken once | `session`, `node` |
| Approval replayed for a different amount, or for another use | The summary holds the amount and currency the node read from the contract-checked request or input; an approval of another summary, an id already spent, or a summary edited on the way is refused | `node`, `approval` |
| Caller splits a payment to stay under a limit | Every payment within the limits is counted under the same lock as the check, over rolling 24-hour and 30-day windows; payments no rule covers, or above one, wait for approval; limits and counts survive a restart through sealed log entries | `limits`, `node` |
| Caller writes the amount, currency or merchant of a summary | The currency is fixed by the policy, the amount is a decimal integer from a required, bounded query parameter or JSON member the contract checked (or the policy), the merchant is the origin of the destination the node sends to; summary lines are written by the node | `policy`, `node` |
| Another caller, or another owner's caller, resumes a waiting operation | The node resumes an id only for a signed call of the same caller name, record (the whole record) and operation; anything else gets `parked_unknown`, the answer for an id nobody parked | `node` |
| Parked values leak (temporaries, the code, opened fields) | Kept in the node's memory only, never logged or returned; the pending reply holds the id, kind, hint and node-built summary; captured secrets and codes are redacted from responses and checked for; dropped on lapse (at most five minutes), revoke and restart | `node`, `session` |
| Flood of waiting operations exhausts the node | At most 8 per owner, 256 in all and 128 MiB of values; an operation that may wait is refused before it sends anything when there is no room | `node` |
| Spending limits set by someone else, or rolled back | Limits are signed by a known device of the owner for one node and record, issued within five minutes of the node clock and after the limits the node holds | `limits`, `node` |
| A lapsed session is used, or renewal sends a secret elsewhere | The node writes a session's expiry when it captures it and checks it before every operation that reads it; renewal runs only an HTTPS operation of the same signed policy that takes no caller request, does not wait or pay, and captures the session without reading it | `policy`, `node` |
| An agent or caller gets code to run on a secret (to encode it where the site echoes it) | `run` takes code only from a URL on one of the operation's destinations, written in the signed policy (optionally pinned by SHA-256), or from a reviewed library compiled into the node (PCR2); never from the caller's request or input | `policy::run` |
| Output of site code leaves its origin (returned, logged, sent to another destination or in the caller's request) | Signing refuses any template that reads the output, a value computed from it, or a temporary value captured from the response of a request that carried it, unless it is injected into a request the policy fixes to the module's origin; `run` needs an HTTPS connection; all `run` steps of an operation share one origin; the output is never a field; responses that echo it are refused; log entries hold only the request's body hash and length, sealed | `policy::run`, `node` |
| The origin serves other code than the owner approved | The SHA-256 pin is checked before the module runs (`ModuleRefused`, no later request); an unpinned module is flagged `run_unpinned` in the summary | `node`, `policy::summary` |
| Site code exhausts the node (loop, memory, output, stack) or reaches its host | wasmi interpreter, no JIT; fuel (10⁹), 64 MiB memory, 64 KiB output, strict structural limits; only four host functions (no WASI, clock, randomness or I/O); one engine and store per run; memory erased after; errors are fixed values | `sandbox` |
| Operator hands the state of a node to its own build, or to an older release (downgrade) | The old node hands over only after its peer's attestation verifies against the `to` measurements of a successor statement, and nothing else; the statement must name the old node's compiled release as `from`, a newer Semantic Version as `to` (a statement that is not is refused before its signature is read), and be signed by the release workflow of this repository at the tag of `to` (Fulcio certificate chained to the pinned root at the Rekor integration time; SAN, issuer, runner, repository and ref extensions), logged in Rekor (signed entry timestamp and inclusion proof to a signed checkpoint, both required). Tested with test roots only: a downgrade, unlisted and debug measurements, another Fulcio root, every signer field, a changed statement, a bent proof, another log's checkpoint | `continuity`, `node` |
| Operator replays a successor statement or a message of the hand-over | A statement of an earlier hand-over names another `from` release and is refused; each side's nonce is used once, within five minutes, and spent on failure; the package is sealed to the successor's key named in the hand-over entry and is refused by any other node; the old node, once handed over, hands back only the same package to the same successor | `continuity`, `node` |
| Operator forks the log at a hand-over (keeps the old node acting, or splices another log) | The old node refuses every act after its `HandOver` entry; `ChainVerifier` takes after a hand-over only a `Continue` entry signed by the named successor whose `prev` is the hand-over's hash, and refuses any later entry of the old key; `credentials verify --next` checks one chain across the nodes | `log`, `node`, `verify` |
| Operator reads or changes the state in transit | HPKE to the successor's attested seal key, with the predecessor, successor, sequence, release and statement hash as additional data; the package hash is in the signed hand-over entry; the host only relays | `node`, `continuity::wire` |
| A grant moves against the owner's wish | `allow_successor` is in the signed grant terms; a grant with it off stays behind and is erased when the node hands over (`grant_without_successor`, `credentials grant --no-successor`); protective state (devices, retired devices, floors, limits) always moves, so a successor cannot be rolled back | `grant`, `node`, `client` |
| Operator steers the re-grant after a crash to its own node | `client::verify_successor` checks the statement of the release the owner granted to and the new node's attestation against its `to` measurements only; `client::regrant` takes only a node so verified and follows the owner's `SuccessorPolicy` (`AskOwner` needs the app to report the owner's approval; `Never` refuses) | `client` |
| A recorded device transfer is used to guess the 6-digit code offline | SPAKE2 (RustCrypto `spake2`, Ed25519 group): the transcript gives no test for a guess (tested: no code, the right one included, reproduces the recorded confirmation); key confirmation by HMAC-SHA256 over the transcript in both directions, before any key is sent | `client::transfer` |
| An attacker takes part in a transfer and guesses the code online, or changes a message | Every answer counts as a guess before it is checked; three wrong codes end the code, a transfer lasts five minutes, and each side seals or opens once: at most 3 in 10^6 per code shown; a changed offer, answer, session, confirmation, nonce or ciphertext fails confirmation or decryption | `client::transfer` |
| A key backup is opened by someone else, or moved to another owner | XChaCha20-Poly1305 under a random 32-byte backup key kept only in the platform's end-to-end encrypted store; owner, format and time in the additional data; no passphrase mode (a memorable passphrase would be guessable offline from the blob) | `client::backup` |
| Server echoes a secret into a streamed response, split across chunks so no single chunk holds it | The stream search holds back one less than the longest searched form of each secret (×6 for JSON escapes) and searches the raw and the JSON-unescaped view; a secret found ends the stream before any byte of it is handed on. Tested at every split offset in every form | `reflection`, `node::live` |
| Server echoes a secret over a WebSocket, whole or split across messages | Each message is searched with the tail of the one before it; a hit closes the connection (`reflection`). Server messages go back only when the policy says `server: true` (flagged `server_frames`) | `node::live`, `policy` |
| Caller sends WebSocket frames the owner did not mean (another command after the policy's login) | Each frame is signed for the call and in sequence, and must match a rule of its kind: a closed JSON schema or a `raw` pattern; anything else closes the connection before it is written. A rule with no shape is flagged `frames_unpinned` | `caller`, `node::live`, `policy` |
| Caller or server bends the WebSocket handshake (extensions that change framing, a subprotocol nobody offered, a wrong accept) | The node sets the handshake fields itself (the policy and the caller cannot); the answer must be `101` with the right `Sec-WebSocket-Accept`, no extension, and only an offered subprotocol. Server frames are parsed strictly (no masking, RSV bits, shortest lengths, control frames ≤ 125 bytes, UTF-8 text, size limit) | `websocket`, `node::live` |
| A node keeps relaying an open connection after it handed over (frames whose templates read a secret, unlogged) | Each streamed response and WebSocket checks, before it waits for and before it writes each caller frame, that the node has not handed over; if it has, it closes (WebSocket 1001) and nothing more is written. Tested by a hand-over in the middle of a WebSocket | `node::live` |
| Open connections exhaust the node or hide use | Idle, duration and byte limits per connection (capped in the policy); at most 4 per caller, 16 per owner and 256 per node; one log entry on open and one on close with counts both ways | `node::live`, `log` |
| Network attacker downgrades a policy that pins HTTP/2 | The transport offers only `h2` by ALPN and refuses an answer without it before writing; the engine checks the version the transport reports again | `transport`, `egress` |
| Server injects fields through HPACK (CR LF or NUL in a value, an upper-case or odd name, a pseudo-header, `content-length` that disagrees, connection-specific fields) to change what the HTTP/1.1 form says | Every field is checked before it is written in HTTP/1.1 form, and the form is parsed by the same response parser as HTTP/1.1 answers; decoding is bounded (table size, header list 64 KiB, Huffman padding) | `transport::h2`, `transport::hpack` |
| Network attacker or a server of the destination's name impersonates an SSH server | `host_keys` pins 1 to 16 keys in the signed policy; the node offers only the pinned keys' algorithms, and refuses a host key blob that is not pinned or a signature that does not verify before it sends any credential (tested: unpinned key, unpinned type, bad signature; no `USERAUTH` sent) | `proto::ssh`, `policy` |
| Network attacker downgrades SSH (SHA-1, CBC, `ssh-rsa`, finite-field groups) or uses Terrapin | Only curve25519/ECDH key exchange, AES-GCM and ChaCha20-Poly1305 are ever offered; strict key exchange (`kex-strict-c-v00`) is offered and, when the server agrees, a packet before KEXINIT is refused and sequence numbers reset; ChaCha20-Poly1305 is refused without strict key exchange; a rekey is refused (tested for each) | `proto::ssh` |
| Network attacker or server strips TLS (STARTTLS not offered, PostgreSQL `N`) or injects plaintext before it (CVE-2011-0411 class) | STARTTLS and `SSLRequest` are required where the policy or kind asks for TLS; a server that refuses fails the call before anything secret is written; bytes after the go-ahead fail the call: the engine refuses what its prelude read past the go-ahead, and anything still in the socket goes into the TLS handshake, which fails (the engine side is tested) | `proto`, `transport` |
| Server downgrades the sign-in (PostgreSQL cleartext or MD5, `AuthenticationOk` before SCRAM, too few iterations; SMTP or IMAP offering a weaker mechanism) | PostgreSQL takes SCRAM-SHA-256 only and verifies the server signature; 4096 to 1,000,000 iterations; SMTP and IMAP use the mechanism the policy names or fail, never another; `LOGINDISABLED` is honoured (tested: no password on the wire in each case) | `proto::postgres`, `proto::smtp`, `proto::imap` |
| Caller runs another command, query or mail than the owner meant (injection through a parameter) | Commands are named rules whose text the caller cannot change; caller parameters match a whole pattern and length before the log or the connection; parameters are bound (PostgreSQL), bulk strings (Redis), POSIX single-quoted words (SSH) or quoted strings with CR, LF and NUL refused (IMAP); mail envelopes match the mail rule, and a bare CR or LF in a message is refused (SMTP smuggling); dot-stuffing (tested: `x; rm -rf /`, `'; DROP TABLE`, a RESP-in-a-parameter, an IMAP line break, smuggled `.`) | `node::proto`, `policy`, `proto` |
| Server echoes the secret in a row, a reply, a mail body or an SSH channel | Every result is redacted and searched as the server sent it (raw values) and as returned (JSON), and across results; an SSH shell goes through the stream search; a hit ends the call with `reflection` (tested for each kind) | `node::proto`, `reflection` |
| Protocol server sends oversized or malformed answers | Bounded lines, messages (16 MiB PostgreSQL), RESP depth 16 and length, IMAP literals within the result limit, SSH packets of at most 256 KiB, the connection's byte limit; `protocol_servers` fuzz target and 15,000 noise inputs in the tests | `proto` |
| Caller or operator reads a secret sent over UDP (datagrams carry no TLS; in an enclave the host relays them) | A `udp` send template must not be tainted: a secret goes into a datagram only through a one-way function (an HMAC, a signature); the destination is fixed by the policy and the socket is connected to it; the summary flags `plain_datagram` | `policy`, `transport::udp` |
| Server or path answers a datagram with another one, or floods the node with datagrams | A connected socket (or the relay's per-destination socket) takes datagrams from the destination's address only; one datagram per read, at most 65,507 bytes; reads searched for reflected secrets like stream reads; at most 3 resends and 10 s per read | `transport::udp`, `relay::datagram`, `node` |
| Host relay sends datagrams to other places than the policy names | The enclave asks for one `host:port` per socket (`DATAGRAM host:port`); the host checks it against its `udp/` allow list; the content is what the policy allows on the path anyway | `relay::datagram`, `host` |
| Caller chooses the key or sender of an HPKE encryption (encrypts a secret to itself) | Rule 7: the recipient key, the PSK, its id and the sender key of `hpke_*` may not be caller-chosen; the suite and mode are fixed (rule 6); a PSK is at least 32 bytes | `template` |
| Caller learns a secret through whether `hpke_open` fails (a chosen info or AAD next to a secret) | Every argument of `hpke_open` and `hpke_receiver_export` is sensitive (rule 1); the plaintext and exported secrets are tainted | `template` |
| Exported TLS keying material leaves the connection it binds | `tls_exporter` exists only in a TLS `send`, after the handshake; it is tainted and never controlled, so it cannot be returned or hashed out alone; refused over TLS 1.2 (no proof of the extended master secret) | `template`, `policy`, `transport` |
| Memory disclosure of freed buffers | `Secret`/`Zeroizing` everywhere in the engine; exact-size buffers; erasing growth in the transport; zeroizing allocator for dependencies | all |

## Residual risks

These remain by design; each is listed in the README.

- **Site code: timing and failure.** Whether a `run` module succeeds, runs out of fuel or
  traps, and how long it takes, may depend on the secret, and the caller sees the outcome and
  the time of its call. The code is the site's own or reviewed, and the site already holds
  the secret; accepted. A module fetched without a pin is whatever the origin serves at the
  time (flagged). A site that echoes the output transformed is not recognised by the search
  (see `docs/sandbox.md`).
- **One TEE (A1).** Only AWS Nitro Enclaves are integrated. Elsewhere the node is an ordinary
  process. The attestation document must be verified by the owner (certificate chain, PCRs,
  nonce, `user_data`); the node only produces it.
- **Grants from a web page are weaker than grants from an app (A2).** The web package of the
  `client` crate runs the same checks, but a page is code its server sends anew at every
  load. Whoever controls that server, or its CDN, or injects script into the page, can serve
  code that reads the device and user keys, skips the attestation check, grants to a node of
  its choosing, or swaps the measurements list, and the owner cannot tell. An app is code the
  owner installed once, signed by its publisher and reviewed by a store, and its key storage
  (Keychain, Android Keystore) is out of reach of other code; a page has no such storage
  (IndexedDB is readable by any script of the origin). Grant from an app where you can; on the
  web, serve the page from an origin you control with a strict Content-Security-Policy and
  Subresource Integrity, and keep grants short.
- **App keys are not hardware keys.** The device and caller keys are Ed25519 and the user key
  is handed to nodes, so none of them can live non-exportable in the iOS Secure Enclave or
  Android StrongBox (P-256 only). Apps keep them wrapped by a hardware key at rest
  (`crates/client/README.md`), but the key bytes are in the app's memory while it signs.
- **Nitro: no sealed storage.** A restarted enclave generates a new node key: it is a new node,
  with a new log file, and owners grant to it again. The host can restart it at will (an
  availability matter: nothing granted to the old node opens on the new one), and the floors
  and devices learnt by the old node do not carry over; pins in new grants bring the floors
  back.
- **Nitro: the clock comes from the host.** The enclave reads its time from the hypervisor of
  the parent instance; the NSM attests nothing about it. A host that sets it back or forward
  has the effects listed under *Trusted clock* below. Owners should keep grant lifetimes
  short and watch checkpoint times.
- **Nitro: the host sees traffic metadata.** It learns which `host:port` the node connects to,
  when, and how many bytes flow (not their content), and when entries are logged. It can
  refuse any of it; the node then fails closed.
- **Nitro: build supply chain.** The PCRs bind the image to the commit, the Rust image, the
  Amazon Linux image and the nitro-cli packages named by digest and version in
  `measurements.json`; a compromised input that every rebuild uses is reproduced too.
- **Nitro attestation trusts AWS and the measurement list.** Whoever holds the AWS Nitro root
  key can sign any document; a release in the owner's list is trusted whatever it does. The
  attestation is checked once, before a grant: a node replaced later under the same identity
  is not re-checked until the next grant. The document's time is the module's, not the
  owner's clock; freshness comes from the nonce.
- **Unknown encodings.** A server that transforms a secret in a way the search does not know
  (compression of its own, encryption, splitting across fields) can return it to the caller.
  Policies should only call services that do not echo credentials.
- **Short secrets.** Fields of 4–7 bytes are searched raw only; shorter captured values are
  refused instead of searched. A short value appearing by chance drops the response.
- **Server-chosen values.** A value captured from a server is known to that server.
- **Short cuts of a secret.** `slice`, `u8` and the like can put fewer than 4 bytes of a
  secret in a request, below what the reflection search looks for. The policy fixes where they
  come from (the caller cannot move them), so this is what the owner signed.
- **What the owner widens.** `"body": "all"`, a query rule without a value rule, `encoded_percent`,
  `override_params`, broad relay patterns and `{"raw": {}}` inputs give the caller what they
  say; the summary flags each with `!`. A server that reads a path or a query in a way none of
  the checks model (other normalisations than dot segments, `;` parameters and two decodings)
  is outside what the contract can bound.
- **Typed data without its hash.** A JSON schema bounds EIP-712 typed data, but no template
  function computes its hash yet, so a policy cannot sign it with the bounds applied.
- **Parser buffers.** The HTML tokenizer and the regex engine keep their own buffers of the
  body they read; the zeroizing allocator erases them when freed, not while in use.
- **Low entropy without `guessable`.** The owner has to mark such fields.
- **What masks show.** A masked projection is part of a value: a card's brand and last four
  digits, the year of its expiry, an e-mail's first character and domain, a phone number's
  last two digits. Any listed caller may read them through `describe`. A check that fails on
  use tells an authenticated caller which field failed (an expired card), never its value.
- **Kinds bound only where the owner binds them.** A record without `item` is an untyped
  record: the shape of a kind protects only policies that bind it. Apps should create cards,
  logins and the like as typed items.
- **The summary's reading of templates is lexical.** `derive_reversible` is raised when a
  template of an output names an encryption, a key agreement or `xor`, directly or through a
  `compute` name; the signing-time analysis remains what refuses an oracle.
- **Trust on first use.** The first grant of an owner on a node decides its devices.
- **Trusted clock.** Freshness of grants, revocations, endorsements and calls uses the node's clock. A clock set back behind the node's start makes the node refuse everything signed until it catches up; a clock set forward lets grants expire early. In a TEE the clock must come from a source the operator cannot set.
- **Shared replay cache.** Each caller and owner may hold 100,000 of the 1,000,000 nonces; owners trusted on first use with many callers can still fill it at about 3,300 signed, logged calls per second, which stops calls for everyone until nonces expire (5 minutes).
- **Rollback without an anchor.** `Node::restore` alone cannot tell a cut log from a whole one; replays stay refused, but forgotten floors and devices come back only from new grants. Keep checkpoints in sealed storage and use `Node::restore_anchored`.
- **Connection slots of `credentials serve`.** Each client has 10 seconds to send a request and the server holds at most `--max-connections` (64) at once; a client that keeps reopening slow connections can make others get 503. Put the server behind a proxy that limits clients per address.
- **Side channels.** Timing and size of responses are visible to the caller. The engine does
  not pad or delay.
- **Waiting is per node.** Parked operations live in one node's memory: a restart or another
  node behind a load balancer loses them, and the caller starts over. An external challenge
  is polled only when the caller resumes.
- **What a waiting operation tells its caller.** The kind and hint of a challenge, and the
  summary of an approval (the masked item view, the amount and the merchant), go to the
  caller that started the operation.
- **Payments counted early.** A payment within the limits is counted when the node decides
  to send it, also when the request then fails; an approved payment is counted when the
  operation goes on. This errs toward waiting for approval sooner.
- **Amounts the contract cannot see.** A payment whose amount is only in a request body (no
  body contract yet) cannot declare `payment`; such an operation should require approval
  (`"approval": true`).
- **Availability.** The operator can always stop the node or the log; the engine fails closed.
- **Continuity rests on the release workflow and Sigstore.** Whoever can run the release
  workflow of this repository at a new tag (a maintainer, or anyone who takes over the
  repository or GitHub Actions) can sign a successor statement for its build; a compromised
  Fulcio could issue a certificate for that identity (the certificate's SCTs are not checked;
  the Rekor inclusion makes such a statement public). Owners who do not accept this grant with
  `grant_without_successor`. The compiled Sigstore trust root is the public instance's (from its
  TUF repository on 2026-11-26); a change of Sigstore's roots needs a new release, and only its
  Rekor v1 log is read.
- **Untested on hardware.** The hand-over, the take-over and the re-grant are tested with a
  test Nitro root and a test Sigstore (roots made at run time), never with the NSM, vsock or the
  real Sigstore root.
- **A hand-over that does not arrive.** If the package is lost after the old node handed over
  and the successor is then restarted (a new key), the state carried only in the package (user
  keys) is gone: owners re-grant (the crash path). The old node hands the same package again
  to the same successor while it runs.
- **Dependencies.** ring, rustls and other crates keep internal buffers; the zeroizing
  allocator erases them when freed, not while in use.
