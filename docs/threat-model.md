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

## Assumptions

- **A1.** In deployment, the node runs inside a TEE whose attestation the owner checks, and
  the quote carries `NodeIdentity::report_data()`. The repository integrates AWS Nitro
  Enclaves (`crates/enclave`, `credentials host`): the NSM attestation document carries it as
  `user_data`, with the owner's nonce, and the owner checks it (`attest`, `credentials attest`, `credentials grant --attestation`):
  the chain to AWS Nitro Enclaves Root-G1, the nonce, `user_data`, and PCR0, PCR1 and PCR2
  against the published measurements of a reproducible release. Outside a TEE, the operator can read node
  memory and every guarantee that relies on the node keeping a secret falls away; the log,
  signatures and policy checks still bind an honest node.
- **A2.** The owner's device and its keys are not compromised.
- **A3.** The standard primitives hold: Ed25519, X25519/HPKE (RFC 9180), ChaCha20-Poly1305,
  SHA-2, HMAC, TLS with WebPKI.
- **A4.** The destination is the service the owner meant; the engine guarantees the secret
  goes to that host over TLS, not what the service then does with it.

## What stops each attack

| Attack | Defence | Where |
| --- | --- | --- |
| Operator changes where a value goes | Policy signed by a device and bound into the record's AEAD | `policy`, `record` |
| Operator swaps in an older record (narrower policy undone, revoked token back) | Generations in the AEAD; node floors; pins in grants and `Node::pin`; unpinned records refused | `record`, `node` |
| Operator impersonates a node: hands the owner an identity whose seal key it holds outside the enclave | The grant is sealed only after the attestation document verifies (chain to the pinned AWS Nitro root at the document's time, ES384 signature, the owner's fresh nonce) and its `user_data` equals `report_data()` of that identity; a document of another node, or replayed from an earlier request, is refused | `attest`, `cli` |
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
| Caller sends a request outside the operation | Host (one-label wildcards), method, path prefix at segment boundaries, header allowlist; dot segments, encoded separators and request-smuggling headers refused | `request` |
| Caller builds an oracle in a derivation | Taint and oracle analysis at signing time. Encryption under a secret key hides only the key: another operation of the same policy could encrypt chosen bytes under it and a chosen nonce, so a secret in the message, nonce or data stays tainted. A hash or MAC of a secret is not a secret key, since some operation may hand it back; a plain hash of a secret alone stays tainted (it is the key of a long HMAC key or an Ed25519 seed); a secret and a chosen value may not meet across the number arguments of `time`, `totp` and `pbkdf2_sha256` | `template`, `policy` |
| Caller brute-forces a PIN through a hash, MAC, signature or encryption | A derivation may depend on a `guessable` field only through `len` (a keyed MAC does not help: another operation could compute it on chosen input) | `template` |
| Server echoes the secret | Captured secrets redacted; reflection search over raw, base64, percent, JSON, hex and decoded JSON strings; the response is dropped on a hit | `reflection`, `node` |
| Server hides the echo in framing (chunks, encodings, ranges, folded headers) | Strict parsing: chunked joined, `Content-Encoding` other than identity, `206`, `Content-Range`, folded headers and duplicate lengths refused; `Accept-Encoding: identity` sent | `response`, `request` |
| Server moves one secret into another field | A captured value holding another secret field is refused | `node` |
| Memory disclosure of freed buffers | `Secret`/`Zeroizing` everywhere in the engine; exact-size buffers; erasing growth in the transport; zeroizing allocator for dependencies | all |

## Residual risks

These remain by design; each is listed in the README.

- **One TEE (A1).** Only AWS Nitro Enclaves are integrated. Elsewhere the node is an ordinary
  process. The attestation document must be verified by the owner (certificate chain, PCRs,
  nonce, `user_data`); the node only produces it.
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
- **Low entropy without `guessable`.** The owner has to mark such fields.
- **Trust on first use.** The first grant of an owner on a node decides its devices.
- **Trusted clock.** Freshness of grants, revocations, endorsements and calls uses the node's clock. A clock set back behind the node's start makes the node refuse everything signed until it catches up; a clock set forward lets grants expire early. In a TEE the clock must come from a source the operator cannot set.
- **Shared replay cache.** Each caller and owner may hold 100,000 of the 1,000,000 nonces; owners trusted on first use with many callers can still fill it at about 3,300 signed, logged calls per second, which stops calls for everyone until nonces expire (5 minutes).
- **Rollback without an anchor.** `Node::restore` alone cannot tell a cut log from a whole one; replays stay refused, but forgotten floors and devices come back only from new grants. Keep checkpoints in sealed storage and use `Node::restore_anchored`.
- **Connection slots of `credentials serve`.** Each client has 10 seconds to send a request and the server holds at most `--max-connections` (64) at once; a client that keeps reopening slow connections can make others get 503. Put the server behind a proxy that limits clients per address.
- **Side channels.** Timing and size of responses are visible to the caller. The engine does
  not pad or delay.
- **Availability.** The operator can always stop the node or the log; the engine fails closed.
- **Dependencies.** ring, rustls and other crates keep internal buffers; the zeroizing
  allocator erases them when freed, not while in use.
