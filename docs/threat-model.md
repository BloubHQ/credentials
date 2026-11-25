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
  the quote carries `NodeIdentity::report_data()`. *This repository does not include the TEE
  integration.* Without it, the operator can read node memory and every guarantee that relies
  on the node keeping a secret falls away; the log, signatures and policy checks still bind
  an honest node.
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
| Operator reads a grant in transit | HPKE to the node's seal key; the key is bound to the attested identity | `grant` |
| Operator replays a stored grant after a revocation | Issue time within ±5 min and newer than the owner's last grant or revocation (restored from the log) | `node` |
| Operator grants its own key under an owner's name | A grant must come from a device the node knows for the owner, or carry the user key in force | `node` |
| Operator revokes to deny service | Revocations need a known device's signature | `grant`, `node` |
| Operator acts without a log entry | Transport calls need a `Confirmed`, made only after the sink confirmed | `log`, `egress` |
| Operator edits, reorders or cuts the log | Signed chain per node and per owner; signed checkpoints; `verify` | `log`, `verify` |
| Log store reads where secrets were used | Use details sealed to the owner's user key | `log` |
| Operator points DNS at its own server | TLS certificate checked for the signed host | `transport` |
| Caller not in the policy, or replaying a call | Per-call Ed25519 signature over node, record generation, operation, request digest, time, nonce; nonce cache | `caller`, `node` |
| Caller floods | Per-caller rate limit; render budgets; size limits on input, request, response, captures | `node`, `template`, `response` |
| Caller sends a request outside the operation | Host (one-label wildcards), method, path prefix at segment boundaries, header allowlist; dot segments, encoded separators and request-smuggling headers refused | `request` |
| Caller builds an oracle in a derivation | Taint and oracle analysis at signing time | `template`, `policy` |
| Caller brute-forces a PIN through a hash | `guessable` fields | `template` |
| Server echoes the secret | Captured secrets redacted; reflection search over raw, base64, percent, JSON, hex and decoded JSON strings; the response is dropped on a hit | `reflection`, `node` |
| Server hides the echo in framing (chunks, encodings, ranges, folded headers) | Strict parsing: chunked joined, `Content-Encoding` other than identity, `206`, `Content-Range`, folded headers and duplicate lengths refused; `Accept-Encoding: identity` sent | `response`, `request` |
| Server moves one secret into another field | A captured value holding another secret field is refused | `node` |
| Memory disclosure of freed buffers | `Secret`/`Zeroizing` everywhere in the engine; exact-size buffers; erasing growth in the transport; zeroizing allocator for dependencies | all |

## Residual risks

These remain by design; each is listed in the README.

- **No TEE here (A1).** The largest gap until a platform integration exists.
- **Unknown encodings.** A server that transforms a secret in a way the search does not know
  (compression of its own, encryption, splitting across fields) can return it to the caller.
  Policies should only call services that do not echo credentials.
- **Short secrets.** Fields of 4–7 bytes are searched raw only; shorter captured values are
  refused instead of searched. A short value appearing by chance drops the response.
- **Server-chosen values.** A value captured from a server is known to that server.
- **Low entropy without `guessable`.** The owner has to mark such fields.
- **Trust on first use.** The first grant of an owner on a node decides its devices.
- **Side channels.** Timing and size of responses are visible to the caller. The engine does
  not pad or delay.
- **Availability.** The operator can always stop the node or the log; the engine fails closed.
- **Dependencies.** ring, rustls and other crates keep internal buffers; the zeroizing
  allocator erases them when freed, not while in use.
