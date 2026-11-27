# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org);
before 1.0, minor versions may break formats and APIs.

## Unreleased

### Changed

- Web client: a secret key returned to JavaScript (`generateKey`, `importKey`,
  `generateBackupKey`, `unwrapKeys`, `TransferReceiver.open`) is decoded from a borrow of the
  key in wasm memory, which is then wiped. Before, the returned `String` was freed from wasm
  memory unwiped. The JavaScript types are unchanged (`string`). Two more copies are gone: the
  keys' JSON of a backup or a transfer is written into a buffer sized up front (a buffer that
  grew freed a copy unwiped), and keys are encoded with `encode_slice` (base64's
  `encode_string` goes through a 1 KiB stack buffer, which on the web is in the module's
  memory). Measured by the web smoke test, which now scans the module's memory for every key
  after each of its 16 parts: before, a device and a user key were left after the backup and
  transfer parts; now none at any point. The READMEs say that on the web the key strings live
  in the JavaScript heap until garbage-collected, where nothing can erase them (#55, first
  step).
- Hostile destinations cannot make the node use far more memory or CPU than they send (#52).
  Measured in release builds with a counting allocator, on the inputs of the report:
  - PostgreSQL: NULL values counted for nothing against the 16 MiB result limit. The rows are
    now written as JSON while they arrive and the JSON counts against the limit, and a result
    of more than 1,664 columns (what PostgreSQL returns at most) is refused. 65,535 columns
    of 200 NULL rows: 51.3 MiB received and a peak of 871 MiB before, refused at the row
    description with a peak of 4.5 MiB now; 1,664 columns of 10,000 NULL rows: 63.6 MiB and
    1,145 MiB before, refused after 12.8 MiB with a peak of 32.1 MiB now.
  - Redis: the budget counted string bytes, so `:1` cost one byte. Each element now costs its
    line with the CRLF, a reply has at most 1,048,576 elements in all (it was that many per
    array), and its JSON is written straight into bytes held to the limit
    (`Reply::json_bytes` replaces `Reply::json`). An array header no longer reserves room for
    the elements it announces, only for those that arrive. 16 arrays of 1,000,000 `:1`: 61 MiB
    received and a peak of 1,033 MiB before, refused after 3.9 MiB with a peak of 32.2 MiB
    now; 17 nested headers of about 1,048,575 elements (about 170 bytes): a peak of 544 MiB
    before, 0.5 MiB now.
  - WebSocket: the decoder copied the rest of its buffer for every frame. It now keeps an
    offset, as the protocol reader does (#46), through one buffer type both use, and refuses a
    message of more than 64 empty fragments. 1 MiB of one-byte fragments in 16 KiB pushes:
    774 ms before, 25 ms now; 1 MiB of empty fragments: 1.2 s before, refused in 8 us now.
- Every reader of a framed stream takes frames off the front of one buffer type
  (`engine::readbuf::ReadBuf`) that keeps an offset, instead of copying or moving the rest of
  its buffer for every frame (#46): the HTTP/2 transport, the SFTP client, the relay's
  datagram links and the node's caller streams, as the protocol reader and the WebSocket
  decoder already did. `relay::datagram::take_datagram` takes a `ReadBuf`. 64 KiB of the
  smallest frames, in the reads each one makes, in release builds (mean of 200 runs, 50 for
  SFTP): HTTP/2, 10-byte frames in 16 KiB reads, 14.7-16.5 ms before, 0.35-0.37 ms now; SFTP,
  10-byte packets, 13.9-14.9 ms before and 0.38-0.42 ms now in 16 KiB reads, 50.7-54.0 ms
  before and 0.42 ms now in 64 KiB reads (an SSH packet carries up to 256 KiB); caller
  streams, 77-byte frames in 16 KiB reads, 109 us before, 12-13 us now. Relay datagrams
  (median of 401 runs, old and new interleaved, a fresh buffer each, every frame used): 10-byte
  frames, 514-543 us before and 368-383 us now in 4 KiB reads (what the links read), 918-977 us
  and 382-397 us in 16 KiB reads; 1,202-byte frames in 4 KiB reads, 6.2-7.0 us and 5.5-6.2 us.
- Log files: one writer per log. `credentials serve` and `credentials host` hold an exclusive
  lock on each log file while they write it (`flock` on Unix; on Windows the file is opened
  sharing reads only), so a second process on the same file fails at start with "the log is
  in use by another process" instead of appending over entries the first one confirmed;
  `credentials verify` can still read a live log. On Unix the directory is synced after a log
  file is created and after a checkpoint is renamed into place, so a power loss cannot lose
  the new name; Windows has no directory sync (documented). Both hold on local filesystems
  only; a log on a network share is not supported. On Unix the lock is advisory: a `serve`
  from before this release does not take it, so stop the old one before starting the new
  one on the same log. New error variant `server::logfile::Error::InUse` (#54).
- Delegation: a delegated call that waits for the owner's approval (an operation marked
  `approval`, a card, a payment over the limits) works. Its summary named the caller as the
  label `delegate/caller`, which is no name, so every such call failed with
  `approval_invalid`; only payments within the limits went through. The summary now has
  `caller` (the delegate's caller) and a new `delegate` field, absent for the owner's own
  callers, so the hash of a summary without a delegate is unchanged. A client from before
  this refuses a summary that has `delegate` (#53).

- SSH: `chacha20-poly1305@openssh.com` works against OpenSSH. The node counted the 4-byte
  packet length in the block alignment of its padding, as in the clear; OpenSSH leaves it
  out for every AEAD, as for AES-GCM, so sshd refused the node's first encrypted packet
  (`padding error`), and the node would have refused sshd's. The node picks its first cipher
  the server offers (AES-256-GCM, AES-128-GCM, then ChaCha20-Poly1305), so this hit only a
  server that offers no AES-GCM: a `Ciphers` limited to ChaCha20, or an SSH server built
  with ChaCha20-Poly1305 alone (TinySSH, by its documentation; not tested). Every
  connection to such a server failed at its first encrypted packet. Found by the new interop
  matrix against OpenSSH 10.2; the fake server now checks the alignment as OpenSSH does (#106).
- SSH: a key re-exchange keeps the strict key exchange the first exchange agreed. OpenSSH
  sends the strict markers in its first KEXINIT only, so with ChaCha20-Poly1305 the node
  refused the server's first re-exchange as "chacha20-poly1305 without strict key
  exchange". The node now sends its own marker in the first KEXINIT only, too. Found by the
  same interop matrix; the fake server now leaves the marker out of a re-exchange (#106).

- DTLS: a server issued through an intermediate CA (almost every public CA) can be reached:
  the `open` step of a `dtls` operation takes `intermediates` (at most 8, each the padded
  standard base64 of a DER certificate of at most 8 KiB), which the certificate check uses as
  the chain. They widen nothing: the chain must still end at one of the node's roots.
  Before, only a certificate issued by a root directly, or a pinned self-signed one, was
  accepted. `Transport::open_dtls` and `transport::dtls::Trust::new` take the intermediates.
  A format addition: a node from before this refuses a policy that lists `intermediates`
  (unknown fields are refused), and the signed bytes of a policy without them do not change
  (#80, for the format versioning of #76).

- SSH: a key re-exchange the server starts is carried out instead of ending the connection.
  Servers rekey after a volume or a time (Dropbear at 1 GiB or 8 hours, Paramiko at 512 MB,
  OpenSSH with `RekeyLimit`), so a long SFTP transfer or shell failed. The server must prove
  the host key of the first exchange; the session identifier stays the first exchange hash;
  strict key exchange, when agreed, resets the sequence numbers at every NEWKEYS; at most
  256 re-exchanges per connection (#82).

- FTP: the address of a `PASV` reply is ignored and only its port is used. The data
  connection still goes to the control connection's server; a port below 1024 is still
  refused. Before, a server behind NAT that names its private address (vsftpd without
  `pasv_address`, IIS on a cloud VM) was refused. When the data connection to an `EPSV`
  port cannot be made, the node asks again with `PASV` and keeps to it for the session;
  before, it fell back only when `EPSV` was refused with a 5xx (#83).

- `credentials verify` takes a node key or user key that starts with `--` (one key in 4,096
  in URL-safe base64) as a key; before, it failed as an unknown option with exit code 2,
  unless it came after `--`. An argument of a key's shape (43 URL-safe base64 characters)
  is never an option (#99).

- **Protocol reads are linear.** `proto::io::Io::take` copied every byte left in the read
  buffer on each take; MySQL packets and AMQP 1.0 frames are read take by take, so 64 KiB of
  small ones cost a copy of the buffer per packet. The buffer now keeps a read offset and is
  compacted (the taken bytes wiped) only before more bytes are appended. Measured in release,
  64 KiB of 10-byte packets in one read, median of 9 runs: MySQL 6,553 packets 65.9 ms and
  429,457,408 bytes copied before, 1.9 ms and 65,530 bytes after; AMQP 1.0 6,553 frames
  39.9 ms and 214,741,810 bytes before, 1.5 ms and 65,530 bytes after. The bounds (deadline,
  idle time, bytes) are checked on every take, also when the bytes are buffered already.
- Live loops (WebSockets, protocol relays, browser fills) read whether the node handed over
  from a flag set with the hand-over under the state lock, without taking that lock every
  10 ms; every write to the log still checks the hand-over under the lock.
- Release builds check integer overflow (`overflow-checks = true`); `panic` stays `unwind`, so
  a panic in a connection still ends only that connection. Measured (`cargo build --release
  -p cli --locked`, Windows x86-64): `credentials.exe` 17,839,104 bytes before, 18,059,264
  after (+220,160, +1.2%).

- Windows: the CLI reads a JSON document that starts with a UTF-8 byte order mark (as
  `Set-Content -Encoding utf8` writes it), and refuses UTF-16 (what `>` writes in Windows
  PowerShell 5.1) with a message that suggests `--out`; before, both failed with "expected
  value at line 1 column 1". The CLI walkthrough has a PowerShell section, and the README
  quick start the PowerShell way to set the token.

- The CLI names where in a JSON document a field fails, in the path style of the semantic
  checks (``policy.json: operations[0].steps[0]: missing field `port` ``, `callers[0].key:
  invalid base64 array`), through `serde_path_to_error` (MIT or Apache-2.0); before, the
  message named no place. A template that does not parse says at which byte
  (`policy invalid at operations[0].steps[0].template (byte 2): template syntax`).

- Tests that failed under load wait for a signal instead of a fixed pause: the SSH slot
  tests wait until each held connection reached the fake server (and hold it for 5 s, not
  1.5 s), the TLS idle-timeout test expects `sent: true` only when the server read the
  request (the timeout also covers the handshake), and the connection-cap test of the CLI
  probes with 500 ms and checks its deadline before each probe. The host's log directory
  test fails instead of passing silently when it cannot set up.

- MQTT 3.1.1: a token or password without a user name now goes with a user name of zero
  length, as [MQTT-3.1.2-22] requires (strict brokers closed the connection). MQTT 5: the
  Server Keep Alive of the CONNACK sets the ping interval ([MQTT-3.2.2-21]); before, 60
  seconds were fixed and a broker with a lower limit disconnected. SMTP says
  `EHLO [127.0.0.1]` (an address literal) instead of `EHLO localhost`, which strict HELO
  checks refuse.

- A response to `HEAD`, and any `204` or `304`, has no body whatever its length headers say
  (RFC 9112 section 6.3, RFC 9113 section 8.1.1), over HTTP/1.1 and HTTP/2; before, one that
  carried `Content-Length: N` (as static file servers send on `HEAD`) failed with "body
  shorter than its length". The framing now knows the request method
  (`response::is_head_request`).

- An operation that may wait now holds its waiting slot from the room check until it parks
  (`node::park::Reservation`, released on drop); before, the room was only checked, so
  overlapping calls all sent their login or challenge request and the extra ones failed with
  `ParkedFull` after it. A resumed operation keeps the slot it leaves while it runs, so an
  external challenge that is still pending is no longer dropped when it parks again.

- **An operation on a streaming call no longer waits.** A WebSocket, an SSH shell or
  forward, a live MQTT relay and an HTTPS operation whose response streams are refused
  `"approval": true`, a `payment` and an item kind that waits for approval when the policy is
  signed: the resume is a call of its own, with no stream left to relay. The node checks it
  again before it parks anything.

- Every browser fill now ends by clearing the page's history and checking it holds one
  entry (a browser that keeps it refuses the fill after the values went in), so the
  back/forward cache cannot bring a filled document back; a fill is refused when any target
  of the browser (a worker, another page) has a client attached, and the node lists the
  targets again before each value and the submit; a fill that stops after a value went in
  blanks what it filled. The approval of a browser operation shows the page's origin, and a
  payment by one counts at the page, not at the CDP endpoint.
- An operation that pays from the caller's request (query, body or form) has exactly one
  `send` that takes the request, and a query that carries the amount holds no `;` (some
  servers split a query there, which carried a second amount past the one counted). A query
  parameter named for a currency in a paying operation must equal the payment's currency.
- A TLS operation that waits for the owner's approval now runs the caller's exchanges when it
  goes on; before, they were not kept with the waiting operation and the resume failed.

- The request variables of an HTTPS injection read the request **as it is sent**, not the
  caller's request before injection (`docs/policy.md`, Injection order; `engine::request`
  `order`): `$path`, `$pathname`, `$query`, `$target_uri` and `$query_param` with the path
  parameters filled and the injected query parameters appended, `$header` also for a header
  the `send` injects (in a fixed request too), `$body` the injected body; never what the
  reading injection sets itself (in a query injection `$query` lacks it, a path parameter keeps
  its own `{name}`, the body's injection reads the caller's body). The injections render in
  dependency order, ties by listed order; the wire order stays the listed order. Signing
  refuses injections that read each other in a cycle and a template that names the header or
  query parameter it sets. A request variable carries the analysis properties of everything
  injected into it, so a secret injected into the path taints `$path` exactly as written there;
  the runtime taint list (the reflection check) and the summary's uses follow the same edges.
  A policy whose templates read a variable that an injection of the same `send` fills now
  renders over the filled value, and one signed before whose injections read each other in a
  cycle (two query injections that both read `$query`) no longer runs. Closes the open question of `docs/design.md` section 13
  left by the request components: RFC 9421, SigV4, OAuth 1.0a and Hawk now cover what the
  policy fills (`crates/engine/tests/final_request.rs`).
- CI fuzzes each target for 10 seconds on a pull request, 60 on main and 300 in a new daily
  scheduled run (previously 60 everywhere).
- A protocol line that arrives whole is held to the line bound too (`proto::io::Io::line`):
  before, a line longer than the bound passed when its end was already buffered.

- Policy IR `repeat` and `if` run (`engine::policy::flow`; `docs/policy.md`, Loops and
  branches). A loop has `times` (1 to 8, fixed by the signed policy), `steps` and an optional
  `until`; a branch has `when`, `then` and `else`. A test is `{"name", "one_of" | "none_of"}`
  (1 to 16 values) and may read only a value no secret influences: a secret field or capture,
  a `run` output, a challenge code, anything computed from one (a MAC or length included) and
  a public capture from the answer to a request that carried one or went over a client
  certificate (except the status) are refused at signing. Bodies hold `send`, `receive`,
  `compute`, `repeat` and `if`, nested at most 2 deep; `await` and `run` are refused in a
  body. HTTPS operations and (only `if`) derivations; not in an operation that pays or whose
  response streams. A loop's requests count as often as it may run against the 8 requests of
  an operation, and every run sends one. A name is readable after a branch only when both
  bodies define it, with the properties of both; inside a loop a capture may give a new value
  to a name captured before it, and a missing optional capture clears the old value.
  Confinement of `run` outputs follows bodies to a fixed point. The old syntax (`until` as a
  string, `if` with `name`/`equals`) is refused.
- Summaries: `most_requests` and `control` per operation, requests and uses inside bodies at
  the step of the loop or branch, the `repeat` flag; the diff ranks a larger cap, a changed
  test, a body that gains a step and more requests per use `wider`. `Operation::most_requests`
  is public. The JSON Schema has the new `Test`, `until` and `when`.
- The policy fuzz target checks that a signed operation never exceeds the request bound.

- The compiled Sigstore trust root (`crates/continuity/trust/trusted_root.json`) is the public
  instance's, from its TUF repository (`gh attestation trusted-root`, 2026-11-26); release
  signing pins Fulcio and Rekor v1 (`--use-signing-config=false`) and checks the bundle has a
  signed entry timestamp and an inclusion proof.
- Minimum Rust 1.88 (was 1.87): `time` 0.3.47, which fixes RUSTSEC-2026-0009, needs it.

### Added

- Web client: key objects `DeviceKey`, `UserKey` and `CallerKey`, which keep a key in wasm
  memory and use it by reference, beside the string API. A key object is wiped when it is
  freed: by `free()`, at the end of a `using` scope (`Symbol.dispose`), or when the garbage
  collector collects it (a `FinalizationRegistry`, whenever that runs). It becomes a
  JavaScript string only through `exportKey()`. Each has the calls of its
  kind as methods (`device.grant(user, node, ...)`, `user.sealRecord(...)`,
  `caller.signCall(...)`), which call the same functions as the string API (#55).
- JavaScript in the sandbox (layer 3): the reviewed library module `js`, the boa engine 0.21.1
  compiled to WebAssembly (`crates/sandbox/js`, checked in as
  `crates/sandbox/libraries/js.wasm`, rebuilt and compared by `build/js-module.sh` and the CI
  job `js-module`), chosen over QuickJS-NG by measurement (`docs/sandbox.md`, Choice of
  engine). A `run` step names a `script` (a URL on the destination's own origin, SHA-256
  required) and the function to call; the node fetches it as a logged request, refuses a
  mismatch, and `sandbox::run_script` runs it with the inputs as `Uint8Array`s. Scripts find
  no `Date`, `Math.random`, timers or I/O, and get `TextEncoder`, `TextDecoder`, `atob`,
  `btoa`; the output is confined to the script's origin like a module's.
- `run` steps take `limits` (`fuel`, `memory`, `time_ms`, `source`), each at most the node's,
  and a library may be pinned by `sha256`. The sandbox has a wall-clock limit of 5 s per run
  (`sandbox::MAX_TIME`, checked at every host call and after the run) and new errors `Time` and
  `Refused`; `sandbox::Limits` gained `time` and `script`.
- Fuzz target `sandbox_script`: arbitrary JavaScript sources and arguments on the engine.
- DTLS 1.2 and 1.3 (RFC 6347, RFC 9147) as the `dtls` connection (`docs/policy.md`, DTLS;
  `docs/design.md` section 7b): `send` writes one record of 1 to 16,384 bytes, `receive`
  reads one, over the datagram path of `udp` (a connected UDP socket, or the enclave's
  datagram relay, `udp/host:port` in `--allow`). Nothing is written before the handshake is
  complete and the server's certificate passes the verifier of a `tls` connection (WebPKI
  chain to the transport's roots, validity, host name); `open.pins` (at most 16,
  `sha256/` and the base64 of the SHA-256 of the `SubjectPublicKeyInfo`) also requires one
  of those keys, and lets a self-signed certificate with a pinned key through. Sends may
  hold secrets (encrypted, unlike `udp`); no client certificate, no PSK suite, no
  `tls_exporter`. The caller's exchanges are at most 64 records with no delimiters, read
  through the delimiter-safe reader and the stream search. A new pin, or dropping all pins,
  widens a policy in its diff. The schema has `dtls` and `pins`; `Transport::open_dtls`
  (default: refused); `transport::dtls` with `DtlsStream`, `Trust` and a `dimpl` crypto
  provider on ring and rustls-webpki; the `dtls_client` fuzz target.
- New dependency `dimpl` 0.8.0 (MIT OR Apache-2.0, `forbid(unsafe_code)`), built with no
  crypto backend, and the provider `transport::dtls` gives it from ring, rustls-webpki and
  `aes`: 11 new packages in `Cargo.lock` (276 to 287): `dimpl`, `arrayvec`, `nom` 8 (next to
  7), `rand` 0.9, `rand_chacha` 0.9, `rand_core` 0.9 (next to 0.10), `ppv-lite86`,
  `getrandom` 0.3 (next to 0.2 and 0.4), and `r-efi` 5.3 (next to 6.0), `wasip2`,
  `wit-bindgen`, which build only for UEFI and WASI targets. No RustCrypto crate of the
  previous generation; `credentials.exe` (release, Windows x86_64) grows from 13,692,928 to
  14,379,008 bytes (+686,080, +5.0 %).

- Typed browser fills and the agent's controller kept out of a fill (`docs/policy.md`,
  Browser fills and Typed browser fills; `docs/design.md` section 6, part 8):
  - `open.browser` on a `browser` connection: `exclusive` (`header`, `value`) names the
    answer by which the CDP endpoint says it handed the browser to the node alone; without
    that exact header in the `101` the node sends no command. Without `exclusive` an
    operation is flagged `browser_shared`. `leave: reload` loads a page that stayed after
    the last submit again with a GET at the fill's origin (outcome and close reason
    `reloaded`); `leave: blank` is the default and today's behaviour.
  - The kinds `card` and `login` allow `browser` connections: `shape.browser` lists the
    roles a fill may put into a page (`username`, `password`, `totp` as a 6-digit RFC 6238
    code; `number`, `expiry`, `expiry_month`, `expiry_year`, `cvc`, `holder`) and the page's
    origin (a login's pinned origin exactly, top frame only; a card at the merchant the owner
    names, fields possibly in a direct child frame). `ItemBinding::browser_fill` (with
    `ItemFill`, `RoleField`) makes the fill from roles and selectors. A typed browser
    operation must ask for `exclusive` and `leave: reload`, put only role templates (each
    once) and inject nothing into the handshake. Custom kinds may name roles too.
  - `engine::cdp`: `Page.resetNavigationHistory`, `Page.getNavigationHistory` and
    `history_entries`.
  - Tests against the fake CDP endpoint (`crates/engine/tests/browser.rs`): the grant missing
    or wrong, a client attached at the start or mid-fill, a second tab mid-fill, values left in
    the page or its history after `navigated`, `submitted` and `reloaded`, six look-alike
    origins, frames of another and the same origin, widened templates, TOTP against three
    RFC 6238 vectors, a card fill before and after the owner's approval, `describe` of both
    kinds. No real browser or endpoint was measured.
- Body contracts and payment amounts read from them (`docs/policy.md`, The body contract and
  Payments and spending limits; `engine::policy::BodyContract`): a caller request may declare
  `body: {"json": {"members": [...]}}` (checked like a JSON input) or
  `body: {"form": {"fields": [...]}}` (fields allowed by name like query parameters). The node
  sends the body it wrote again (JSON compact; form bytes percent-encoded but the unreserved
  ones) with the contract's content type; signing refuses a body contract with a caller or
  injected `Content-Type` or `Content-Encoding`, an injected body, gRPC, a non-HTTPS
  connection, or differing contracts on the sends of one caller request. A payment's amount
  may come `{"from": "body", "pointer"}` or `{"from": "form", "name"}`, in minor units or
  (`"format": "decimal"`, strings and form fields only) as a decimal with exactly the
  currency's digits; it is read from the bytes the node sends, by the parser that wrote them,
  canonical only, at most 10^18 minor units and 2^53 − 1 as a JSON number. A currency in the
  body (`currency_at`, or any member, field or query parameter named for a currency) must be
  fixed to the payment's. A new risk flag `caller_amount` names every amount the caller
  chooses; a body contract changed or removed counts as wider. `Request::checked` gives the
  request the node sends. `crates/engine/tests/amounts_await.rs`; the `caller_request` and
  `decimal_amount` fuzz targets cover the new parsers.
- `await` on TLS, before the connection opens (`docs/policy.md`, `await`): code challenges
  directly after `open`; the node logs, renders and connects only once the code came, and
  keeps the caller's exchanges with the waiting operation. Closing the connection at the park
  and reconnecting on resume was rejected (it replays the login, and a site's challenge is
  tied to its connection); an `await` anywhere else on TLS, and on UDP, WebSocket and protocol
  connections, stays refused.
- SSH remote port forwarding and AMQP 1.0 (`docs/policy.md`, Protocol connections;
  `docs/design.md` section 7c), the two protocol rows left in section 7c:
  - SSH `channel: "tcpip-forward"` (RFC 4254 section 7.1): the server listens on the
    `address:port` the signed policy fixes (port 1 to 65535, never the caller's), and the one
    `forwarded-tcpip` connection it forwards there, for exactly that address and port, is the
    call's relay; the node opens no socket of its own. Any other channel the server opens is
    refused (more than 16 end the connection); the forwarded connection takes a live slot of
    its own and ends on a hand-over. A wildcard bind needs `wildcard_bind: true`. Summary
    flags `remote_forward` and `wildcard_bind`. Engine `ssh::Client::tcpip_forward`,
    `accept_forwarded`, `refuse_forwarded`, `ssh::Event::Forwarded`, `MAX_REFUSED_OPENS`.
  - `connection: "amqp1"`: AMQP 1.0 over TLS or the AMQP TLS header, SASL `plain`,
    `external` (new mechanism: the open's client certificate), `scram-sha-256` and `xoauth2`;
    commands `send` (address, body) and `receive` (address; `max_messages`, `wait_ms`) with
    `settle` `settled`, `first` or `second`. Frames of 64 KiB, values 16 deep and 16,384 a
    decode, descriptors a `ulong` or a symbol of 256 bytes, messages of 1 MiB; unknown
    performatives, other channels or links, a changed settle mode and deliveries past the
    credit are refused. Engine `proto::amqp1` (codec, framing, client),
    `postgres::Scram::with_user`, `policy::SettleMode`, `policy::bind_target`. Schema: the
    connection, the mechanism, the channel, `settle` and `wildcard_bind`.
  - Fuzz target `amqp1_frames` (the AMQP 1.0 type decoder, frames, performatives and
    messages); `protocol_servers` and the noise test take the AMQP 1.0 client too.
- SRP-6a and OpenPGP framing as template families (`docs/policy.md`, SRP-6a and OpenPGP;
  `docs/design.md` section 11), two rows of the list of schemes not done:
  - `srp_public`, `srp_x`, `srp_u`, `srp_premaster`, `srp_m1` and `srp_verify` (RFC 2945,
    RFC 5054) over the seven groups of RFC 5054 appendix A with SHA-1 or SHA-2, on
    `crypto-bigint` 0.7.11 (already a dependency of `rsa`): constant-time Montgomery
    arithmetic at precisions set by the group and the input lengths. RFC 5054 appendix B
    (`k`, `x`, `v`, `A`, `u`, the premaster secret) byte for byte; the seven groups checked
    to be safe primes. A `B` of zero or not below `N` and a `u` of zero are refused;
    `srp_verify` fails the operation when the server's `M2` does not match. A premaster
    secret counts 3 against the 32 signatures of an operation.
  - New rule 11: the SRP private value is neither caller-chosen nor captured; `B` and the
    arguments of `srp_verify` are not caller-chosen. Rule 10 now also refuses a tainted input
    to `pgp_mpi`.
  - `pgp_packet`, `pgp_subpacket`, `pgp_mpi` and `pgp_armor` (RFC 9580, CRC-24 on request for
    RFC 4880 readers). Detached signatures are policies over them and the existing signature
    functions: version 4 with RSA and with EdDSALegacy, version 6 with Ed25519 and a salt.
  - A two-request SRP login (`srp-login`) against a server on `num-bigint`, and the three
    signing policies, verified by ring, `rsa` and GnuPG 2.4.9 (v4 only, by hand).
  - Dev-dependencies `num-bigint` 0.4.8 and `crypto-primes` 0.7.2, both already in
    `Cargo.lock`.
- Parameter lists, derived EC keys and binary-message helpers as template families
  (`docs/policy.md`, Parameter lists, derived EC keys and binary messages; `docs/design.md`
  section 11), for OAuth 1.0a, the SigV4A key and NTLMv2 over HTTP:
  - `sorted_params(list, ...)`: 1 to 8 form-encoded lists, decoded, encoded again as RFC 3986
    says, sorted by name and value and joined (RFC 5849 section 3.4.1.3.2). A secret and a
    chosen value may not meet in it (rule 2); a malformed `%` fails.
  - `kbkdf_ec_key(curve, hash, key, fixed_prefix, fixed_suffix)`: an EC private key on
    `p256`, `p384` or `k256` from NIST SP 800-108 counter-mode candidates (HMAC-SHA-2, the
    candidate byte 1 to 254 between prefix and suffix), the first with `c <= n - 2` giving
    `c + 1` (FIPS 186-5 appendix A.2.2). Curve and hash are fixed by the policy (rule 6); the
    key is a secret (rule 8). `kbkdf_counter` shares its counter-mode code.
  - `utf16le`, `utf16be` (UTF-8 to UTF-16, no BOM), `uint_be`, `uint_le` (1 to 8 bytes as a
    decimal number; refused on a secret, rule 9).
  - The summary flags `weak_mechanism` on every operation whose templates compute `md4`.
- Worked policies `oauth1-hmac-sha1`, `oauth1-rsa-sha1`, `sigv4a` and `ntlm-http` (NTLMv2 with
  the server's timestamp, `MsvAvFlags` and the MIC, on one TLS connection with hand-written
  HTTP/1.1, then a relay), tested in `crates/engine/tests/schemes_primitives.rs` against RFC
  5849 sections 1.2 and 3.4.1 and MS-NLMP section 4.2.4, and by verifiers written in the test.
- Fuzz target `parameter_lists`: `sorted_params` never panics, stays within its bound and
  is idempotent.

- DEFLATE and XML canonicalization as template families (`docs/policy.md`, Compression and
  XML; `docs/design.md` section 11), the two gaps of the scheme table:
  - `deflate`, `inflate`, `zlib_deflate`, `zlib_inflate`, `gzip_deflate` and `gzip_inflate`
    (RFC 1951, 1950, 1952) over `miniz_oxide` 0.9.1. One inflation writes at most 1 MiB and
    no more than the budget has left, into a buffer sized before it starts; past it the stream
    is refused. Trailing bytes, a second gzip member, a zlib preset dictionary and a wrong
    checksum or length are refused. The gzip header the engine writes has no name, MTIME 0 and
    OS 255.
  - `xml_c14n(algorithm, document[, inclusive_prefixes])`: Canonical XML 1.0 and 1.1 and
    Exclusive XML Canonicalization 1.0, with and without comments, named by their W3C
    identifiers, with the `InclusiveNamespaces` prefix list; and `xml_escape(text)`. Over the
    `quick-xml` 0.42 tokenizer (no default features). Documents are UTF-8 XML 1.0 of at most
    1 MiB, 64 levels and 65,536 nodes, with no DTD; a canonical form is at most 8 MiB and the
    budget left.
  - `engine::compress` and `engine::xml` are public, for the fuzz targets `inflate_stream` and
    `xml_c14n`.
  - The SAML 2.0 service provider bindings are policies over them: HTTP-Redirect signed with
    RSA-SHA256 and ECDSA P-256, HTTP-POST with an enveloped XML signature, and WS-Security
    (UsernameToken digest, BinarySecurityToken signature over the timestamp and the caller's
    body); `crates/engine/tests/schemes_xml.rs` verifies each with `rsa` and ring.
- Protocol connections `pop3` and `ftp` (`engine::proto::pop3`, `engine::proto::ftp`;
  `docs/policy.md`, Protocol connections), and typed SFTP operations:
  - POP3 (RFC 1939) over implicit TLS or `STLS` (RFC 2595): `CAPA`, then the mechanism the
    policy names and no other: `user` (`USER`/`PASS`), `apop` (MD5, flagged
    `weak_mechanism`), or SASL (RFC 5034) `plain`, `login`, `xoauth2`. `STAT`, `LIST`,
    `UIDL`, `RETR`, `TOP`, `DELE`, `NOOP`, `RSET` with message numbers only.
  - FTP over TLS only (RFC 959, 4217): implicit or `AUTH TLS`, `PROT P` required, typed
    `list` (MLSD or NLST), `retrieve`, `store`, `delete`, `mkdir`, `rename`. Passive data
    connections only (EPSV, then PASV), each to the control connection's own address (a
    `PASV` reply naming another host is refused: FTP bounce), to a port of at least 1024,
    over TLS resuming the control session, and ending in `close_notify`.
  - SFTP `list`, `stat`, `rename`, `delete`, `mkdir`, `rmdir`, each path checked as for
    `read`, never through a link; `rename` never overwrites.
  - Replies of both kinds come back with the sign-in's user name and password replaced by
    `[redacted]` (`engine::proto::io::Scrub`); paths cannot hold a control byte; replies,
    lines, listings and files are bounded. The `ftp` kind is typed (`tls` pins the mode;
    `plain` allows no operation), and the `mail` kind takes optional `pop3_host` and
    `pop3_port`. Kind shapes take `pop3`, `ftp` and `tls`; the schema takes the new
    connections and mechanisms. Fuzz target `ftp_pop3_replies`.
  - The transport's `Stream` gives the peer address and opens a data connection to the
    same server (`peer_ip`, `open_data`).
- Template capabilities for the gaps the scheme tests found, each a family (`docs/policy.md`,
  Request components, AEAD parts and public keys; `docs/design.md` section 11):
  - Request components: `$header("name")` reads a header of the caller's request (only one
    the `send`'s contract lists; combined as RFC 9110 section 5.3 says, without surrounding
    whitespace), `$query_param("name")` a query parameter as RFC 9421 `@query-param`
    normalizes it, and `$port`, `$scheme`, `$authority` and `$target_uri` the RFC 9421 derived
    components. Names are string literals; signing refuses a component the contract does not
    list, any in a fixed request, a `compute` step or a derivation. Values are controlled and
    caller-chosen like `$body`; no rule of the analysis changed.
  - AEAD parts: `aead_ciphertext(...)` and `aead_tag(...)` around an AEAD call written in
    place (`aes_gcm_encrypt`, `chacha20_poly1305_encrypt`, `aes_cbc_hmac_encrypt`,
    `aes_ccm_encrypt`, `aes_eax_encrypt`), cut at the algorithm's tag length; each part has the
    properties of the encryption. A JWE whose plaintext mixes the caller's bytes and a secret
    now signs; `slice` of such a value is still refused.
  - Public keys: `ed25519_public(key)`, `ed448_public(key)`, `ecdsa_public(curve, key)` (P-256,
    P-384, P-521, secp256k1, brainpool P-256 and P-384, SM2) and `rsa_public(form, key)`
    (`n`, `e`, `spki`, `pkcs1`), one-way and a signature each in the budget.
  - New test file `crates/engine/tests/schemes_more.rs` (19 tests): RFC 9421 B.2.6 and B.2.5
    with the caller's headers, the Hawk specification's examples with the caller's content
    type and `$port`, RFC 7516 A.3 and A.1, a JWE of the caller's JSON with a card number
    opened by `rsa` and `aes-gcm`, public keys against RFC 8032, RFC 8037, RFC 9421 B.1.4 and
    RFC 6979, and the attacks: headers outside the contract, repeated, folded or with control
    bytes; components the contract does not list; caller headers meeting secrets; AEAD parts
    of anything but an AEAD call; taint of the parts; rule 9.
- Worked examples of signing and encryption schemes as policies, with no engine change
  (`docs/policy.md`, Worked examples; results in `docs/design.md` section 11): DPoP with `ath`
  and a server nonce, HTTP Message Signatures (ed25519, ecdsa-p256-sha256, rsa-pss-sha512,
  hmac-sha256 over `@method`, `@authority`, `@path`, `@query` and `content-digest`), Hawk,
  ACME with `jwk`, `kid` and chained nonces, JWE (RSA-OAEP-256, ECDH-ES+A128KW, `dir`),
  `private_key_jwt` and `client_secret_jwt`, and a SAML login through forms. New test file
  `crates/engine/tests/schemes.rs` (16 tests) reads the operations from `docs/policy.md` and
  checks them against RFC 9421 B.2.6, RFC 7515 A.1, RFC 8037 A.4, RFC 7518 appendix C and the
  Hawk specification's examples, or a verifier in the test. Gaps found, each a generic
  capability: a template variable for the caller's request headers, a detached AEAD output,
  an Ed25519 public key from its private key, DEFLATE, Exclusive XML Canonicalization, and
  IR `if` for nonce retries.
- Owner controls (`docs/design.md` section 11, part 11): delegation, emergency access and
  credential vending.
  - New module `engine::delegation`: `DeviceKey::delegate` signs a `Delegation` of one record
    to another owner's callers under a narrower policy signed by the same device (same fields
    and item binding, no capture into a field, nothing wider in the summary diff), bound to
    the SHA-256 of the record's signed policy, with the record and log-detail keys HPKE-sealed
    to the node, a lifetime of at most 366 days and a waiting period (0, or 1 hour to 90 days
    for emergency access). `DeviceKey::change_delegation` cancels a request (`cancel`) or ends
    a delegation (`revoke`). `Node::delegate` and `Node::change_delegation`; server endpoints
    `POST /delegate` (`{"delegation", "record"}`) and `POST /delegation/change`. At most 16
    per record and 64 per owner. Delegations survive a restart (sealed under the state key in
    the log), end on the owner's grant revocation, and are not carried in a hand-over.
  - Delegated calls: `Authorization.delegation` (signed, omitted when absent so earlier
    signatures still verify), `CallerKey::sign_delegated_call_at` and
    `call::sign_delegated_call`; log entries name the caller `delegate/caller`, under the
    owner. The first call of an emergency delegation starts the wait and is refused with
    `Error::DelegationWaiting`.
  - Log events `delegate`, `delegated` (under the delegate), `access_request`, `undelegate`
    and `vend`.
  - `Operation.vend` (`policy::vend`): `lifetime_ms` (1 s to 12 h) and `expires` (a capture
    source over HTTPS, or a node-set JSON input member with no connection; format `unix`,
    `unix_ms`, `rfc3339` or `seconds`). HTTPS vending needs fixed requests and a JSON-member
    projection; the node refuses a credential expiring after the lifetime plus 60 s with
    `Error::VendRefused` and returns nothing. Risk flag `vend`; JSON Schema `Vend`.
  - The summary diff counts a longer vend lifetime, a changed vend expiry, and changed open
    `limits` or `protocol` as wider.
  - `client`: `delegate` (to a `VerifiedNode` only), `change_delegation`,
    `sign_delegated_call` (UniFFI and wasm: `delegate`, `changeDelegation`,
    `signDelegatedCall`).
  - Errors `DelegationInvalid`, `DelegationUnknown`, `DelegationWaiting`, `VendRefused`.
  - Fuzz target `owner_controls`; tests in `crates/engine/tests/owner_controls.rs`.
- Protocol connections, rest of part 6 (`docs/design.md` section 7c): `mysql` (TLS before
  anything else, `caching_sha2_password` only, full auth over TLS only, no LOCAL INFILE,
  prepared statements with string parameters), `mqtt` 3.1.1 and 5 over TLS (QoS 0 and 1, no
  retain, will or topic alias, no `+`/`#` in caller topics), `amqp` 0-9-1 over TLS (PLAIN
  only, mandatory publishes with confirms, exchanges, routing keys and queues from the policy);
  SSH SFTP (absolute paths without `.`, `..` or empty segments, REALPATH and LSTAT checked
  before opening, no symlinks followed) and local forwarding (`direct-tcpip`) to destinations
  the policy fixes; typed items `ssh` and `mail`. Tests for P-384/P-521 key exchange, RSA host
  keys and ECDSA, RSA and OpenSSH-format client keys. The `protocol_servers` fuzz target covers
  the new clients.
- Protocol connections (`docs/design.md` section 11, part 6, second half): `open` takes
  `connection` `ssh`, `postgres`, `smtp`, `imap` or `redis`, with `login` (user and one
  credential: `password`, `key`, `token` or keyboard-interactive `answers`; optional
  `mechanism` and PostgreSQL `database`), `host_keys` (SSH, required, 1 to 16 pinned keys)
  and `tls` (SMTP and IMAP: `implicit` or `starttls`). `send` takes `command` (fixed text and
  parameter templates); `return.relay` takes `commands` (named rules, the caller's parameters
  under a whole-match `pattern` and `max_len`, PostgreSQL `columns`) and `mail` (SMTP sender
  and recipient patterns, `max_recipients`, `max_bytes`); an SSH shell runs on a streaming
  call with `frames` and `server`. Callers send `Body::Session` (`{"session": {"destination",
  "commands", "mail"}}`) and get `Output::Session` (`{"kind": "session", "results": [{"name",
  "status", "data", "utf8", "stderr"}], "error"}`). New module `engine::proto`: own
  synchronous clients on ring for SSH (curve25519 and NIST ECDH key exchange with strict
  KEX, AES-GCM and ChaCha20-Poly1305 only, pinned host keys verified before any credential,
  password, public-key signing inside the node and keyboard-interactive, exec and shell,
  rekey refused), PostgreSQL (TLS required, SCRAM-SHA-256 only with the server signature
  verified, extended query protocol with bound parameters), SMTP submission (AUTH PLAIN,
  LOGIN, XOAUTH2, dot-stuffing, bare CR/LF refused), IMAP (LOGIN, AUTHENTICATE PLAIN and
  XOAUTH2, quoted parameters, literals) and Redis (AUTH, RESP bulk-string commands, JSON
  replies). Results are searched for secrets raw and as returned; connections take the
  caller, owner and node slots of open connections and log `use` and `closed`. Transport:
  `Transport::open_plain` and `Transport::open_starttls` (`TlsTransport` implements both).
  Errors `ServerUntrusted` and `AuthRefused` (502 in the server). Summary: forms `login` and
  `command`, flags `password_to_server`, `param_unpinned`, `mail_relay`, `shell_relay`, and
  widening on a new sign-in, host key, TLS mode, command or mail rule. JSON Schema, fuzz
  target `protocol_servers`. MySQL, MQTT and AMQP are not done.
- Browser fills (`docs/design.md` sections 6 and 11, part 8): the `browser` connection kind
  and the `fill` member of `send` (origin, 1 to 16 fields with selector, optional frame
  origin and template, submit, optional `navigate` path, `wait_ms`). The node connects to
  the CDP endpoint the policy fixes through its own transport (the caller never relays
  CDP), picks the one tab at the origin with no other client attached, checks the top
  frame's and the field frame's origin and loader before and after each value, sets each
  value with fixed functions in an isolated world (`engine::cdp::FIND`, `FILL`, `SUBMIT`,
  `CLEAR`; never `Runtime.evaluate`), submits, and blanks the fields when the page stays.
  The caller gets `Output::Fill` (`{"kind": "fill"}` from `/call`): the outcome and the
  final origin. `Error::FillRefused`; limits of 4 MiB per CDP message, 10,000 events and
  2,000 commands, idle/duration (at most 5 minutes)/bytes, an open-connection slot; `use`
  and `closed` log entries. Summary flags `browser_fill` and `frame_origin`, secret form
  `browser_field`; JSON Schema; fuzz target `cdp_message`. New module `engine::cdp` (the
  strict CDP reader). A typed item has no browser operation yet.
- Primitive families of part 9 (`docs/design.md` section 11 and Appendix A, Part 9), checked
  against official vectors where a crate ships them (`crates/engine/tests/fixtures/vectors/README.md`;
  SM2 signing and brainpool by verification only):
  HPKE (RFC 9180; `hpke_seal`, `hpke_open`, `hpke_export`, `hpke_receiver_export`,
  `hpke_public`, `hpke_derive_key`; DHKEM P-256/P-384/P-521/X25519/X448, HKDF-SHA256/384/512,
  AES-128/256-GCM, ChaCha20-Poly1305 and export-only, modes base, psk, auth and auth_psk; a
  PSK of at least 32 bytes); TurboSHAKE128/256 and KT128/256 (RFC 9861; crates `keccak` 0.2,
  `k12` 0.5.1); ML-DSA 44/65/87 (`mldsa_sign`, hedged, and `mldsa_public`; crate `ml-dsa`
  0.1.2); SM2 with SM3 (`sm2_sign`; crate `sm2` 0.14); brainpool P256r1 and P384r1 in
  `ecdsa_sign_prehash` (`bp256`, `bp384` 0.14). Each is classified by the template analysis
  (lengths, algorithms and keys fixed by the policy; exported and decrypted values tainted).
- `tls_exporter(label, context, length)` (RFC 8446 section 7.5, the RFC 9266 binding) in the
  `send` templates of a TLS stream, rendered after the handshake; refused at signing anywhere
  else and at run time over TLS 1.2. `Stream::tls_exporter` in the engine.
- The `udp` connection kind: one datagram per `send` and `receive`, resent after 1, 2 and 4 s,
  10 s per read, 65,507 bytes at most; caller exchanges of one datagram each; reads searched
  for reflected secrets; a `send` template may not be tainted (datagrams are not encrypted).
  Summary flag `plain_datagram`. Engine `Transport::open_datagrams`; `transport::udp`
  (`UdpConnector`, `DatagramStream`, `TlsTransport::datagrams`); `relay::datagram` (the
  `DATAGRAM host:port` request on the egress port and its frames) and the host relay, with
  `--allow udp/host:port` entries; the enclave sends datagrams through the host. Fuzz target
  `relay_datagrams`.
- Node continuity (`docs/design.md` section 11, part 10; section 10): a node hands its state
  to a node of a newer release. New crate `continuity`: successor statements
  (`successor.json`, "release X may hand over to the measurements of release Y") signed in the
  release workflow with Sigstore keyless signing (`cosign sign-blob --new-bundle-format`,
  `id-token: write`) and verified offline in Rust (Fulcio chain to a pinned root, the
  workflow identity, the signature, the `hashedrekord` entry, the Rekor signed entry timestamp
  and the inclusion proof to a signed checkpoint; no maintained pure-Rust verifier of the
  current RustCrypto generation existed); the four-message mutual-attestation protocol and
  its framing over vsock port 5003; test roots for Nitro and Sigstore behind the `testing`
  feature. Engine: `Node::hand_over` and `Node::take_over` (state sealed with HPKE to the
  successor; devices, retired devices, floors and limits always, user keys of grants with
  `allow_successor`), log events `HandOver`, `Continue` and `Carry`, one chain across nodes
  in `ChainVerifier`, errors `HandedOver` and `HandOverInvalid`; `GrantTerms::allow_successor`
  (default on, absent from old signed terms) and `GrantTerms::without_successor`. CLI:
  `credentials hand-over --from-cid --to-cid --statement --bundle`, `credentials grant
  --no-successor`, `credentials verify --next <log>` (JSON `hand_overs`). Enclave: the
  release name compiled in (`CREDENTIALS_RELEASE` from `build/build.sh`, so it is part of the
  measurements) and the hand-over listener. Release workflow: the successor statement, its
  signature and verification, and a check of the compiled Sigstore trust root against
  Sigstore's TUF repository. The compiled trust root
  (`crates/continuity/trust/trusted_root.json`) is empty until it is committed, so every
  statement is refused until then.
- `client`: `verify_successor` and `regrant` with `SuccessorPolicy` (`Automatic`,
  `AskOwner`, `Never`) for a node whose predecessor is gone; `grant_without_successor`; key
  backup (`generate_backup_key`, `wrap_keys`, `unwrap_keys`, format
  `credentials-key-backup/v1`); 6-digit device transfer over SPAKE2 (`start_transfer`,
  `join_transfer`; RustCrypto `spake2` 0.5.0-pre.0, HMAC key confirmation, three wrong codes
  per code, five minutes); errors `successor_refused`, `transfer_refused`, `backup_refused`;
  UniFFI and wasm bindings and the web smoke test.
- Fuzz targets `sigstore_bundle`, `fulcio_certificate`, `successor_statement`,
  `handover_package`, `key_transfer`.

- Connections that stay open (`docs/design.md` section 11, part 6, first half;
  `docs/policy.md`, HTTP versions and gRPC, WebSocket):
  - HTTP/2 by ALPN (`h2`, then `http/1.1`) in the transport: an own synchronous client
    (`transport::h2`) and HPACK decoder with Huffman (`transport::hpack`), strict frame and
    field checks; answers are handed to the engine in HTTP/1.1 form with trailers. `open`
    takes `protocol` (`h2` or `http1`) to pin the version: a server that does not agree fails
    the call before anything is written (`TransportKind::Downgrade`, checked again by the
    engine). Chosen over `h2` 0.4.21, which needs tokio: in a size probe (same release
    profile, Windows host) `h2` + tokio 1.54.1 add 538,112 bytes and `tungstenite` 0.28.0
    196,608 bytes, while this whole part adds 351,232 bytes to `credentials.exe`.
  - Unary gRPC: `send` takes `grpc: true` (needs `protocol: "h2"`, a POST): the body is
    length-prefixed, `te: trailers` set, the one message of the answer unframed. Responses
    carry trailers: `return.response.trailers` and the capture source `trailer`.
  - Streamed responses: `"body": "stream"` hands the body on as it arrives (server-sent
    events, chunked) on `POST /stream` (`Node::relay`); the stream search
    (`reflection::Scrubber`) holds back one less than the longest searched form of a secret
    (×6 for JSON escapes), so a secret split across chunks is found before any byte of it
    leaves.
  - The `websocket` connection: a handshake `send` (the node sets the WebSocket fields and
    checks the answer: 101, accept value, no extension), message `send`s with `frame` and a
    template (first-message authentication), `receive` of the next message, and
    `return.relay` with `frames` (per kind, a closed JSON schema or a pattern, and a template)
    and `server`. Caller frames are signed per call and in sequence
    (`CallerKey::sign_frame`); a frame outside the rules closes the connection. Server
    messages go back only with `server: true`, each searched with the tail of the one before.
  - Limits per open connection (`limits`: idle, duration, bytes) and at most 4 open per caller,
    16 per owner, 256 per node (`Error::StreamsFull`, HTTP 429); a log entry `closed` with
    the reason, status and the messages and bytes each way. Errors `FrameRefused`,
    `TransportKind::Protocol`.
  - The server's `/stream` endpoint speaks a framed protocol
    (`application/vnd.credentials.stream`, `server::stream`); open connections have their own
    pool (16 by default). Everything stays synchronous: one thread per open connection. The
    Nitro host relay needs no change.
  - Summaries flag `frames_unpinned` and `server_frames`; the JSON Schema covers the new
    members. Fuzz targets `h2_response` (HTTP/2 framing and HPACK), `websocket_frames` and
    `stream_scrubber`.
- Trusted code sandbox (`docs/design.md` section 11, part 7; `docs/sandbox.md`): the IR step
  `run {module, entry, inputs, into}` runs a WebAssembly module fetched from the
  destination's own origin (`{"url": ..., "sha256": ...}`, fetched as a logged `GET` over the
  operation's connection, pin checked) or a reviewed library compiled into the node
  (`{"library": "lenprefix8"}`). Its output may only go into a request the policy fixes to
  that origin; signing refuses `return`, the caller's request, another destination, a field,
  a second origin, and temporary values captured from a response to a request that carried
  it. New crate `sandbox` (wasmi 1.1.0, chosen over wasmtime 51 and wasmi 2.0.3 by
  measurement): fuel (10⁹), 64 MiB memory, 64 KiB output, four host functions, no WASI,
  clock or randomness. Errors `ModuleRefused` and `Sandbox`. Summaries list `runs` and a
  `module_input` form, and flag `run_unpinned`. Fuzz target `sandbox_module`. JavaScript:
  boa compiled to WebAssembly measured inside the sandbox; shipping plan in
  `docs/sandbox.md`.
- Operations that wait (`docs/design.md` section 11, part 5; `docs/policy.md`, Operations
  that wait): an `await` step parks an operation in the node's memory under a random id
  (at most 8 per owner, 256 and 128 MiB in all, five minutes, dropped on revoke and restart)
  and the caller gets `Output::Pending` (`challenge {id, challenge, hint, expires_ms}` or
  `approval_required {id, summary}`); it resumes with `Body::Resume {id}`, as the same
  caller on the same record and operation only.
  - Code challenges (`sms`, `email`, `app`, `3ds`): the owner's device answers with
    `DeviceKey::answer_challenge`, signed and sealed to the node (`engine::session`,
    `Node::answer`, `POST /answer`); the code becomes a secret temporary value and is never
    logged.
  - External challenges: the node polls a fixed status request of the policy when the caller
    resumes, no sooner than `every_ms`, and goes on, fails or keeps waiting by its
    conditions.
  - Approvals at run time: an operation with `"approval": true`, every use of a `card`, and a
    payment no spending limit covers or above one wait before anything is sent for an
    `Approval` over the node-built summary (`Node::approve`, `POST /approve`).
  - Payments and spending limits (section 8b): `"payment"` reads an amount only from a
    required, bounded query parameter or JSON input member, or the policy; owner-signed
    `SpendingLimits` (`engine::limits`, `DeviceKey::sign_limits`, `Node::set_limits`,
    `POST /limits`) per currency and merchant, per payment, rolling day and 30 days, counted
    under one lock and restored from sealed log entries.
  - Sessions: a secret field with `"session": {lifetime_ms, expires, renew}`; the node writes
    the expiry when it captures the session and, when it lapsed, runs the renewal operation
    first or refuses with `session_expired` (`renew: owner`), after which the device seals a
    new one with `Record::update`.
  - Log events `answer`, `approve`, `limits` and `spend`; errors `Pending`, `ParkedUnknown`,
    `ParkedFull` (HTTP 429), `ChallengeFailed`, `AnswerInvalid`, `SessionExpired`,
    `LimitsInvalid`.
  - `client` crate (UniFFI and wasm): `answer_challenge`, `sign_resume_call`, `sign_limits`,
    `update_record`; `approve` and `approval_hash` also take the pending reply.
  - Fuzz targets `decimal_amount` and `owner_waits`.
- Typed items (`docs/design.md` section 11, part 3): a policy may bind its record to a kind
  (`"item": {"kind": ..., "pins": {...}, "signoff": [...]}`), a schema of secret, masked
  and public fields with checks and a shape of what its policies may do. Twelve reviewed
  kinds ship in the node (`card`, `login`, `oauth`, `identity`, `totp`, `ssh`, `database`,
  `ftp`, `mail`, `queue`, `vpn`, `api`); custom kinds are signed by the owner's device
  (`DeviceKey::sign_kind`) and checked like policies. The node re-derives the shape on every
  signature check and refuses a wider policy. Checks: Luhn, expiry (by the node's clock on
  every use), security code length per IIN brand, exact origins, hosts, integers, lengths,
  patterns, lists, e-mail addresses, dates, base32 seeds of at least 128 bits, base64 keys,
  SSH host keys, and owner sign-offs for plain-text connections.
- `describe` (operation `:describe`, body `{"kind": "describe"}`): the public fields and
  the node-computed masked projections of a typed record, never a secret field; any listed
  caller, logged as a `describe` entry.
- `engine::policy::summarize(policy, previous)`: per secret, where it can go and in what
  form; per operation, requests, projections and inputs; risk flags (`outside_origin`,
  `wildcard`, `plain_http`, `plain_signoff`, `raw_input`, `derive_reversible`, `relay`,
  `relay_broad`, `response_all`, `query_any`, `encoded_percent`, `override_params`,
  `client_certificate`, `wider`, `new_destination`) and the diff against a previous version.
- `crates/engine/policy.schema.json` (`engine::policy::JSON_SCHEMA`): a JSON Schema (draft
  2020-12) of the policy IR, item bindings and kinds, tested against every policy of the
  README, its translations, `docs/policy.md`, the converted fixtures and the reviewed kinds.
- Approvals (`engine::approval`): the format of the node-built `ApprovalSummary`, its
  SHA-256, the owner device's `Approval` over it and its verification. Parking an operation
  until the approval arrives is part 5.
- `client` crate: `summarize`, `policy_json_schema`, `item_kinds`, `sign_kind`,
  `sign_describe_call`, `approval_hash`, `approve` (UniFFI and wasm); `seal_record` checks a
  typed record's values against its kind by the device's clock.
- Fuzz target `kind_schema`; `policy_json` also summarizes.

- `compute` steps: a template rendered into a name later steps read, with exactly the
  properties of its template in the analysis.
- Input schemas for operations with no connection: `raw` (length, pattern), `json` (closed:
  types, fixed values, allowed values, pattern, decimal bounds, members the node sets from its
  clock; duplicate keys refused, the checked value re-serialized) and `rlp` (closed,
  canonical, optional prefix, fixed and allowed items, integer bounds).
- `credentials policy upgrade OLD --out NEW`, and `upgrade_policy` in the `client` crate.
- Fuzz targets `policy_upgrade`, `caller_request` and `input_schema`.
- Template functions, the first group of the primitives of `docs/design.md` section 8d, each
  with its taint rule (`docs/policy.md`) and threat-model rows:
  - structure: `slice(value, start, length)`, `between(value, start, end)` (empty delimiters
    mean the ends), `add(a, b)` on signed 64-bit decimals, `json_set_number(object, key,
    integer)`, and the fixed-width integer encoders `u8`, `be64`, `le16`, `le32`, `le64` next
    to `be16` and `be32`; `random(n)`;
  - hashes and MACs: `md4`, `sha384`, `sha512_256`, `hmac_md5`, `hmac_sha384`, and
    `pbkdf2(hash, password, salt, rounds[, length])` for SHA-1, -256, -384 and -512
    (`pbkdf2_sha256` stays);
  - signatures: `rsa_sign_pkcs1(hash, key, msg)` (SHA-1, -256, -384, -512),
    `rsa_sign_pss(hash, key, msg)` (SHA-256, -384, -512), `p521_sign` (`rsa_sign_*_sha256`
    stay);
  - key agreement: `ecdh(curve, peer[, private])` and `ecdh_public(curve)` on P-256, P-384,
    P-521 and X25519, with one ephemeral key pair per curve and operation that never leaves
    the node, or a static private key from a field;
  - encryption: `chacha20_poly1305_encrypt`, AES-192 keys in `aes_gcm_encrypt`, and
    `rsa_encrypt_oaep(hash, public_key, msg)` / `rsa_encrypt_pkcs1(public_key, msg)`, whose
    public key may not be chosen by the caller.
- New analysis rules: a secret and a chosen value may not meet in `slice`, `between`, `add`
  or `json_set_number`; hash and curve names must be fixed by the policy; an RSA encryption
  key may not come from request variables or `$input`; every `ecdh` result is a secret that
  a plain hash does not clean.
- Template functions, the second group of section 8d, whole families, each with its taint
  rule (`docs/policy.md`), threat-model rows and an exfiltration test:
  - hashes: `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `shake128(msg, length)`,
    `shake256(msg, length)`;
  - KDFs over SHA-256, -384 and -512: `hkdf(hash, ikm, salt, info, length)`,
    `hkdf_expand(hash, prk, info, length)`, `concat_kdf(hash, z, other_info, length)`
    (SP 800-56A, as JOSE and COSE ECDH-ES use it), `kbkdf_counter(hash, key, fixed_input,
    length)` (SP 800-108 counter mode over HMAC);
  - Kerberos: `nfold(value, bits)` and `kerberos_dk(key, constant)` (RFC 3961);
  - AES modes and MACs: `aes_cbc_hmac_encrypt` (RFC 7518 5.2), `aes_ccm_encrypt` (any nonce
    length 7-13 and even tag 4-16), `aes_eax_encrypt`, `aes_cts_encrypt` (CBC-CS3, RFC 3962),
    `aes_cmac` (RFC 4493), `aes_cbc_mac`; key wrapping `aes_kw_wrap` (RFC 3394) and
    `aes_kwp_wrap` (RFC 5649);
  - signatures: `ed448_sign(key, msg[, context])`, `ecdsa_sign_prehash(curve, key, digest)`
    on P-256, P-384, P-521 and secp256k1, `dsa_sign` / `dsa_sign_der(hash, key, msg)`
    (RFC 6979 nonces);
  - key agreement: X448 in `ecdh` and `ecdh_public`;
  - CBOR in its deterministic form (RFC 8949 4.2.1): `cbor_int`, `cbor_bytes`, `cbor_text`,
    `cbor_array`, `cbor_map`, `cbor_tag`, enough for `COSE_Sign1`, `COSE_Mac0`,
    `COSE_Encrypt0` and their `Sig_structure`, `MAC_structure` and `Enc_structure`.
- New analysis rules: a key derived from a secret is a secret and not controlled (rule 8); no
  length argument may depend on a secret (rule 9); block-cipher MACs are one-way only under a
  secret key; in `cbor_map` a secret key may not meet a chosen key.
- Known-answer tests from FIPS 202, RFC 3394, 3610, 3961, 3962, 4493, 5649, 5869, 6979,
  7518, 7748, 8009, 8032, 8949, 9052, NIST SP 800-38A/B/C, NIST CAVP (KBKDF), Wycheproof
  (HKDF-SHA-384/512) and the EAX paper (`engine/src/vectors_families.rs`); the in-house CCM
  matches the `ccm` crate on every nonce and tag length.
- Dependencies: `aes-kw` 0.3, `cmac` 0.8, `eax` 0.6, `cts` 0.7, `shake` 0.1, `dsa` 0.7
  (`hazmat`, for signing), `ed448-goldilocks` 0.14.0-pre.15 and `x448` 0.14.0-pre.12
  (pre-releases, pinned exactly); `ccm` 0.6 for tests only.
- Capture sources `html` (one compound selector over the `html5gum` tokenizer; an attribute
  or the element's text) and `regex` (the `regex` crate, linear time, a chosen group), at most
  2 MiB read, 256-byte selectors and patterns; `regex` also reads stream bytes. Fuzz targets
  `html_capture` and `regex_capture`.
- Known-answer tests from RFC 1320, 2202, 4231, 6070, 6979, 7748, 7914, 8439, FIPS 180, the
  GCM specification, NIST CAVP (ECC CDH) and the PKCS #1 v2.1 vectors (`engine/src/vectors.rs`).
- Dependencies: `rsa` 0.10, `p521` 0.14, `md4` 0.11, `x25519-dalek` 3 (already in the tree
  through `hpke`), `regex` 1 (no Unicode tables), `html5gum` 0.9; the `ecdh` features of
  `p256` and `p384`.

- `client` crate: the app side for iOS, Android and the web, one Rust implementation over
  `engine` and `attest` with a string and bytes API: device, user and caller keys as base64url
  (`generate_key`, `import_key`, `public_key`); `nonce` and `verify_node` /
  `verify_attestation_reply`, which check the Nitro attestation and the identity binding and
  make the only `VerifiedNode`; `grant`, which takes a `VerifiedNode` verified within five
  minutes from a nonce used once; `revoke`, `endorse_device`, `retire_device`,
  `sign_policy`, `seal_record`, `rewrap_record`, `pin_record`, `sign_call`,
  `sign_derive_call`. One error type with stable codes. Swift and Kotlin bindings through
  UniFFI 0.32 (generated by the workspace binary `uniffibindgen`), JavaScript through
  wasm-bindgen (time from `Date.now()`, randomness from `crypto.getRandomValues`).
  `build/client.sh` builds the web package (with a Node smoke test), the Android libraries
  (arm64-v8a, x86_64) and an XCFramework (device and simulator); CI builds all three, and
  releases attach `client-wasm-<tag>.tgz`, `client-android-<tag>.zip` and
  `client-ios-<tag>.xcframework.zip` with a `client` SBOM. The threat model now covers grants
  from web pages and app key storage.
- AWS Nitro Enclaves. The `enclave` crate and program: a fresh node key at every boot (after
  checking that the kernel draws randomness from the NSM), the HTTP API of `credentials serve`
  on vsock, and `GET /attestation?nonce=` with an NSM attestation document whose `user_data`
  is `NodeIdentity::report_data()`. Egress and the log go through the parent instance:
  `credentials host` forwards HTTP to the enclave, relays `CONNECT host:port` tunnels (TLS
  stays in the enclave; optional `--allow` list) and writes one synced JSONL log per node key,
  confirming each entry only after `sync_data`.
- Reproducible enclave image: `build/build.sh` (static musl build in a Rust image pinned by
  digest, `SOURCE_DATE_EPOCH`, path remapping, `--locked`; `nitro-cli` from a pinned Amazon
  Linux image) writes `enclave.eif` and `measurements.json` (release, commit, PCR0/1/2, input
  digests); `build/reproduce.sh` builds twice and fails if the measurements differ. CI runs it
  on changes to the enclave and its build; releases attach `enclave.eif` and
  `measurements.json`, include them in `SHA256SUMS` and the provenance attestation, and print
  the measurements in the notes.
- `server` crate: the HTTP server of a node, shared by `credentials serve` and the enclave,
  over any connection (`Connection`), log sink (`Sink`) and transport, with `Hooks` for
  checkpoints and extra endpoints; the `relay` crate holds the vsock protocol between an
  enclave and its host.
- `transport`: `TlsTransport` runs over any byte stream a `Connector` opens (`TcpConnector` by
  default; `TlsTransport::connector`).

- `transport` crate: a TLS transport on rustls (ring provider, Mozilla roots, client
  certificates, connect/read/total deadlines, size limits, erasing buffers), tests against
  local TLS servers with fixed test certificates, and the `github_user` example.
- Sealed grants: a device signs the terms of a grant and seals them with the user key to the
  node (HPKE, RFC 9180). Nodes accept grants only from devices they know for the owner
  (first use trusted) and refuse replays. `NodeIdentity::report_data()` for TEE quotes.
- Signed revocations (`DeviceKey::revoke`).
- Pins in grants; records the owner never pinned are refused (`Error::RecordUnpinned`).
- Use details (host, path, body hash) in the log are sealed to the owner's user key;
  `log::open_detail` and `credentials verify --owner <owner> --user-key <file>` read them.
- `guessable` fields: derivations may not return a check for guesses of a PIN or password.
- P-384 signing with RustCrypto `p384` (erased on drop; raw 48-byte keys accepted).
- Documentation: README in English with diagrams, policy reference, threat model, security
  policy, contributing guide.
- CI: tests on Linux, macOS and Windows and on the MSRV (1.87), docs with warnings denied,
  `cargo deny check` with licenses, a reproducible-build check, fuzzing, caching and
  cancellation of superseded runs.
- `cli` crate: the `credentials` tool. `keygen`, `policy check|sign`, `seal`, `grant`, `revoke`,
  `device`, `pin`, `call`, `node identity`, and `serve`, which runs a node over HTTP with a
  durable JSONL log and a signed head.
- `credentials verify`: flags in any order, `--json` summary, `--help`, documented exit codes
  (0 valid, 1 invalid, 2 usage or I/O), `--head` checked against `--owner` files, and a clear
  message when an entry belongs to another owner. A first entry whose signature fails asks
  whether the key is the node's log key; checkpoint times are printed as RFC 3339 UTC next
  to milliseconds; with `--owner --head`, a checkpoint past the owner's last entry is warned
  about (`"owner_tail_unchecked"` in `--json`). `log::owner_entries` picks one owner's entries.
- `credentials`: documented exit codes (0 ok, 1 other, 2 usage, 3 refused by the node, 4 rate
  limited, 5 connection, transport, log or I/O failure); `policy check` takes a signed policy
  too (`--device <key>` checks its signature); a signed and an unsigned policy given in each
  other's place are named as such; `seal` names the field and rule a value breaks (`field
  `key` is empty`); `grant` without `--pin` warns that calls are refused until a record is
  pinned; a key file readable by others is warned about on Unix.
- `credentials serve`: connections are capped (`--max-connections`, 503 beyond), each request
  must arrive within 10 seconds, a body larger than `--max-body` (4 MiB by default) is refused
  before it is read, and reads of `/identity` and `/checkpoint` never wait behind acts. The
  checkpoint file is written only when the log grew.
- Signed calls in one value: `call::SignedCall`, `CallerKey::sign_call`, `Node::run` and
  `call::Output`; requests, responses and exchanges serialize to JSON.
- Policy builders in `build` (`Policy::new().with_field(..)`, `Operation::http(..)`, `Step`,
  `Exchange`, `Source`, `Capture`).
- `GrantTerms::new(owner, Duration)`, `GrantTerms::pin(&record)`, `node::now_ms()`;
  `UserKey::to_b64` / `from_b64`.
- Device retirement: `DeviceKey::retire`, `Node::retire_device`, `Event::Retire`.
- `Node::restore_anchored`: restart from a log and a checkpoint kept outside the operator's
  reach; a cut log is refused.
- Examples: `oauth_refresh`, `aws_sigv4`, `jwt_derive`, `imap_stream`, `node_restore`.
- Tests that the README quick start matches the example, and an end-to-end doctest.
- Fuzz targets (`template_parse`, `policy_json`, `log_entry`), run in CI.
- Release workflow: binaries for Linux, macOS and Windows, `SHA256SUMS`, CycloneDX SBOM and
  build provenance; Scorecard; Dependabot groups; CODEOWNERS; Code of Conduct; DCO sign-off.
- READMEs in Korean, Simplified Chinese and Japanese (`docs/i18n`).
- `attest` crate: verifies AWS Nitro Enclaves attestation documents (COSE_Sign1 with ES384,
  certificate chain to the pinned AWS Nitro Enclaves Root-G1 at the document's time, nonce,
  PCR0–2 against accepted `measurements.json` entries, debug enclaves refused) and binds them
  to `NodeIdentity::report_data()`. Tested on real documents of a production and a debug
  enclave.
- `credentials attest --document <file|-> --nonce <b64url> --measurements <file>
  [--identity <file>]` prints the verified release, PCRs and time; a refused document exits 3.
- `credentials grant --attestation <file> --nonce <b64url> --measurements <file>`: the grant is
  sealed only if the document verifies and vouches for the node identity. Without
  `--attestation`, `grant` warns.

### Changed

- Every use of a `card` item waits for the owner's approval (`"approval": true` in the kind's
  shape); the `login` kind has a public `session_expires` field. `Step::Await`,
  `Operation::payment`, `Operation::approval`, `FieldSpec::session` and `Shape::approval` are
  new members; `call::Output::Pending`, `call::Body::Resume`, `caller::Payload::Resume` are
  new variants. `Node::http`, `stream` and `derive` fail with `Error::Pending` where `run`
  returns the pending reply.
- `Policy` has an optional first member `item`; a policy without it signs and verifies as
  before. `call::Body::Describe`, `call::Output::Describe`, `caller::Payload::Describe`,
  `log::Event::Describe` and the errors `KindInvalid`, `KindSignature`, `FieldInvalid`,
  `ApprovalInvalid` and `NotAnItem` are new variants. `Record::seal` checks a typed record's
  values against its kind (without a clock); `Node` checks them with its clock on every use.
- **Policy format (breaking).** Operations are one step language over a connection instead of
  the kinds `http`, `stream` and `derive`: `open` (`https`, `tls`, or none), `send`,
  `receive`, `compute`, `return`; `repeat` and `if` are parsed and refused for now. The policy
  signing domain is `policy/v4`: every policy must be converted and **signed again**.
  `credentials policy upgrade` and `engine::policy::legacy::upgrade_json` convert the old
  format and print what they narrowed. In Rust, `Operation::https`, `Operation::tls`,
  `Operation::local` and `Operation::then` with `Send`, `Receive`, `Return` and
  `CallerRequest` replace `Operation::http`, `Operation::stream`, `Step` and `Exchange`.
- A caller's HTTPS request is checked against a contract on its `send`: methods, path
  templates matched exactly (`*`, `**`, whole-segment `{name}` placeholders) instead of path
  prefixes, headers, and query parameters with their values.
- An HTTPS operation returns the status and only the headers and JSON members its `return`
  lists (`"body": "all"` for the whole body); before, the whole response went back.
- A stream relays the caller's exchanges only when its `return` lists patterns their sends
  match whole; before, any exchange ran.
- An operation that reads `$input` declares an `input` schema; new error
  `Error::InputInvalid { rule }` (a caller error, HTTP 400 from the server).
- Policy errors that name a step use its index in `steps` (`operations[0].steps[2].capture[0]`)
  and path errors name the rule that failed (`path holds an encoded /, \ or .`).
- `crates/engine/src/vectors.rs` is formatted (the base branch failed `cargo fmt --check`).
- The render budget of 32 signatures per operation also counts key agreements.
- `crates/engine/src/primitives.rs` is stored with LF line endings, like every other file.

- `CHANGELOG.md` moved to `docs/`, `deny.toml` to `.github/` (`cargo deny --config .github/deny.toml check`).
- Fuzz targets moved from `fuzz/` to `crates/fuzz/`.
- Releases attach one CycloneDX SBOM per shipped artifact instead of one per crate:
  `credentials-<tag>.cdx.json` for the `credentials` binary (every target's dependencies) and
  `enclave-<tag>.cdx.json` for the enclave program (`x86_64-unknown-linux-musl`), both in
  `SHA256SUMS` and the provenance attestation.
- Crate layout: the vsock wire between an enclave and its host (ports, the `CONNECT` tunnel,
  the log protocol, `RelaySink`, vsock) moved from `server::relay` to the new `relay` crate,
  and `credentials host` to the new `host` library crate (`host::run`, its own error type);
  the `credentials` binary only parses the command line and keeps its exit codes. The JSONL
  log file and its checkpoint (`FileSink`, `HeadFile`, `head_path`) moved from the `cli`
  crate to `server::logfile`. `host` depends on neither `attest`, `verify` nor `cli`.
- Crate directories and package names are `engine`, `transport`, `verify` and `cli`. The log
  verifier is the `credentials verify` subcommand (the `verify` crate is its library); only the
  `credentials` binary ships. The packages are not published to crates.io.
- `credentials serve` runs on its own small HTTP/1.1 server instead of `tiny_http`.
- `Endorsement` carries the node and issue time (domain `endorse/v2`); `Event::Device` carries
  the issue time.
- Errors carry context: `FieldMissing { field }`, `DestinationDenied { host }`,
  `OperationUnknown { name }`, `CallerDenied { caller, operation }`, `MethodDenied { method }`,
  `PathDenied { path }`, `LogBehindAnchor { len, anchor }`, `SignatureInvalid`; policy errors
  name the unknown name. `Outcome` is `#[must_use]`.
- `CONTRIBUTING.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md` moved to `.github/`.
- `Node::grant` takes a `SealedGrant`; `Node::revoke` takes a `Revocation`.
- Log events: `Grant` carries the issue time and pins; `Revoke` carries the issue time and
  device; `Use`, `Stream` and `Derive` carry a `SealedDetail`.

### Security

- **A panic inside the sandbox's interpreter no longer reaches the node.** The fuzz target
  `sandbox_script` found a 2-byte script (`0a b0`, not UTF-8) that panics wasmi 1.1.0
  (`unreachable` in its executor) through the JavaScript engine module. Every call into wasmi
  now runs under `catch_unwind`: a panic ends the run with the new error `Interpreter`, and
  the memory is still wiped. `run_script` refuses a source that is not UTF-8 before the
  engine sees it (#95).
- **The sandbox no longer resumes a run after it ran out of fuel.** Resuming a wasmi 1.1.0
  call after `OutOfFuel` can land on an instruction parameter instead of an instruction:
  a panic in a debug build, undefined behaviour (a segfault) in a release build, so
  `catch_unwind` alone does not cover it. The entry now gets all its fuel at once and runs
  as one call; the wall clock is checked at every host call instead of between slices, and
  `sandbox::FUEL_SLICE` is removed. A run that runs out of fuel after its time was up fails
  with `Time`, as a run that finishes late does. wasmi is built with `extra-checks`, which turns its
  unchecked instruction decoding into a panic in release too; across 4 release runs each of
  the JavaScript benchmark, its cost was below the run-to-run spread (#95).
- The sandbox now wipes a module's memory when a run fails (trap, fuel, time, output limit,
  a start function that traps, an entry it refuses), not only when it succeeds: the memory
  handle is kept outside the run, by the instance or by the first host call, so a lost
  instance no longer leaves inputs and derived values in freed memory for binaries without
  the zeroing allocator (tested on each path).
- An SSH write that waited for the server's window dropped what the server sent meanwhile:
  shell output, error output, the exit status (a failed command could end as a success) and
  a forwarded channel, which was then never accepted or refused. These events are now kept
  in order, at most 2 MiB of output and 256 events, and every read takes them before it
  reads the connection again; closing a channel refuses a forwarded channel still waiting
  (tested with a server that sends output and `exit-status` while the window is 0).
- A panic while the node's state is locked halts the node for good, as a failed log append
  halts it, instead of serving on from a half-updated state (sequence numbers, floors, rate
  counts): every act, checkpoint and reconcile fails with the new `Error::StateLost` (503 in
  the server), `Node::is_halted` and the new `Node::is_state_lost` are true, live loops end,
  and `Node::with_sink` still reads the sink so the node can restart from its log. A
  poisoned lock of the connection counts refuses new connections (`StateLost`); a poisoned
  transport pool lends no transport; a checkpoint hook that panicked halts the server's acts
  (503), since what it stored is unknown.
- Numbers on the wire and in templates are ASCII digits only (`engine::encoding::digits`,
  `signed_digits`): the node's own `Content-Length` (server), a response's `Content-Length`
  (HTTP/1.1 and HTTP/2) and the template functions `u8`, `be16` ... `le64`, `add` and `slice`
  no longer take a leading `+` (RFC 9110 `1*DIGIT`), which a front proxy could read
  differently.

- Spending limits carried in a hand-over package are checked rule by rule
  (`LimitRule::fault`) and the package is refused when one is not valid; a rule whose bound
  is no amount (`"1e9"`, `"025"`) now reads as exceeded, so the payment waits for approval
  (before, the bound was skipped and the payment came back within the limits). A node whose
  clock reads before 1970 takes no act (`Error::ClockBeforeEpoch`, through the new
  `Clock::checked_now_ms`) instead of reading the time as 0, which left every expiry in the
  future; a node started with such a clock refuses what was granted before its start until
  it restarts.

- An approved operation on a protocol connection (SSH and SFTP, PostgreSQL, MySQL, Redis,
  SMTP, IMAP, POP3, FTP, MQTT, AMQP 0-9-1 and 1.0) never went on: the caller's commands and
  messages were not kept with the waiting operation, so the resume failed
  (`operation_unknown`, or `policy_invalid` on IMAP; measured: 13 of 13 approved sessions
  failed, now 13 of 13 return what the same call returns unapproved, with nothing opened
  before the approval). They are now kept as signed, counted against the 128 MiB of waiting
  values, and wiped (as every kept caller payload now is) when the operation goes on, lapses
  or is dropped. A resumed protocol or browser operation now takes a connection slot, as
  the call that started it did. UDP exchanges and derivation input were already kept
  (tested).
- The delimiters of a caller's TLS exchanges were an oracle on a secret the server echoes:
  with `until` set to the bytes before the secret plus a guessed byte, the read ended there
  only when the guess was right (measured: 3 of 3 bytes learned). A match is now taken only
  where no occurrence of a secret, in any searched form, overlaps it; the reader looks ahead
  after a match as far as an overlapping occurrence could reach and keeps the bytes read ahead,
  in order, for the next read (`reflection::delimit`; measured after: 0 bytes). A reflection in
  any read of a call (or in a read that fails) now returns no read of the call; before, the
  reads before it went back with the error. Transports must implement `Stream::read_some` for
  TLS exchanges with delimiters. The residual timing channel is in `docs/threat-model.md`.
- The reflection search finds more encoded forms of a secret field: base64 in both alphabets
  at the three alignments inside a longer value (the characters its own bits decide), the raw
  value in the percent-decoded response (`%XX` in either case, `+` as a space and as itself,
  reserved characters left unencoded) and hex in any mix of cases, in whole responses and in
  the stream search. Before, base64 matched only a value encoded alone, percent only one
  encoder's uppercase form and hex only all-lower or all-upper. `reflection::forms` lists the
  lowercase percent and mixed-case hex forms too; `Scrubber::for_secret` searches like for a
  secret field.

- Rule 10 of the template analysis: the input of `deflate`, `zlib_deflate` and
  `gzip_deflate` may not be tainted (a compressed length tells how the input repeats itself:
  CRIME, BREACH). `inflate`, `zlib_inflate`, `gzip_inflate` and `xml_escape` refuse a secret
  mixed with chosen bytes (rule 1); `xml_c14n` joins rule 2 (no secret and chosen value in any
  argument), its algorithm rule 6 and its prefix list rule 9.
- XML: a document type declaration is refused, so no external entity and no entity expansion
  can occur; nesting, node count, input and output size are capped.
- A secret can no longer set an output's length or a cut: `random(n)`, the length of
  `pbkdf2_sha256` and `pbkdf2`, the start and length of `slice`, the delimiters of `between`
  and the text `replace` looks for are refused when tainted, as the new key-derivation lengths
  are; before, `len(random(key))` returned a number taken from the secret.
- Closes the gaps of the policy audit; each has a regression test in
  `crates/engine/tests/audit_bounds.rs` that shows the attack refused before the log:
  - a caller could add query parameters to a signed request (another action for the same
    signature) and read whatever the server returned: query allow-list per name and value,
    and response projection;
  - a caller could send a query name the policy injects, first: refused;
  - `..;`, `%252e%252e` and `..%3b` passed the path check: segments are checked as sent,
    without `;` parameters, after one and two decodings, and `%25` is refused unless the
    contract allows it;
  - `_method` in the query or body could turn a POST into a DELETE: refused unless the
    contract allows it;
  - a caller could place a path parameter (a secret) in its own query: placeholders are whole
    segments of signed templates;
  - a derivation signed any input: input schemas;
  - a stream relayed any command after the login: relay patterns.
- `crates/transport/examples/aws_sigv4.rs` claimed the caller could only send
  `GET https://sts.amazonaws.com/`, but the caller could pick the action; the example now pins
  `Action` and `Version` and projects the response. `docs/threat-model.md` claimed dot
  segments and encoded separators were refused; `..;` and double encoding were not.
- Template analysis: encryption under a secret field hides only the key; a secret in its
  message, nonce or data stays tainted. Hashes and MACs of a secret no longer count as secret
  keys. A `guessable` field may reach a derivation output only through `len`.
- A node refuses grants, endorsements, retirements and caller signatures issued before it
  started, so a saved grant or call does not work again after a restart.
- The replay cache has a quota per caller (100,000 per window) and refuses times more than
  60 seconds ahead; one caller can no longer fill it for everyone.
- Endorsements name the node and the issue time; a retired device cannot add itself back.
- `Node::revoke` writes the log before it changes state.
- Policy JSON refuses unknown keys next to every tag, including variants without fields.
- The transport erases bytes read past a delimiter.
- A plain hash of a secret alone stays tainted (it equals the key of a long HMAC key or an
  Ed25519 seed); a secret and a chosen value may not meet across the number arguments of
  `time`, `totp` and `pbkdf2_sha256`.
- Once an owner has a device, a new device joins only through an endorsement; the user key
  alone no longer lets a retired device back in under a fresh key.
- A clock set back behind the node's start no longer re-opens what was signed before a
  restart.
- Grant, pin and generation errors are given only after the policy and the caller's
  signature verify; a call of the wrong kind spends no nonce or rate limit.
- The number of owners on a node is capped (`MAX_OWNERS`).

## Earlier

- Callers with per-call signatures, replay protection and rate limits; path prefixes and header
  allowlists; strict response parsing; reflection search over encodings; template taint and
  oracle analysis; render budgets; record generations and pins; per-owner log chains and
  signed checkpoints; restore and reconcile; a thread-safe node.
