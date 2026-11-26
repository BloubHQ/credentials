# client

The app side of the credentials engine, for iOS, Android and the web. One Rust implementation
over [`engine`](../engine) and [`attest`](../attest), bound to Swift and Kotlin with
[UniFFI](https://mozilla.github.io/uniffi-rs/) and to JavaScript with
[wasm-bindgen](https://wasm-bindgen.github.io/wasm-bindgen/).

It is what an owner's app runs on the device: it makes and keeps keys, checks the Nitro
attestation of a node, seals grants only to a node it checked, signs revocations, device
changes, policies and pins, seals records, and signs calls for apps that use a record. It does
no networking: the app sends the JSON it returns to the node server (`POST /grant`, `/revoke`,
`/pin`, `/device/add`, `/device/retire`, `/call`) and hands back what the node answers
(`GET /attestation?nonce=`).

The API is strings and bytes: keys are 32 bytes as unpadded base64url (the format of the key
files of the `credentials` CLI, so keys move between the two), documents are the JSON the
node server takes.

## API

Rust names; Swift and Kotlin use the same names in camel case (`verifyNode`), JavaScript too
(see [JavaScript](#javascript)).

| Function | Returns | What it does |
| --- | --- | --- |
| `generate_key(kind: KeyKind)` | `String` | A new device, user or caller key |
| `import_key(kind, text)` | `String` | Checks a key from elsewhere (a CLI key file, a backup) and returns it canonical |
| `public_key(kind, secret)` | `String` | The public key of a device or caller key |
| `nonce()` | `Nonce` | 32 random bytes for one attestation request, good once within five minutes |
| `Nonce::to_b64()`, `Nonce::bytes()` | `String`, bytes | The nonce to send: `GET /attestation?nonce=<to_b64()>` |
| `verify_node(document, nonce, measurements_json, identity_json)` | `VerifiedNode` | Verifies the attestation document of the node and that it vouches for the identity |
| `verify_attestation_reply(reply_json, nonce, measurements_json)` | `VerifiedNode` | The same, on the `{identity, document}` answer of `GET /attestation` |
| `VerifiedNode::release()`, `module_id()`, `timestamp_ms()`, `verified_ms()`, `pcr(index)`, `identity_json()`, `log_key()` | | What the verified document states |
| `grant(device_key, user_key, node: VerifiedNode, owner, valid_for_secs, pins_json)` | sealed grant JSON | Grants the node the user key; pins each record given. The node may hand the grant over to a node of a newer release signed by the release workflow |
| `grant_without_successor(...)` (same arguments) | sealed grant JSON | The same, but the grant never moves to a successor node |
| `verify_successor(document, nonce, statement, bundle, previous_release, identity_json, trusted_root_json?)` | `VerifiedNode` | When the node the owner granted to is gone: verifies a node of a newer release against the signed successor statement of `previous_release` (`successor.json`, `successor.sigstore.json`) |
| `VerifiedNode::successor_of()` | `String?` | The release a successor-verified node succeeds |
| `regrant(device_key, user_key, node, owner, valid_for_secs, pins_json, policy: SuccessorPolicy, owner_approved)` | sealed grant JSON | Grants to a node from `verify_successor` if the owner's policy allows: `Automatic`, `AskOwner` (needs `owner_approved`), `Never` |
| `generate_backup_key()` | `String` | A random backup key, for the platform's end-to-end encrypted store only |
| `wrap_keys(backup_key, owner, keys: [BackedUpKey])` | backup blob JSON | The keys encrypted under the backup key (format `credentials-key-backup/v1`) |
| `unwrap_keys(backup_key, owner, blob)` | `[BackedUpKey]` | The keys of a blob, for its owner only |
| `start_transfer()` | `TransferSender` | The old device's side of a 6-digit transfer: `code()`, `offer()`, `seal(answer, owner, keys)`, `attempts_left()` |
| `join_transfer(code, offer_json)` | `TransferReceiver` | The new device's side: `answer()`, then `open(sealed)` gives `TransferredKeys {owner, keys}` |
| `revoke(device_key, owner, identity_json)` | revocation JSON | Takes the user key back |
| `endorse_device(device_key, owner, identity_json, new_device_public_key)` | endorsement JSON | Adds another device of the owner on the node |
| `retire_device(device_key, owner, identity_json, device_public_key)` | retirement JSON | Withdraws another device |
| `sign_policy(device_key, policy_json)` | signed policy JSON | Signs a policy ([docs/policy.md](../../docs/policy.md)) |
| `seal_record(user_key, signed_policy_json, record_id, owner, fields: [Field])` | record JSON | Encrypts the values of a record; a typed record's values are checked against its kind first |
| `rewrap_record(user_key, record_json, signed_policy_json)` | record JSON | The record under a new policy, one generation later |
| `pin_record(device_key, record_json)` | pin JSON | Nodes refuse older generations of the record |
| `sign_call(caller_key, caller, identity_json, record_json, operation, body_json)` | signed call JSON | A call of an app on a record |
| `sign_derive_call(caller_key, caller, identity_json, record_json, operation, input)` | signed call JSON | The same for a derivation of `input` |
| `sign_describe_call(caller_key, caller, identity_json, record_json)` | signed call JSON | `describe` on a typed record: public fields and masks, never a secret field |
| `summarize(policy_json, previous_policy_json?)` | summary JSON | Where each secret can go, what comes back, risk flags, and what widens over the previous version |
| `policy_json_schema()` | `String` | The JSON Schema of the policy format |
| `item_kinds()` | `String` | The reviewed kinds of item |
| `sign_kind(device_key, kind_json)` | signed kind JSON | A custom kind of item |
| `approval_hash(summary_json)` | `String` | The SHA-256 an approval signs (of a summary, or of the pending reply that carries it) |
| `approve(device_key, identity_json, summary_json)` | approval JSON | Approves a summary that node built (or the `approval_required` reply as the node sent it), while it is open; for `POST /approve` |
| `answer_challenge(device_key, owner, identity_json, pending_json, code)` | sealed answer JSON | Answers a code challenge the node handed back, signed by the device and sealed to the node; the code is erased once sealed; for `POST /answer` |
| `sign_resume_call(caller_key, caller, identity_json, record_json, operation, id)` | signed call JSON | Goes on with a waiting operation: the same caller, record (the last one the node handed back) and operation, and the pending `id` |
| `sign_limits(device_key, owner, identity_json, record_id, rules_json)` | limits JSON | Spending limits of a record on the node: per currency and merchant, per payment, day and 30 days; for `POST /limits` |
| `delegate(device_key, user_key, node: VerifiedNode, record_json, delegate_owner, policy_json, wait_secs, valid_for_secs)` | delegation request JSON | Lets another owner's callers use the record under `policy_json` (the record's policy or narrower, its callers the delegate's), the record key sealed to the verified node; `wait_secs` 0, or 1 hour to 90 days of emergency access; at most 366 days; for `POST /delegate` |
| `change_delegation(device_key, owner, identity_json, record_id, id, change)` | change JSON | `cancel` an open request of emergency access, or `revoke` the delegation `id`; for `POST /delegation/change` |
| `sign_delegated_call(caller_key, caller, identity_json, record_json, operation, body_json, delegation_id)` | signed call JSON | A call of the delegate's caller under the delegation; refused with `delegation_waiting` while emergency access waits |
| `update_record(user_key, record_json, fields: [Field])` | record JSON | Replaces values one generation later, writing a session's expiry: how the owner renews a session the node cannot |

A call whose operation waits for the owner gets `{"kind": "challenge", ...}` or
`{"kind": "approval_required", ...}` back (see [docs/policy.md](../../docs/policy.md),
Operations that wait). The app shows it on the owner's device, which answers or approves;
then the app resumes:

```kotlin
val reply = http.post("$url/call", signCall(callerKey, "app", identity, record, "pay", """{"kind": "http"}"""))
val pending = reply.ok                                     // {"kind": "approval_required", "id", "summary"}
// On the owner's device, after showing the summary:
http.post("$url/approve", approve(deviceKey, identity, pending))
// Back in the app:
http.post("$url/call", signResumeCall(callerKey, "app", identity, record, "pay", pending.id))
```

`grant` takes a `VerifiedNode`, never a bare identity, and only `verify_node` and
`verify_attestation_reply` make one; it must be at most five minutes old. So an app cannot
seal the user key to a node whose attestation it did not check in the same flow, with a
nonce of its own: a `Nonce` is made only by `nonce()` and is spent by its first
verification, even a failed one.

A grant:

```kotlin
import uniffi.client.*

val nonce = nonce()
val reply = http.get("$url/attestation?nonce=${nonce.toB64()}")      // {identity, document}
val node = verifyAttestationReply(reply, nonce, measurementsJson)   // throws ClientException
val sealed = grant(deviceKey, userKey, node, "alice", 3600uL, listOf(recordJson))
http.post("$url/grant", sealed)
```

The Kotlin package is `uniffi.client` and the Swift module `client` (UniFFI's defaults).

### When the node changes

A node of a newer release takes over grants by itself (`docs/design.md`, section 10): the app
has nothing to do. When the old node is gone instead (it crashed), the app re-grants on its
next start, after checking the new node against the successor statement of the release it had
granted to:

```kotlin
val nonce = nonce()
val reply = http.get("$url/attestation?nonce=${nonce.toB64()}")
val node = verifySuccessor(document, nonce, successorJson, bundleJson, "v1.0.0", identity, null)
val sealed = regrant(deviceKey, userKey, node, "alice", 3600uL, listOf(recordJson),
                     SuccessorPolicy.ASK_OWNER, ownerApproved = askTheOwner(node.release()))
```

`verify_successor` refuses a downgrade, a statement of another release than `previous_release`,
a statement not signed by the release workflow of this repository at the tag of the newer
release (Sigstore: Fulcio certificate chain, signer, Rekor signed entry timestamp and inclusion
proof, all checked offline), and a node whose PCRs are not the statement's. The Sigstore trust
root compiled in is empty until it is committed: until then, pass a `trusted_root.json` the app
fetched through Sigstore's TUF repository, or every statement is refused.

### A new phone

Two ways to bring the device and user keys to a new phone, both without the keys ever being
readable on the way:

- **Backup.** `generate_backup_key()` once; store it only in iCloud Keychain (a synchronizable
  item) or Google Block Store (`setShouldBackupToCloud(true)`), which both encrypt end to end
  with the device passcode. `wrap_keys` gives the blob (JSON: `format`
  `credentials-key-backup/v1`, `owner`, `created_ms`, `nonce`, `ciphertext`; XChaCha20-Poly1305
  under HKDF-SHA256 of the backup key, with format, owner and time as additional data), which
  may be stored anywhere. On the new phone, `unwrap_keys` with the restored backup key. There is
  no passphrase mode on purpose: a passphrase a person remembers can be guessed offline from
  the blob.
- **Transfer with a 6-digit code.** The old phone calls `start_transfer()` and shows `code()`;
  the messages go through any relay:

  ```kotlin
  // old phone                                   // new phone
  val sender = startTransfer(); show(sender.code())
  send(sender.offer())                           val receiver = joinTransfer(typedCode, offer)
                                                 send(receiver.answer())
  send(sender.seal(answer, "alice", keys))       val got = receiver.open(sealed)
  ```

  SPAKE2 runs on the code, so a recorded transfer gives nothing to test guesses against; each
  side confirms the other (HMAC over the transcript) before any key is sent. Three wrong codes
  end the code, a transfer lasts five minutes, and each side seals or opens once.

### Errors

Every function fails with one error type, `ClientError`, whose variant is a stable code
(`ClientError::code()` in Rust; the case of the error enum in Swift and Kotlin; the `code`
property of the thrown `Error` in JavaScript). Each carries a `detail` message for people,
which never holds a secret and may change.

| Code | When |
| --- | --- |
| `invalid_key` | A key is not 32 bytes of unpadded base64url, or not a key of its kind |
| `invalid_input` | JSON that does not parse, an empty owner, a zero lifetime, a pinned record of another owner, a malformed field |
| `nonce_rejected` | The nonce was already used, or is older than five minutes |
| `measurements_invalid` | The measurements list does not parse or is empty |
| `attestation_refused` | The document was refused; `reason` names the check: `nonce_mismatch`, `unknown_measurement`, `debug_enclave`, `chain_untrusted`, `signature_invalid`, `certificate_not_valid_at`, `not_cbor`, ... |
| `binding_mismatch` | The document verifies but its user data is not the report data of the identity |
| `verification_expired` | The `VerifiedNode` is older than five minutes |
| `refused` | The engine refused: a policy that breaks a rule, an invalid record, too many pins; or a re-grant the owner's policy does not allow |
| `successor_refused` | A successor statement or its node was refused; `reason` names the check: `downgrade`, `not_for_this_release`, `signer_mismatch`, `chain_untrusted`, `signature_invalid`, `log_proof_invalid`, `bundle_invalid`, `trust_root_empty`, ... (a refused attestation of the node is `attestation_refused`) |
| `transfer_refused` | A wrong code or a changed message (with the attempts left), too many wrong codes, a transfer older than five minutes, or one already done |
| `backup_refused` | Another backup key, another owner, or a changed blob |

## Builds

```sh
# Web (wasm-bindgen): then wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/client.wasm
cargo build -p client --release --target wasm32-unknown-unknown
# Android: libclient.so for each ABI, with the NDK's clang as linker
cargo build -p client --release --target aarch64-linux-android
# iOS: libclient.a for the device and the simulator, then xcodebuild -create-xcframework
cargo build -p client --release --target aarch64-apple-ios
# Swift and Kotlin sources, from any built library (library mode of UniFFI)
cargo run -p client --features bindgen --bin uniffibindgen -- \
    generate --library target/release/libclient.so --language kotlin --language swift --out-dir out
```

The generated Swift and Kotlin sources are not kept in the repository (UniFFI's practice: they
are generated from the built library, so they always match it). CI builds them on every
change, with the web package, the Android libraries and an XCFramework; releases attach
`client-wasm-<tag>.tgz`, `client-android-<tag>.zip` (`jniLibs/<abi>/libclient.so` and the
Kotlin source, which needs JNA) and `client-ios-<tag>.xcframework.zip` (with the Swift
source).

The C compiler for wasm32 (ring has C code) is any clang with the wasm32 target, such as the
one of the Android NDK: set `CC_wasm32_unknown_unknown` and `AR_wasm32_unknown_unknown`.

Sizes of the release builds (the workspace release profile: `opt-level = 3`,
`codegen-units = 1`, LTO; Rust 1.97.1, built on Windows; gzip `-9`):

| Build | Size | gzip |
| --- | --- | --- |
| `client.wasm` (wasm32-unknown-unknown, before `wasm-bindgen`) | 1,691,790 B | 470,466 B |
| the same, with `strip = "symbols"` | 1,417,252 B | 424,025 B |
| the same, with `strip = "symbols"` and `opt-level = "s"` | 1,250,384 B | 362,231 B |
| `libclient.so` (aarch64-linux-android) | 1,967,976 B | |
| the same after `llvm-strip --strip-unneeded`, as packaged | 1,379,976 B | 665,921 B |

`build/client.sh` runs `wasm-bindgen --remove-name-section`, so the packaged
`client_bg.wasm` should come close to the stripped size; CI prints the package (not measured
locally: `wasm-bindgen` was not installed on the machine these were measured on).

### JavaScript

The web build exposes the same functions in camel case (`generateKey`, `verifyNode`,
`verifyAttestationReply`, `grant`, `sealRecord`, ...), with `Nonce` and `VerifiedNode`
classes. Bytes are `Uint8Array`, `valid_for_secs` a number of seconds, millisecond times
numbers, and the fields of `sealRecord` and `updateRecord` a `Map<string, Uint8Array>`. A failure throws an
`Error` with `code` (and `reason` for `attestation_refused`). Randomness comes from
`crypto.getRandomValues`, the time from `Date.now()`.

## Keeping the keys

The client hands every secret key to the app as a string and erases its own copies, including
the key strings the app passes in, once a call is done. Where the app keeps them decides how
safe the owner is.

- **Device key** (Ed25519): signs grants, revocations, policies, pins and device changes. It
  never needs to leave the device.
- **User key** (32 random bytes): encrypts the records, and leaves the device by design,
  sealed to an attested node in each grant.
- **Caller key** (Ed25519): signs the calls of an app that uses a record.

**Hardware key stores do not hold these keys.** The iOS Secure Enclave holds only P-256 keys,
and Android StrongBox only P-256 (and RSA, AES, HMAC) keys; the Android Keystore of a TEE
holds Ed25519 keys from Android 13 (KeyMint 2), but not in StrongBox, and the engine signs
with key bytes it holds itself. The engine's device and caller keys are Ed25519 and the user
key must be handed to a node, so none of them can be a non-exportable hardware key. The
consequence: while the app signs, the key bytes are in the app's memory, and a compromise of
the running app (or of the OS) can copy them. At rest they can still be protected by hardware:

- **iOS**: store the key in the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  (never synced to iCloud or restored to another device), optionally behind a
  `SecAccessControl` of `.userPresence` or `.biometryCurrentSet`; or encrypt it to a Secure
  Enclave P-256 key (`SecKeyCreateEncryptedData`, `eciesEncryptionCofactorX963SHA256AESGCM`)
  and keep only the ciphertext, so it opens only on that device and, with an access control,
  only after the user unlocks it.
- **Android**: wrap the key with an AES-256-GCM key of the Android Keystore
  (`setIsStrongBoxBacked(true)` where the device has StrongBox, else the TEE;
  `setUserAuthenticationRequired(true)` to ask for the user), and keep only the ciphertext in
  the app's private storage. Exclude it from backups.
- **Web**: there is no hardware store a page can rely on. Wrap the key with a non-extractable
  WebCrypto AES-GCM key kept in IndexedDB; that keeps it out of plain storage dumps, not out of
  reach of code running in the page. See the threat model: grants from the web are weaker
  than from an app.

Options for later, which change the engine and are not part of this crate: P-256 (ECDSA)
device keys, which the Secure Enclave and StrongBox could hold without ever exporting them
(the device key is the one key that never has to leave the device); or a P-256 key of the
platform that endorses the Ed25519 device key, so a node could require proof that the device
key is wrapped by hardware.

## Dependencies

Beyond the workspace: `uniffi` 0.32 (MPL-2.0, Swift and Kotlin bindings; not on wasm32),
`wasm-bindgen` 0.2 and `js-sys` 0.3 (MIT or Apache-2.0, wasm32 only), and the `wasm_js`
feature of `getrandom` and the `wasm32_unknown_unknown_js` feature of `ring` on wasm32 only.
The `bindgen` feature adds UniFFI's generator (`uniffibindgen`); apps never build it.
