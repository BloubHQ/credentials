# cli

The `credentials` command: the owner's device, a caller and a node, as one tool.

- **Owner** (on a device it controls): `keygen`, `policy check|sign|upgrade`, `seal`, `pin`, `grant`,
  `revoke`, `device endorse|retire`, and `attest` to check a node's AWS Nitro Enclaves
  attestation before granting.
- **Caller** (an application or agent): `call http|derive` signs a call and can send it.
- **Node**: `serve` runs a node behind a small HTTP/1.1 server with its log in a JSONL file;
  `node identity` prints the keys owners grant to.
- **Anyone**: `verify` checks the signed log of a node, offline.

Keys are files holding base64url text. Every other document is JSON. Secret values are read
from files (`@path`) or environment variables (`env:VAR`), never from the command line, so they
stay out of shell history and process listings.

```sh
cargo install --path crates/cli     # or: cargo run -p cli -- <command>
```

## Walkthrough: owner → node → caller

Everything below runs on one machine for the demonstration; in a deployment each part runs
where it belongs (device keys on the owner's device, the node in a TEE, the caller key with the
application).

### 1. Keys

```sh
mkdir demo && cd demo
credentials keygen device --out device.key      # prints the device public key
credentials keygen user   --out user.key        # prints nothing: it is secret
CALLER=$(credentials keygen caller --out caller.key)   # the caller's public key
credentials keygen node   --out node.key        # on the node; prints its log key
```

A key file is never overwritten; on Unix it is created with mode `0600`, and reading a key file
that the group or other users can read prints a warning. `credentials pubkey
device|caller|node --key <file>` prints a public key again later.

**Windows:** a key file is not made owner-only; it inherits the access list of its directory.
Keep key files in a directory only you can read (your user profile is, by default), or
restrict each file yourself:

```bat
icacls device.key /inheritance:r /grant:r "%USERNAME%:F"
```

### 2. A policy

The policy says what may be done with the secret, and by whom (see
[docs/policy.md](../../docs/policy.md)). Here: one operation with no connection, an HMAC of
the caller's input (at most 64 bytes of lowercase letters and digits), for one caller.

```sh
cat > policy.json <<EOF
{
  "fields": [{"name": "key", "secret": true}],
  "callers": [{"name": "app", "key": "$CALLER", "operations": ["sign"]}],
  "operations": [{"name": "sign",
                  "input": {"raw": {"max_len": 64, "pattern": "[a-z0-9]+"}},
                  "steps": [{"do": "return",
                             "template": "{{ hex(hmac_sha256(key, \$input)) }}"}]}]
}
EOF
credentials policy check policy.json
credentials policy sign policy.json --device device.key --out signed.json
```

`policy check` prints one line per field, operation and caller and exits 1 with the rule that
fails (`policy invalid at fields[0].name: name is not a token`). `policy sign` prints the same
summary to stderr before it signs: read it. `policy check signed.json` reads a signed policy
too; add `--device <device public key>` to check its signature (a signed policy does not name
its signer). Giving a signed policy where an unsigned one is expected, or the reverse, says
which one it is and what to run.

### 3. A record

```sh
head -c 32 /dev/urandom > hmac.key       # a new random HMAC key; or use an existing secret
credentials seal --user-key user.key --id signer --owner me --policy signed.json \
    --field key=@hmac.key --out record.json
rm hmac.key
```

`--field NAME=@PATH` takes the bytes of the file exactly as they are (mind a trailing newline);
`--field NAME=env:VAR` takes an environment variable (`--field key=env:HMAC_KEY` after
`export HMAC_KEY=...`). Repeat `--field` for each field. A value that breaks a rule is named
before anything is sealed: `field `key` is empty`, a name that is not a token, a field given
twice, more than 32 fields or more than 16 MiB in all. The record (`record.json`) is
ciphertext: the operator and the caller may hold it.

Later, once the node of step 4 runs, change the policy by signing the new one (here
`policy2.json`, an edited copy of `policy.json`) and rewrapping the record: the values stay
inside the engine and the generation grows by one.

```sh
credentials policy sign policy2.json --device device.key --out signed2.json
credentials seal --user-key user.key --policy signed2.json --from record.json --out record.json.new
credentials pin --device device.key --record record.json.new --send http://127.0.0.1:8700
```

After the pin, the node refuses the older generation.

### 4. The node

```sh
credentials serve --key node.key --log log.jsonl --listen 127.0.0.1:8700
```

On start it reads every entry of `log.jsonl` (created when missing), checks the chain and
restores the node (record floors, known devices, last grant times; grants themselves do not
survive a restart, so owners grant again). It then writes the signed checkpoint of the log to
`log.jsonl.head.json` after every act.

The owner gets the node's identity from the key file or from the running server:

```sh
credentials node identity --key node.key --out identity.json
credentials node identity --url http://127.0.0.1:8700 --out identity.json
```

In a deployment, check the node's attestation against `NodeIdentity::report_data()` before
granting. For a node in an AWS Nitro Enclave, ask it for an attestation document over a fresh
random nonce (32 bytes, base64url) and check it against the `measurements.json` of the releases
you accept:

```sh
credentials attest --document doc.cbor --nonce "$NONCE" --measurements measurements.json \
    --identity identity.json
```

It prints the release, module, time and PCR0–2, and that the document vouches for the node
identity. It checks the COSE_Sign1 structure (ES384), the certificate chain to the pinned AWS
Nitro Enclaves Root-G1 at the time the document states, the signature, the nonce, that PCR0–2
are not all zero (a debug enclave) and equal one accepted release, and with `--identity` that
the document's `user_data` is the identity's `report_data()`. `--document -` reads stdin.
`measurements.json` is one object `{"release", "git_commit", "pcr0", "pcr1", "pcr2"}` (PCRs as
96 hex digits; other keys ignored) or an array of them. A refused document exits 3.

### 5. A grant

```sh
credentials grant --device device.key --user-key user.key --node identity.json \
    --owner me --valid 60 --pin record.json --send http://127.0.0.1:8700
```

The grant (the user key and the signed terms) is sealed to the node's seal key; only that node
can open it. `--pin` pins each record at its generation; without a pin the node refuses the
record, and `grant` warns about it on stderr (pin later with `credentials pin`). `--out
grant.json` keeps a copy; with neither `--out` nor `--send` it is printed.

To seal the grant only to an attested node, add the document:

```sh
credentials grant --device device.key --user-key user.key --node identity.json \
    --owner me --valid 60 --pin record.json \
    --attestation doc.cbor --nonce "$NONCE" --measurements measurements.json \
    --send http://127.0.0.1:8700
```

The three options go together. The grant is made only if the document passes every check of
`credentials attest` and vouches for `identity.json`; otherwise nothing is written or sent and
`grant` exits 3. Without `--attestation`, `grant` warns that nothing shows what code holds the
seal key.

### 6. A call

```sh
credentials call derive --caller-key caller.key --caller app --node identity.json \
    --record record.json --operation sign --input 'hello' --send http://127.0.0.1:8700
```

```json
{"ok":{"kind":"derive","output":"<base64url>","utf8":"<hex hmac>"},"record":null}
```

The exit status is 0 when the node ran the call, 3 when it refused it, 4 when it rate
limited it and 5 when the node could not be reached (see [Exit codes](#exit-codes)). An HTTP
operation:

```sh
credentials call http --caller-key caller.key --caller app --node identity.json \
    --record github.json --operation github \
    --method GET --host api.github.com --path /user \
    --header 'Accept: application/vnd.github+json' --header 'User-Agent: demo' \
    --send http://127.0.0.1:8700
```

Leave out `--method` (and the request options) when every step of the operation sends a
fixed request. `--body` and `--input` take `@path`, `env:VAR` or literal text. When the node
seals the record again (an operation captured a new token), the reply carries the new record
and `--send` writes it over the `--record` file: keep it, or the next call fails as stale.
Without `--send`, `--out call.json` writes the signed call for any other transport; a node
accepts it within five minutes, once.

### 7. Devices and revocation

```sh
NEW=$(credentials keygen device --out laptop.key)
credentials device endorse --device device.key --owner me --node identity.json \
    --target "$NEW" --send http://127.0.0.1:8700
OLD=$(credentials pubkey device --key device.key)
credentials device retire  --device laptop.key --owner me --node identity.json \
    --target "$OLD" --send http://127.0.0.1:8700    # the laptop withdraws the old device
credentials revoke --device laptop.key --owner me --node identity.json \
    --send http://127.0.0.1:8700
```

`--target` also takes `@file` holding the public key. A retired device signs nothing more for
the owner on that node, so the laptop signs the revocation.

After `revoke` the node erases the user key of the owner; calls fail with `no grant in force`.
Here they fail even earlier, with `policy signature invalid` (exit code 3): the policy of the
record was signed by the device the laptop retired, and the node accepts only policies signed
by a device it still knows for the owner. Sign the policy again with a current device and
rewrap the record before granting again.

### 8. Checking the log

The log is one signed entry per line, the format `credentials verify` reads (the verifier is
the [`verify`](../verify) crate, built into this binary):

```sh
NODE_KEY=$(credentials pubkey node --key node.key)
credentials verify log.jsonl "$NODE_KEY" --head log.jsonl.head.json
```

`credentials verify --help` lists its options. It has its own exit codes: 0 the log is valid,
1 it is invalid, 2 usage error or a file that cannot be read. A first entry whose signature
fails asks whether the key given is the node's log public key.

## Commands

| Command | Does |
| --- | --- |
| `keygen device\|caller\|node\|user --out F` | Writes a new key file; prints the public key (not for `user`). |
| `pubkey device\|caller\|node --key F` | Prints the public key of a key file. |
| `policy check P [--device KEY]` | Validates a policy or a signed policy (and with `--device` its signature), prints the summary; exit 1 with the rule on error. |
| `policy sign P --device F --out S` | Summary to stderr, then writes the signed policy. |
| `policy upgrade OLD --out P` | Converts a policy of the format before steps (`"kind": "http"`, `"stream"`, `"derive"`; signed or not) and writes it unsigned; notes on stderr say what it narrowed. Read the summary and sign the result again. |
| `seal --user-key F --id I --owner O --policy S --field N=@path\|N=env:V... --out R` | Seals values into a new record (generation 1). |
| `seal --user-key F --policy S --from R --out R2` | Rewraps a record under a new signed policy. |
| `pin --device F --record R [--out\|--send]` | Pins a record at its generation (`POST /pin`). |
| `grant --device F --user-key F --node ID --owner O --valid MIN [--pin R...] [--attestation DOC --nonce N --measurements M] [--out\|--send]` | A sealed grant (`POST /grant`); with `--attestation`, only to a node whose document verifies and binds `ID`. |
| `attest --document DOC\|- --nonce N --measurements M [--identity ID]` | Verifies a Nitro attestation document; prints release, module, time and PCR0–2; with `--identity`, checks the binding (refused: exit 3). |
| `revoke --device F --owner O --node ID [--out\|--send]` | A revocation (`POST /revoke`). |
| `device endorse\|retire --device F --owner O --node ID --target KEY [--out\|--send]` | Adds or withdraws another device (`POST /device/add`, `/device/retire`). |
| `call http\|derive --caller-key F --caller N --node ID --record R --operation OP ... [--out\|--send]` | A signed call (`POST /call`). |
| `serve --key F --log L [--listen A] [--anchor H] [--threads N] [--max-connections N] [--max-body BYTES]` | The node server. |
| `host --enclave-cid CID --log-dir D [--listen A] [--allow HOST:PORT...] [--http-port P] [--egress-port P] [--log-port P] [--max-connections N]` | The parent-instance side of a node in a Nitro Enclave (Linux only). |
| `node identity --key F \| --url U [--out ID]` | The node identity JSON. |
| `verify LOG NODE_KEY [--head H] [--owner O] [--user-key F] [--json]` | Checks a node log offline (own exit codes 0, 1, 2). |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Any other failure: an invalid document, a value the engine refuses. |
| 2 | Usage error (a wrong option, a missing argument, a literal secret). |
| 3 | Refused by the node (HTTP 400, 403 or 404), or the node's attestation document refused (`attest`, `grant --attestation`). |
| 4 | Rate limited by the node (HTTP 429). |
| 5 | Connection, transport, log or file I/O failure (including HTTP 502 or 503 from the node, and `serve` failing to start). |

`credentials --help` lists them too. `credentials verify` keeps its own: 0 valid, 1 invalid,
2 usage or I/O.

## The server

| Endpoint | Body | Reply |
| --- | --- | --- |
| `GET /identity` | | `NodeIdentity` |
| `GET /checkpoint` | | `SignedHead` |
| `POST /grant` | `SealedGrant` | `{"ok": true}` or `{"error": "..."}` |
| `POST /revoke` | `Revocation` | same |
| `POST /pin` | `Pin` | same |
| `POST /device/add` | `Endorsement` | same |
| `POST /device/retire` | `Retirement` | same |
| `POST /call` | `SignedCall` | `{"ok": <output>, "record": <Record or null>}` or `{"error": "...", "record": ...}` |

The output of a call is `{"kind": "http", "response": <Response>}`,
`{"kind": "stream", "reads": [<base64url>...], "error": <string or null>}` or
`{"kind": "derive", "output": <base64url>, "utf8": <string or null>}`. Bytes are base64url
throughout. Errors map to 400 (the caller's request), 403 (refused by grant, record or
policy), 429 (rate limit), 502 (transport) and 503 (log). Failures before the caller is
authenticated (no grant, expired grant, unpinned or stale record, bad policy signature) all
answer 403, so the status tells a stranger nothing more.

- **Limits.** One request per connection (`Connection: close`). At most `--max-connections`
  (64) connections are open at once; beyond that the server answers 503. A client has 10
  seconds to send its whole request; the head is limited to 16 KiB, and a body larger than
  `--max-body` (4 MiB: a call with a 1 MiB input and a record of about 2 MiB) is refused with
  413 before it is read. A POST needs `Content-Length`; chunked bodies are refused. At most
  `--threads` (4) acts run at once; `GET /identity` and `GET /checkpoint` never wait behind
  them or behind slow clients.

- **Log.** Each entry is appended as one line, flushed and `sync_data`'d before the act goes
  on. When a write fails the node halts (it takes no act); the server cuts the file back to the
  last confirmed entry and reconciles on the next request, else answers 503. On start a last
  line without its newline (a write that never completed, so never confirmed) is cut off.
- **Checkpoint.** `log.jsonl.head.json` is the signed head after the last act that appended to
  the log (a refused act writes nothing). Here it sits next to the log, where the operator can
  roll both back together; a real deployment keeps it in TEE-sealed storage or behind a monotonic counter and restarts with `--anchor <head.json>`,
  which refuses a log that ends before it.
- **Exposure.** The server speaks plain HTTP and authenticates no connection: each act is
  authorized only by what it carries (a sealed grant, a device signature, a signed call). It
  binds to `127.0.0.1:8700` by default and warns when it listens on anything else. TLS
  termination and limits on who may connect are the deployer's job.
- **Memory.** The binary installs a zeroizing global allocator, so freed buffers (TLS
  records, parsed keys) are erased.

## The host (Nitro Enclaves)

`credentials host` runs on the Linux parent instance of an AWS Nitro Enclave; the
[`host`](../host) crate implements it, and its README describes the command.
