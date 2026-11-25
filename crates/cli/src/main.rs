//! `credentials`: the command-line tool of the credentials engine.
//!
//! - The owner's device: `keygen`, `policy check|sign`, `seal`, `pin`, `grant`, `revoke`,
//!   `device endorse|retire`, and `attest` to check a node's Nitro attestation first.
//! - A caller: `call http|derive` signs a call and can send it to a node.
//! - A node: `serve` runs a node behind a small HTTP server, its log in a JSONL file;
//!   `node identity` prints what owners grant to; `host` runs on the parent instance of a
//!   Nitro Enclave that runs the `enclave` node (HTTP forwarding, egress relay, log writer).
//! - Anyone: `verify` checks a node log offline (the `verify` crate).
//!
//! Keys are files holding base64url text; documents are JSON. Secret values are read from
//! files or environment variables, never from the command line.

mod attestation;
mod client;
mod files;
mod serve;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use engine::call::Body;
use engine::fields::Fields;
use engine::grant::{GrantTerms, NodeIdentity};
use engine::keys::{CallerKey, DeviceKey, DevicePublicKey, NodeKey, UserKey};
use engine::node::{Node, SystemClock, now_ms};
use engine::policy::{Destination, Method, Policy, SignedPolicy};
use engine::record::Record;
use engine::request::Request;
use serde::Serialize;
use serde_json::Value;

use crate::files::{Failure, Res};

/// Every freed heap block is erased, including the buffers of dependencies (TLS records,
/// parsed keys) the engine cannot reach.
#[global_allocator]
static ALLOCATOR: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);

const EXIT_CODES: &str = "\
Exit codes:
  0  success
  1  any other failure (an invalid document, a value the engine refuses)
  2  usage error
  3  refused by the node (HTTP 400, 403, 404), or its attestation document refused
  4  rate limited by the node (HTTP 429)
  5  connection, transport, log or file I/O failure (HTTP 502, 503 from the node)
`credentials verify` keeps its own codes: 0 valid, 1 invalid, 2 usage or I/O.";

const KEYGEN_HELP: &str = "\
On Unix the key file is created with mode 0600. On Windows it inherits the access list of
its directory: keep key files in a directory only you can read (your user profile is, by
default), or restrict the file yourself:
  icacls <file> /inheritance:r /grant:r \"%USERNAME%:F\"";

#[derive(Parser)]
#[command(
    name = "credentials",
    version,
    about = "Owner, caller and node tool of the credentials vault engine",
    after_help = EXIT_CODES
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a key in a new file (never overwritten) and prints its public key.
    #[command(after_help = KEYGEN_HELP)]
    Keygen {
        /// The kind of key.
        kind: KeyKind,
        /// The new key file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Prints the public key of a key file.
    Pubkey {
        /// The kind of key.
        kind: PublicKind,
        /// The key file.
        #[arg(long)]
        key: PathBuf,
    },
    /// Checks or signs a policy.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Seals secret values into a record, or rewraps a record under a new policy.
    Seal(SealArgs),
    /// Pins a record on a node: the node then refuses older generations of it.
    Pin(PinArgs),
    /// Grants a node the user key for a while, sealed so only that node can open it.
    Grant(GrantArgs),
    /// Verifies an AWS Nitro Enclaves attestation document of a node: the chain to the pinned
    /// AWS root, the signature, the nonce, and that the PCRs are those of an accepted release.
    Attest(AttestArgs),
    /// Takes the user key back from a node.
    Revoke(RevokeArgs),
    /// Endorses or retires another device of the owner on a node.
    #[command(subcommand)]
    Device(DeviceCommand),
    /// Signs a call of a caller, and optionally sends it to a node server.
    #[command(subcommand)]
    Call(CallCommand),
    /// Runs a node server.
    Serve(ServeArgs),
    /// Runs the host side of a node in an AWS Nitro Enclave (Linux parent instance only).
    Host(HostArgs),
    /// Hands the state of a running enclave over to an enclave of a newer release (Linux
    /// parent instance only): both enclaves check the signed successor statement and each
    /// other's attestation; this program only carries the messages.
    HandOver(HandOverArgs),
    /// Node information.
    #[command(subcommand)]
    Node(NodeCommand),
    /// Checks the signed log of a node, offline (see `credentials verify --help`).
    #[command(disable_help_flag = true)]
    Verify {
        /// The arguments of the verifier: `<log.jsonl> <node-public-key> [--head <file>]
        /// [--owner <name>] [--user-key <file>] [--json]`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum KeyKind {
    /// Signs policies, grants, pins and device changes; stays on the owner's device.
    Device,
    /// Signs the calls of an application or agent.
    Caller,
    /// Signs the log of a node; grants are sealed to a key derived from it.
    Node,
    /// The user key: records are encrypted under keys derived from it.
    User,
}

#[derive(Clone, Copy, ValueEnum)]
enum PublicKind {
    /// A device key.
    Device,
    /// A caller key.
    Caller,
    /// A node key (prints the log key).
    Node,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Parses and validates a policy (signed or not) and prints its summary; exits 1 when it
    /// is invalid. With --device, also checks the signature of a signed policy.
    Check {
        /// The policy JSON, or a signed policy.
        policy: PathBuf,
        /// The public key of the device that should have signed it (base64url, or @file
        /// holding it). A signed policy does not carry its signer, so without it the
        /// signature is not checked.
        // Keys are base64url and may start with `-`.
        #[arg(long, value_name = "KEY", allow_hyphen_values = true)]
        device: Option<String>,
    },
    /// Validates a policy, prints its summary to stderr and writes it signed.
    Sign {
        /// The policy JSON.
        policy: PathBuf,
        /// The device key file.
        #[arg(long)]
        device: PathBuf,
        /// The signed policy to write.
        #[arg(long)]
        out: PathBuf,
    },
    /// Converts a policy of the format before the step language (operations of kind `http`,
    /// `stream` and `derive`, signed or not) and writes it unsigned. The notes printed to
    /// stderr say what the conversion narrowed; the result must be read and signed again.
    Upgrade {
        /// The old policy JSON, or an old signed policy.
        policy: PathBuf,
        /// The converted policy to write.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args)]
struct SealArgs {
    /// The user key file.
    #[arg(long)]
    user_key: PathBuf,
    /// The signed policy.
    #[arg(long)]
    policy: PathBuf,
    /// The record id (not with --from).
    #[arg(long, required_unless_present = "from")]
    id: Option<String>,
    /// The owner (not with --from).
    #[arg(long, required_unless_present = "from")]
    owner: Option<String>,
    /// A value: NAME=@PATH (the bytes of the file as they are) or NAME=env:VAR. Repeat it.
    #[arg(long = "field", value_name = "NAME=@PATH|NAME=env:VAR")]
    fields: Vec<String>,
    /// Rewraps this record under the new policy, keeping its values, one generation later.
    #[arg(long, conflicts_with_all = ["id", "owner", "fields"])]
    from: Option<PathBuf>,
    /// The record to write.
    #[arg(long)]
    out: PathBuf,
}

/// Where a signed document goes: a file, a node server, or stdout when neither is given.
#[derive(Args)]
struct Deliver {
    /// Writes the JSON to this file.
    #[arg(long)]
    out: Option<PathBuf>,
    /// POSTs it to a node server, such as http://127.0.0.1:8700, and prints the reply.
    #[arg(long, value_name = "URL")]
    send: Option<String>,
}

#[derive(Args)]
struct PinArgs {
    /// The device key file.
    #[arg(long)]
    device: PathBuf,
    /// The record to pin at its generation.
    #[arg(long)]
    record: PathBuf,
    #[command(flatten)]
    deliver: Deliver,
}

#[derive(Args)]
struct GrantArgs {
    /// The device key file.
    #[arg(long)]
    device: PathBuf,
    /// The user key file.
    #[arg(long)]
    user_key: PathBuf,
    /// The node identity JSON (from `credentials node identity`).
    #[arg(long)]
    node: PathBuf,
    /// The owner.
    #[arg(long)]
    owner: String,
    /// How long the grant lasts, in minutes (a node shortens it to 30 days).
    #[arg(long, value_name = "MINUTES")]
    valid: u64,
    /// Records to pin at their generations. Repeat it, or list several.
    #[arg(long = "pin", value_name = "RECORD", num_args = 1..)]
    pins: Vec<PathBuf>,
    /// An attestation document of the node (CBOR, `-` for stdin): the grant is sealed only if
    /// it verifies and vouches for the node identity of --node. Needs --nonce and
    /// --measurements.
    #[arg(long, value_name = "FILE", requires_all = ["nonce", "measurements"])]
    attestation: Option<PathBuf>,
    /// The nonce the attestation document was asked for (base64url).
    // Base64url may start with `-`.
    #[arg(long, requires = "attestation", allow_hyphen_values = true)]
    nonce: Option<String>,
    /// The measurements.json of the releases to accept (one object or an array).
    #[arg(long, value_name = "FILE", requires = "attestation")]
    measurements: Option<PathBuf>,
    /// Keep this grant from moving to a successor node: by default a node hands it over to a
    /// node of a newer release signed by the release workflow (docs/design.md, section 10).
    #[arg(long)]
    no_successor: bool,
    #[command(flatten)]
    deliver: Deliver,
}

#[derive(Args)]
struct HandOverArgs {
    /// The vsock CID of the running enclave, which hands over.
    #[arg(long)]
    from_cid: u32,
    /// The vsock CID of the enclave of the newer release, which takes over.
    #[arg(long)]
    to_cid: u32,
    /// The successor statement of the newer release (`successor.json` of its release).
    #[arg(long, value_name = "FILE")]
    statement: PathBuf,
    /// Its Sigstore bundle (`successor.sigstore.json`).
    #[arg(long, value_name = "FILE")]
    bundle: PathBuf,
}

#[derive(Args)]
struct AttestArgs {
    /// The attestation document (CBOR, as the node returns it), or `-` for stdin.
    #[arg(long, value_name = "FILE", allow_hyphen_values = true)]
    document: PathBuf,
    /// The nonce the document was asked for (base64url, at least 16 bytes).
    // Base64url may start with `-`.
    #[arg(long, allow_hyphen_values = true)]
    nonce: String,
    /// The measurements.json of the releases to accept (one object or an array).
    #[arg(long, value_name = "FILE")]
    measurements: PathBuf,
    /// The node identity JSON: also checks that the user data of the document is its report
    /// data, so the keys in it belong to the attested enclave.
    #[arg(long, value_name = "FILE")]
    identity: Option<PathBuf>,
}

#[derive(Args)]
struct RevokeArgs {
    /// The device key file.
    #[arg(long)]
    device: PathBuf,
    /// The owner.
    #[arg(long)]
    owner: String,
    /// The node identity JSON.
    #[arg(long)]
    node: PathBuf,
    #[command(flatten)]
    deliver: Deliver,
}

#[derive(Args)]
struct DeviceArgs {
    /// The key file of a device the node already knows for the owner.
    #[arg(long)]
    device: PathBuf,
    /// The owner.
    #[arg(long)]
    owner: String,
    /// The node identity JSON.
    #[arg(long)]
    node: PathBuf,
    /// The public key of the other device (base64url, or @file holding it).
    #[arg(long, allow_hyphen_values = true)]
    target: String,
    #[command(flatten)]
    deliver: Deliver,
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Vouches for another device of the owner on the node.
    Endorse(DeviceArgs),
    /// Withdraws another device of the owner (lost, sold, replaced) on the node.
    Retire(DeviceArgs),
}

#[derive(Args)]
struct CallCommon {
    /// The caller key file.
    #[arg(long)]
    caller_key: PathBuf,
    /// The name of the caller in the policy.
    #[arg(long)]
    caller: String,
    /// The node identity JSON.
    #[arg(long)]
    node: PathBuf,
    /// The record to use. With --send, a new record the node hands back replaces this file.
    #[arg(long)]
    record: PathBuf,
    /// The operation of the policy.
    #[arg(long)]
    operation: String,
    #[command(flatten)]
    deliver: Deliver,
}

#[derive(Args)]
struct HttpCallArgs {
    #[command(flatten)]
    common: CallCommon,
    /// The method of the caller's request; leave it out when every step sends a fixed request.
    #[arg(long)]
    method: Option<String>,
    /// The host of the request.
    #[arg(long, requires = "method")]
    host: Option<String>,
    /// The port of the request.
    #[arg(long, default_value_t = 443, requires = "method")]
    port: u16,
    /// The path and query of the request.
    #[arg(long, requires = "method")]
    path: Option<String>,
    /// A header 'Name: value'. Repeat it.
    #[arg(long = "header", value_name = "NAME: VALUE", requires = "method")]
    headers: Vec<String>,
    /// The body: @path, env:VAR or literal text.
    #[arg(long, requires = "method")]
    body: Option<String>,
}

#[derive(Args)]
struct DeriveCallArgs {
    #[command(flatten)]
    common: CallCommon,
    /// The input ($input of the template): @path, env:VAR or literal text.
    #[arg(long)]
    input: String,
}

#[derive(Subcommand)]
enum CallCommand {
    /// An HTTP operation.
    Http(HttpCallArgs),
    /// A derive operation.
    Derive(DeriveCallArgs),
}

#[derive(Args)]
struct ServeArgs {
    /// The node key file.
    #[arg(long)]
    key: PathBuf,
    /// The log: one signed entry per line; created when missing. The latest checkpoint is
    /// written next to it as LOG.head.json.
    #[arg(long)]
    log: PathBuf,
    /// The address to listen on. Anything but loopback prints a warning.
    #[arg(long, default_value = "127.0.0.1:8700")]
    listen: String,
    /// A checkpoint the log must reach, such as a copy of LOG.head.json kept where the
    /// operator cannot roll it back.
    #[arg(long)]
    anchor: Option<PathBuf>,
    /// Requests that run acts (grant, pin, call...) at once; reads of the identity and the
    /// checkpoint do not wait for them.
    #[arg(long, default_value_t = 4)]
    threads: usize,
    /// Most connections open at once; beyond it the server answers 503. Each client has
    /// 10 seconds to send its whole request.
    #[arg(long, default_value_t = serve::DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
    /// Largest request body, in bytes; a larger one is refused (413) before it is read.
    #[arg(long, value_name = "BYTES", default_value_t = serve::DEFAULT_MAX_BODY)]
    max_body: usize,
}

#[derive(Args)]
struct HostArgs {
    /// The vsock CID of the enclave (`nitro-cli describe-enclaves`).
    #[arg(long)]
    enclave_cid: u32,
    /// The directory of the logs: one JSONL file per node key (a restarted enclave is a new
    /// node), each with its latest checkpoint next to it.
    #[arg(long)]
    log_dir: PathBuf,
    /// The TCP address clients connect to; each connection is forwarded to the enclave.
    #[arg(long, default_value = "127.0.0.1:8700")]
    listen: String,
    /// A destination the egress relay may connect to, as host:port (repeat it). Without any,
    /// the relay connects wherever the node asks (the node checks the signed policies).
    #[arg(long, value_name = "HOST:PORT", value_parser = host::parse_allow)]
    allow: Vec<String>,
    /// The vsock port of the node server in the enclave.
    #[arg(long, default_value_t = relay::HTTP_PORT)]
    http_port: u32,
    /// The vsock port of the egress relay on this host.
    #[arg(long, default_value_t = relay::EGRESS_PORT)]
    egress_port: u32,
    /// The vsock port of the log writer on this host.
    #[arg(long, default_value_t = relay::LOG_PORT)]
    log_port: u32,
    /// Most client connections open at once; beyond it the host answers 503.
    #[arg(long, default_value_t = serve::DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Prints the identity of a node (its log key and seal key) as JSON.
    Identity {
        /// From the node key file.
        #[arg(long, required_unless_present = "url", conflicts_with = "url")]
        key: Option<PathBuf>,
        /// From a running node server, such as http://127.0.0.1:8700.
        #[arg(long)]
        url: Option<String>,
        /// Writes it to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn device_key(path: &Path) -> Res<DeviceKey> {
    let mut bytes = files::read_key32(path)?;
    Ok(DeviceKey::from_bytes(&mut bytes))
}

fn caller_key(path: &Path) -> Res<CallerKey> {
    let mut bytes = files::read_key32(path)?;
    Ok(CallerKey::from_bytes(&mut bytes))
}

fn user_key(path: &Path) -> Res<UserKey> {
    let mut bytes = files::read_key32(path)?;
    Ok(UserKey::from_bytes(&mut bytes))
}

fn engine(context: &str) -> impl FnOnce(engine::Error) -> String + '_ {
    move |e| format!("{context}: {e}")
}

fn keygen(kind: KeyKind, out: &Path) -> Res<()> {
    let public = match kind {
        KeyKind::Device => {
            let key = DeviceKey::generate();
            files::write_secret_file(out, files::key_text(&key.to_bytes()).as_bytes())?;
            Some(key.public().to_b64())
        }
        KeyKind::Caller => {
            let key = CallerKey::generate();
            files::write_secret_file(out, files::key_text(&key.to_bytes()).as_bytes())?;
            Some(key.public().to_b64())
        }
        KeyKind::Node => {
            let key = NodeKey::generate();
            files::write_secret_file(out, files::key_text(&key.to_bytes()).as_bytes())?;
            Some(key.public().to_b64())
        }
        KeyKind::User => {
            let key = UserKey::generate();
            let mut text = key.to_b64();
            text.push('\n');
            files::write_secret_file(out, text.as_bytes())?;
            None
        }
    };
    match public {
        Some(public) => println!("{public}"),
        None => eprintln!("wrote the user key to {}", out.display()),
    }
    Ok(())
}

fn pubkey(kind: PublicKind, key: &Path) -> Res<()> {
    let public = match kind {
        PublicKind::Device => device_key(key)?.public().to_b64(),
        PublicKind::Caller => caller_key(key)?.public().to_b64(),
        PublicKind::Node => serve::node_key(key)?.public().to_b64(),
    };
    println!("{public}");
    Ok(())
}

/// What a policy file holds.
enum PolicyFile {
    /// A policy as written by hand.
    Unsigned(Policy),
    /// A policy signed by `credentials policy sign`.
    Signed(SignedPolicy),
}

/// Reads a policy file, signed or not, and tells which one it is from its keys, so a mix-up
/// gets a clear message instead of a serde error about an unknown field.
fn read_policy_file(path: &Path) -> Res<PolicyFile> {
    let value = files::read_json_value(path)?;
    let signed = value
        .as_object()
        .is_some_and(|o| o.contains_key("policy") && o.contains_key("signature"));
    let parsed = if signed {
        serde_json::from_value(value).map(PolicyFile::Signed)
    } else {
        serde_json::from_value(value).map(PolicyFile::Unsigned)
    };
    parsed.map_err(|e| Failure::from(format!("{}: {e}", path.display())))
}

/// An unsigned policy, validated; a signed one is refused with what to do instead.
fn read_policy(path: &Path) -> Res<Policy> {
    let policy = match read_policy_file(path)? {
        PolicyFile::Unsigned(policy) => policy,
        PolicyFile::Signed(_) => {
            return Err(format!(
                "{}: this policy is already signed; sign the unsigned policy JSON instead",
                path.display()
            )
            .into());
        }
    };
    policy
        .validate()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(policy)
}

/// A signed policy; an unsigned one is refused with what to do instead.
fn read_signed_policy(path: &Path) -> Res<SignedPolicy> {
    match read_policy_file(path)? {
        PolicyFile::Signed(policy) => Ok(policy),
        PolicyFile::Unsigned(_) => Err(format!(
            "{}: this policy is not signed; run `credentials policy sign {} --device <device key> --out <signed policy>` first",
            path.display(),
            path.display()
        )
        .into()),
    }
}

/// A device public key given as base64url or `@file`.
fn device_public_key(spec: &str) -> Res<DevicePublicKey> {
    let text = match spec.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| Failure::io(format!("cannot read {path}: {e}")))?,
        None => spec.to_string(),
    };
    DevicePublicKey::from_b64(text.trim())
        .map_err(|_| Failure::usage(format!("{spec}: not a device public key")))
}

fn policy_check(path: &Path, device: Option<&str>) -> Res<()> {
    let policy = match read_policy_file(path)? {
        PolicyFile::Unsigned(policy) => {
            if device.is_some() {
                return Err(Failure::usage(format!(
                    "{}: this policy is not signed, so --device has nothing to check",
                    path.display()
                )));
            }
            policy
                .validate()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            println!("unsigned policy");
            policy
        }
        PolicyFile::Signed(signed) => {
            match device {
                Some(spec) => {
                    let key = device_public_key(spec)?;
                    signed
                        .verify(&key)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    println!(
                        "signed policy: the signature of device {} verifies",
                        key.to_b64()
                    );
                }
                None => {
                    signed
                        .policy
                        .validate()
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    println!(
                        "signed policy: signature not checked (a signed policy does not name its signer; give --device <public key> to check it)"
                    );
                }
            }
            signed.policy
        }
    };
    for line in policy.summary() {
        println!("{line}");
    }
    Ok(())
}

/// Checks the values of `seal` against the rules of the engine first, so the message names
/// the field and the rule. `before` is the size of the values already in `fields`.
fn check_field(fields: &Fields, before: usize, name: &str, value: &[u8], spec: &str) -> Res<()> {
    let token = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !token {
        return Err(Failure::usage(format!(
            "--field {spec:?}: the name must be 1 to 64 letters, digits, '-' or '_'"
        )));
    }
    if fields.names().contains(&name) {
        return Err(Failure::usage(format!("field `{name}` is given twice")));
    }
    if value.is_empty() {
        return Err(format!(
            "field `{name}` is empty (from {spec:?}); a value needs at least one byte"
        )
        .into());
    }
    if fields.names().len() >= engine::fields::MAX_FIELDS {
        return Err(format!(
            "field `{name}`: a record holds at most {} fields",
            engine::fields::MAX_FIELDS
        )
        .into());
    }
    let total = before.saturating_add(value.len());
    if total > engine::fields::MAX_TOTAL {
        return Err(format!(
            "field `{name}` is too large: the values of a record hold at most {} bytes in all ({total} given)",
            engine::fields::MAX_TOTAL
        )
        .into());
    }
    Ok(())
}

fn seal(args: &SealArgs) -> Res<()> {
    let key = user_key(&args.user_key)?;
    let policy = read_signed_policy(&args.policy)?;
    let record = if let Some(from) = &args.from {
        let old: Record = files::read_json(from)?;
        old.rewrap(&key, policy)
            .map_err(engine("cannot rewrap the record"))?
    } else {
        let (Some(id), Some(owner)) = (&args.id, &args.owner) else {
            return Err(Failure::usage(
                "--id and --owner are required without --from",
            ));
        };
        let mut fields = Fields::new();
        let mut total = 0usize;
        for spec in &args.fields {
            let (name, source) = spec.split_once('=').ok_or_else(|| {
                Failure::usage(format!(
                    "--field {spec:?}: expected NAME=@PATH or NAME=env:VAR"
                ))
            })?;
            let mut value = files::secret_value(source)?;
            check_field(&fields, total, name, &value, spec)?;
            total = total.saturating_add(value.len());
            fields
                .insert(name, std::mem::take(&mut *value))
                .map_err(engine(&format!("field `{name}`")))?;
        }
        Record::seal(&key, id, owner, policy, &fields).map_err(engine("cannot seal"))?
    };
    files::write_json(&args.out, &record)?;
    eprintln!(
        "wrote record {} of {} at generation {} to {}",
        record.id,
        record.owner,
        record.generation,
        args.out.display()
    );
    Ok(())
}

/// Writes, sends or prints a document. Fails with the exit code of the status when the node
/// refused it.
fn deliver<T: Serialize>(value: &T, deliver: &Deliver, endpoint: &str) -> Res<()> {
    if let Some(out) = &deliver.out {
        files::write_json(out, value)?;
        eprintln!("wrote {}", out.display());
    }
    if let Some(url) = &deliver.send {
        let body = serde_json::to_vec(value).map_err(|e| format!("cannot encode JSON: {e}"))?;
        let reply = client::request(url, "POST", endpoint, Some(&body))?;
        println!("{}", String::from_utf8_lossy(&reply.body));
        return reply.check(url);
    }
    if deliver.out.is_none() {
        print!("{}", files::to_json(value)?);
    }
    Ok(())
}

fn pin(args: &PinArgs) -> Res<()> {
    let device = device_key(&args.device)?;
    let record: Record = files::read_json(&args.record)?;
    let pin = device.pin(&record).map_err(engine("cannot pin"))?;
    deliver(&pin, &args.deliver, "/pin")
}

fn grant(args: &GrantArgs) -> Res<()> {
    let device = device_key(&args.device)?;
    let key = user_key(&args.user_key)?;
    let node: NodeIdentity = files::read_json(&args.node)?;
    match (&args.attestation, &args.nonce, &args.measurements) {
        (Some(document), Some(nonce), Some(measurements)) => {
            let verified = attestation::check(document, nonce, measurements, Some(&node))?;
            eprintln!(
                "attestation verified: release {}, module {}, at {}; it vouches for the node identity",
                verified.release,
                verified.module_id,
                verify::rfc3339(verified.timestamp_ms)
            );
        }
        (None, None, None) => eprintln!(
            "warning: no --attestation given: nothing shows that the node runs an accepted release \
             (see `credentials attest --help`)"
        ),
        _ => {
            return Err(Failure::usage(
                "--attestation, --nonce and --measurements go together",
            ));
        }
    }
    let minutes = Duration::from_secs(args.valid.saturating_mul(60));
    let mut terms = GrantTerms::new(&args.owner, minutes);
    if args.no_successor {
        terms = terms.without_successor();
    }
    if args.pins.is_empty() {
        eprintln!(
            "warning: no --pin given: the node refuses every call on a record of {} until the \
             record is pinned (here with --pin <record>, or later with `credentials pin`)",
            args.owner
        );
    }
    for path in &args.pins {
        let record: Record = files::read_json(path)?;
        if record.owner != args.owner {
            return Err(Failure::usage(format!(
                "{}: the record belongs to {}, not {}",
                path.display(),
                record.owner,
                args.owner
            )));
        }
        terms = terms.pin(&record);
    }
    let sealed = device
        .grant(&key, &node, terms)
        .map_err(engine("cannot grant"))?;
    deliver(&sealed, &args.deliver, "/grant")
}

fn hand_over(args: &HandOverArgs) -> Res<()> {
    let read = |path: &Path| {
        std::fs::read(path).map_err(|e| Failure::io(format!("{}: {e}", path.display())))
    };
    let statement =
        continuity::SignedStatement::from_files(&read(&args.statement)?, &read(&args.bundle)?)
            .map_err(|e| Failure::usage(format!("{}: {e}", args.bundle.display())))?;
    match host::hand_over(args.from_cid, args.to_cid, &statement) {
        Ok(taken) => {
            eprintln!(
                "handed over: {} owners, {} grants; the old node refuses every act from now on",
                taken.owners, taken.grants
            );
            Ok(())
        }
        Err(host::HandOverError::Host(e @ host::Error::Unsupported)) => {
            Err(Failure::usage(e.to_string()))
        }
        Err(e) => Err(Failure::new(1, e.to_string())),
    }
}

fn revoke(args: &RevokeArgs) -> Res<()> {
    let device = device_key(&args.device)?;
    let node: NodeIdentity = files::read_json(&args.node)?;
    let revocation = device
        .revoke(&args.owner, &node.log_key, now_ms())
        .map_err(engine("cannot revoke"))?;
    deliver(&revocation, &args.deliver, "/revoke")
}

fn device_change(command: &DeviceCommand) -> Res<()> {
    let (DeviceCommand::Endorse(args) | DeviceCommand::Retire(args)) = command;
    let device = device_key(&args.device)?;
    let node: NodeIdentity = files::read_json(&args.node)?;
    let target = device_public_key(&args.target)?;
    match command {
        DeviceCommand::Endorse(_) => {
            let endorsement = device
                .endorse(&args.owner, &node.log_key, &target, now_ms())
                .map_err(engine("cannot endorse"))?;
            deliver(&endorsement, &args.deliver, "/device/add")
        }
        DeviceCommand::Retire(_) => {
            let retirement = device
                .retire(&args.owner, &node.log_key, &target, now_ms())
                .map_err(engine("cannot retire"))?;
            deliver(&retirement, &args.deliver, "/device/retire")
        }
    }
}

fn parse_method(text: &str) -> Res<Method> {
    serde_json::from_value(Value::String(text.to_ascii_uppercase()))
        .map_err(|_| Failure::usage(format!("{text}: not a method the engine knows")))
}

fn http_body(args: &HttpCallArgs) -> Res<Body> {
    let Some(method) = &args.method else {
        return Ok(Body::http_fixed());
    };
    let (Some(host), Some(path)) = (&args.host, &args.path) else {
        return Err(Failure::usage("--method needs --host and --path"));
    };
    let mut request = Request::new(
        parse_method(method)?,
        Destination::new(host, args.port),
        path,
    );
    for header in &args.headers {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| format!("--header {header:?}: expected 'Name: value'"))?;
        request
            .headers
            .push((name.trim().to_string(), value.trim().to_string()));
    }
    if let Some(body) = &args.body {
        request.body = files::data_value(body)?;
    }
    Ok(Body::http(request))
}

fn call(common: &CallCommon, body: Body) -> Res<()> {
    let key = caller_key(&common.caller_key)?;
    let node: NodeIdentity = files::read_json(&common.node)?;
    let record: Record = files::read_json(&common.record)?;
    let call = key
        .sign_call(
            &common.caller,
            &node.log_key,
            record,
            &common.operation,
            body,
        )
        .map_err(engine("cannot sign the call"))?;
    if let Some(out) = &common.deliver.out {
        files::write_json(out, &call)?;
        eprintln!("wrote {}", out.display());
    }
    let Some(url) = &common.deliver.send else {
        if common.deliver.out.is_none() {
            print!("{}", files::to_json(&call)?);
        }
        return Ok(());
    };
    let json = serde_json::to_vec(&call).map_err(|e| format!("cannot encode JSON: {e}"))?;
    let reply = client::request(url, "POST", "/call", Some(&json))?;
    println!("{}", String::from_utf8_lossy(&reply.body));
    if let Ok(answer) = serde_json::from_slice::<Value>(&reply.body) {
        if let Some(record) = answer.get("record").filter(|r| !r.is_null()) {
            let record: Record = serde_json::from_value(record.clone())
                .map_err(|e| format!("the node handed back a malformed record: {e}"))?;
            files::write_json(&common.record, &record)?;
            eprintln!(
                "the node sealed the record again: generation {} written to {}",
                record.generation,
                common.record.display()
            );
        }
    }
    reply.check(url)
}

fn node_identity(key: Option<&Path>, url: Option<&str>, out: Option<&Path>) -> Res<()> {
    let identity: NodeIdentity = match (key, url) {
        (Some(key), _) => {
            let key = serve::node_key(key)?;
            Node::new(key, serve::NoSink, SystemClock).identity()
        }
        (None, Some(url)) => {
            let reply = client::request(url, "GET", "/identity", None)?;
            reply.check(url)?;
            serde_json::from_slice(&reply.body)
                .map_err(|e| format!("{url}: not a node identity: {e}"))?
        }
        (None, None) => return Err(Failure::usage("give --key or --url")),
    };
    match out {
        Some(out) => files::write_json(out, &identity),
        None => {
            print!("{}", files::to_json(&identity)?);
            Ok(())
        }
    }
}

fn run(command: Command) -> Res<()> {
    match command {
        Command::Keygen { kind, out } => keygen(kind, &out),
        Command::Pubkey { kind, key } => pubkey(kind, &key),
        Command::Policy(PolicyCommand::Check { policy, device }) => {
            policy_check(&policy, device.as_deref())
        }
        Command::Policy(PolicyCommand::Sign {
            policy,
            device,
            out,
        }) => {
            let policy = read_policy(&policy)?;
            for line in policy.summary() {
                eprintln!("{line}");
            }
            let signed = device_key(&device)?
                .sign_policy(policy)
                .map_err(engine("cannot sign"))?;
            files::write_json(&out, &signed)?;
            eprintln!("wrote {}", out.display());
            Ok(())
        }
        Command::Policy(PolicyCommand::Upgrade { policy, out }) => {
            let text = std::fs::read_to_string(&policy)
                .map_err(|e| format!("cannot read {}: {e}", policy.display()))?;
            let upgraded = engine::policy::legacy::upgrade_json(&text)
                .map_err(|e| format!("{}: {e}", policy.display()))?;
            for note in &upgraded.notes {
                eprintln!("note: {note}");
            }
            if let Err(e) = upgraded.policy.validate() {
                eprintln!("note: the converted policy does not validate yet: {e}");
            }
            files::write_json(&out, &upgraded.policy)?;
            eprintln!("wrote {}", out.display());
            Ok(())
        }
        Command::Seal(args) => seal(&args),
        Command::Pin(args) => pin(&args),
        Command::Grant(args) => grant(&args),
        Command::Attest(args) => attestation::attest(
            &args.document,
            &args.nonce,
            &args.measurements,
            args.identity.as_deref(),
        ),
        Command::Revoke(args) => revoke(&args),
        Command::Device(command) => device_change(&command),
        Command::Call(CallCommand::Http(args)) => {
            let body = http_body(&args)?;
            call(&args.common, body)
        }
        Command::Call(CallCommand::Derive(args)) => {
            let input = files::data_value(&args.input)?;
            call(&args.common, Body::derive(&input))
        }
        Command::Serve(args) => serve::serve(&serve::Config {
            key: args.key,
            log: args.log,
            listen: args.listen,
            anchor: args.anchor,
            threads: args.threads,
            max_connections: args.max_connections,
            max_body: args.max_body,
        })
        // Whatever stops the server from starting or running is a key, log or socket
        // failure.
        .map_err(|e| Failure::io(e.message)),
        Command::Host(args) => host::run(&host::Config {
            listen: args.listen,
            enclave_cid: args.enclave_cid,
            http_port: args.http_port,
            egress_port: args.egress_port,
            log_port: args.log_port,
            log_dir: args.log_dir,
            allow: args.allow,
            max_connections: args.max_connections,
        })
        .map_err(|e| match e {
            host::Error::Unsupported => Failure::usage(e.to_string()),
            host::Error::Io { .. } => Failure::io(e.to_string()),
        }),
        Command::HandOver(args) => hand_over(&args),
        Command::Node(NodeCommand::Identity { key, url, out }) => {
            node_identity(key.as_deref(), url.as_deref(), out.as_deref())
        }
        Command::Verify { .. } => Ok(()),
    }
}

fn main() -> ExitCode {
    let command = Cli::parse().command;
    if let Command::Verify { args } = &command {
        return ExitCode::from(verify::run(args));
    }
    match run(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("error: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}
