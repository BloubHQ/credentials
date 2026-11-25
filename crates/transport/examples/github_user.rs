//! Calls `GET https://api.github.com/user` with a token the caller never sees.
//!
//! ```sh
//! GITHUB_TOKEN=ghp_... cargo run -p transport --example github_user
//! ```
//!
//! Everything happens in one process here, to show the parts: the device of the owner seals
//! the token into a record and grants a node; an application signs a call; the node writes the
//! log entry, adds the token and sends the request over TLS; the application gets the response,
//! checked for the token. In a deployment each part runs where it belongs (device, node in a
//! TEE, application elsewhere).
//!
//! The README quick start quotes lines of this file; `crates/engine/tests/readme.rs` checks
//! that they stay the same.

use std::alloc::System;
use std::process::ExitCode;
use std::time::Duration;

use engine::call::{Body, Output};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{MemorySink, open_detail, verify_chain};
use engine::node::{Node, SystemClock};
use engine::policy::{Caller, Destination, FieldSpec, Injection, Method, Operation, Policy, Step};
use engine::record::Record;
use engine::request::Request;
use transport::TlsTransport;
use zeroizing_alloc::ZeroAlloc;

/// Every freed heap block is erased, including the buffers of dependencies (TLS records,
/// parsed keys) the engine cannot reach.
#[global_allocator]
static ALLOCATOR: ZeroAlloc<System> = ZeroAlloc(System);

fn main() -> ExitCode {
    let Ok(token) = std::env::var("GITHUB_TOKEN") else {
        eprintln!("usage: GITHUB_TOKEN=<token> cargo run -p transport --example github_user");
        return ExitCode::from(2);
    };
    match run(token) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(token: String) -> Result<(), Box<dyn std::error::Error>> {
    // On the owner's device: its keys, the key of the application, and the policy.
    let device = DeviceKey::generate();
    let user_key = UserKey::generate();
    let app = CallerKey::generate();
    let policy = Policy::new()
        .with_field(FieldSpec::secret("token"))
        .with_operation(
            Operation::http("github", Destination::https("api.github.com"))
                .methods([Method::Get])
                .paths(["/user"])
                .caller_headers(["Accept", "User-Agent"])
                .step(
                    Step::caller().inject(Injection::header("Authorization", "Bearer {{token}}")),
                ),
        )
        .with_caller(Caller::new("example", app.public(), ["github"]));
    for line in policy.summary() {
        println!("policy: {line}");
    }
    let mut values = Fields::new();
    values.insert("token", token.into_bytes())?;

    // The node publishes its identity; owners grant to it.
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);

    // The application asks for GET /user.
    let mut request = Request::new(Method::Get, Destination::https("api.github.com"), "/user");
    request.headers = vec![
        ("Accept".into(), "application/vnd.github+json".into()),
        ("User-Agent".into(), "credentials-example".into()),
    ];

    // On the owner's device.
    let policy = device.sign_policy(policy)?;
    let record = Record::seal(&user_key, "github", "me", policy, &values)?;
    let terms = GrantTerms::new("me", Duration::from_secs(600)).pin(&record);
    let grant = device.grant(&user_key, &node.identity(), terms)?;

    // On the node.
    node.grant(&grant)?;

    // In the application: it holds the record (ciphertext) and its caller key, never the token.
    let body = Body::http(request);
    let call = app.sign_call("example", &node.public_key(), record, "github", body)?;

    // On the node: log, inject the token, send over TLS, check the response for the token.
    let outcome = node.run(&call, &mut TlsTransport::new());

    let Output::Http(response) = outcome.result? else {
        return Err("an HTTP operation hands back an HTTP response".into());
    };
    println!("status {}", response.status());
    println!("{}", String::from_utf8_lossy(response.body()));

    // The log: verified by anyone with the node key, details readable by the owner only.
    let entries = node.with_sink(|sink| sink.entries().to_vec());
    verify_chain(&entries, &node.public_key())?;
    for signed in &entries {
        println!("log entry: {}", serde_json::to_string(&signed.entry)?);
        if let Some(detail) = open_detail(&user_key, &signed.entry)? {
            println!(
                "  detail for the owner: {}",
                serde_json::to_string(&detail)?
            );
        }
    }
    Ok(())
}
