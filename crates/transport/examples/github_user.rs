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

use std::alloc::System;

use engine::caller::Payload;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{MemorySink, open_detail, verify_chain};
use engine::node::{Clock, Node, SystemClock};
use engine::policy::{
    Caller, Destination, FieldSpec, Injection, Method, Operation, Policy, Step, StepRequest,
};
use engine::record::Record;
use engine::request::Request;
use transport::TlsTransport;
use zeroizing_alloc::ZeroAlloc;

/// Every freed heap block is erased, including the buffers of dependencies (TLS records,
/// parsed keys) the engine cannot reach.
#[global_allocator]
static ALLOCATOR: ZeroAlloc<System> = ZeroAlloc(System);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("GITHUB_TOKEN").map_err(|_| "set GITHUB_TOKEN")?;

    // On the device of the owner.
    let device = DeviceKey::generate();
    let user_key = UserKey::generate();
    let app = CallerKey::generate();
    let policy = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![Caller {
            name: "example".into(),
            key: app.public(),
            operations: vec!["github".into()],
            limit: None,
        }],
        operations: vec![Operation::Http {
            name: "github".into(),
            destinations: vec![Destination::https("api.github.com")],
            methods: vec![Method::Get],
            paths: vec!["/user".into()],
            caller_headers: vec!["Accept".into(), "User-Agent".into()],
            identity: None,
            steps: vec![Step {
                request: StepRequest::Caller,
                inject: vec![Injection::header("Authorization", "Bearer {{token}}")],
                capture: vec![],
            }],
        }],
    };
    for line in policy.summary() {
        println!("policy: {line}");
    }
    let mut values = Fields::new();
    values.insert("token", token.into_bytes())?;
    let record = Record::seal(
        &user_key,
        "github",
        "me",
        device.sign_policy(policy)?,
        &values,
    )?;

    // The node publishes its identity; the device seals a grant to it.
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let now = SystemClock.now_ms();
    let grant = device.grant(
        &user_key,
        &node.identity(),
        GrantTerms {
            owner: "me".into(),
            expires_ms: now + 10 * 60 * 1000,
            issued_ms: now,
            pins: vec![RecordPin {
                record_id: "github".into(),
                generation: record.generation,
            }],
        },
    )?;
    node.grant(&grant)?;

    // The application asks for GET /user.
    let mut request = Request::new(Method::Get, Destination::https("api.github.com"), "/user");
    request.headers = vec![
        ("Accept".into(), "application/vnd.github+json".into()),
        ("User-Agent".into(), "credentials-example".into()),
    ];
    let auth = app.authorize(
        "example",
        &node.public_key(),
        &record,
        "github",
        &Payload::Http(Some(&request)),
        SystemClock.now_ms(),
    )?;
    let mut transport = TlsTransport::new();
    let response = node
        .http(&record, "github", &auth, Some(&request), &mut transport)
        .result?;
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
