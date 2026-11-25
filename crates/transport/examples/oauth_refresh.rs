//! Refreshes an OAuth 2.0 access token; the caller never sees the client secret or a token.
//!
//! ```sh
//! OAUTH_HOST=oauth2.googleapis.com OAUTH_PATH=/token \
//! OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... OAUTH_REFRESH_TOKEN=... \
//!     cargo run -p transport --example oauth_refresh
//! ```
//!
//! The policy fixes the request: `POST https://<OAUTH_HOST><OAUTH_PATH>` with a form body the
//! node renders from the record. The node captures `access_token` (and a rotated
//! `refresh_token`, if the server sends one) from the JSON response into fields of the record,
//! seals the record again as a new generation, and hands the caller the response with the
//! captured values redacted. The caller must store the new record: the node now refuses the
//! old one.
//!
//! Without the variables, the example prints what it would do and sends nothing.

use std::time::Duration;

use engine::Error;
use engine::call::{Body, Output};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};
use engine::policy::{
    Caller, Capture, Destination, FieldSpec, Injection, Method, Operation, Policy, Receive, Return,
    Send, Source, Store,
};
use engine::record::Record;
use transport::TlsTransport;

const BODY: &str = "grant_type=refresh_token&refresh_token={{pct(refresh_token)}}\
                    &client_id={{pct(client_id)}}&client_secret={{pct(client_secret)}}";

fn policy(host: &str, path: &str, app: &CallerKey) -> Policy {
    Policy::new()
        .with_field(FieldSpec::public("client_id"))
        .with_field(FieldSpec::secret("client_secret"))
        .with_field(FieldSpec::secret("refresh_token"))
        .with_field(FieldSpec::secret("access_token").optional())
        .with_operation(
            Operation::https("refresh", Destination::https(host))
                .then(
                    Send::fixed(Method::Post, path)
                        .inject(Injection::header(
                            "Content-Type",
                            "application/x-www-form-urlencoded",
                        ))
                        .inject(Injection::body(BODY)),
                )
                .then(
                    Receive::response()
                        .capture(Capture::new(
                            Source::json("/access_token"),
                            Store::field("access_token"),
                        ))
                        .capture(
                            Capture::new(
                                Source::json("/refresh_token"),
                                Store::field("refresh_token"),
                            )
                            .optional(),
                        ),
                )
                .then(Return::status().json("/expires_in")),
        )
        .with_caller(Caller::new("app", app.public(), ["refresh"]).limit(10, 60_000))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("OAUTH_HOST").unwrap_or_else(|_| "auth.example.com".into());
    let path = std::env::var("OAUTH_PATH").unwrap_or_else(|_| "/oauth/token".into());
    let app = CallerKey::generate();
    let policy = policy(&host, &path, &app);
    policy.validate()?;
    for line in policy.summary() {
        println!("policy: {line}");
    }

    let secrets = [
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET",
        "OAUTH_REFRESH_TOKEN",
    ]
    .map(|name| std::env::var(name).ok());
    let [Some(client_id), Some(client_secret), Some(refresh_token)] = secrets else {
        println!(
            "would: POST https://{host}{path} with the refresh token, capture /access_token \
             into a new generation of the record, and refuse the old record afterwards"
        );
        println!(
            "set OAUTH_HOST, OAUTH_PATH, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET and \
             OAUTH_REFRESH_TOKEN to run it"
        );
        return Ok(());
    };

    // On the owner's device.
    let device = DeviceKey::generate();
    let user_key = UserKey::generate();
    let mut values = Fields::new();
    values.insert("client_id", client_id.into_bytes())?;
    values.insert("client_secret", client_secret.into_bytes())?;
    values.insert("refresh_token", refresh_token.into_bytes())?;
    let signed = device.sign_policy(policy)?;
    let record = Record::seal(&user_key, "oauth", "me", signed, &values)?;
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let terms = GrantTerms::new("me", Duration::from_secs(600)).pin(&record);
    node.grant(&device.grant(&user_key, &node.identity(), terms)?)?;

    // In the application: the request is the policy's; the call carries no request.
    let call = app.sign_call(
        "app",
        &node.public_key(),
        record.clone(),
        "refresh",
        Body::http_fixed(),
    )?;
    let outcome = node.run(&call, &mut TlsTransport::new());

    // The new record replaces the old one, even when the result is an error.
    let Some(new_record) = outcome.record else {
        outcome.result?;
        return Err("the response held no access token".into());
    };
    println!(
        "record generation {} -> {}: store this one (it is ciphertext, {} bytes as JSON)",
        record.generation,
        new_record.generation,
        serde_json::to_string(&new_record)?.len()
    );
    if let Output::Http(response) = outcome.result? {
        println!("status {}", response.status());
        println!("{}", String::from_utf8_lossy(response.body()));
    }

    // The old record is refused before the log and before the network.
    let stale = app.sign_call(
        "app",
        &node.public_key(),
        record,
        "refresh",
        Body::http_fixed(),
    )?;
    match node.run(&stale, &mut TlsTransport::new()).result {
        Err(error @ Error::RecordStale { .. }) => println!("the old record is refused: {error}"),
        other => return Err(format!("expected a stale record, got {other:?}").into()),
    }
    Ok(())
}
