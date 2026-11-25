//! Calls AWS STS `GetCallerIdentity`, signed with AWS Signature Version 4 by the node.
//!
//! ```sh
//! AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... \
//!     cargo run -p transport --example aws_sigv4
//! ```
//!
//! SigV4 is two header templates in the policy (`X-Amz-Date` and `Authorization`); the engine
//! knows nothing of AWS. The signing key is derived from the secret key with nested
//! `hmac_sha256`, so the secret key never leaves the node. The caller may only send
//! `GET https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15`: the query is
//! part of the contract, each parameter pinned to its one value, so the same signature cannot
//! be spent on another action (such as one that mints temporary credentials). Only the
//! identity members of the response go back to the caller. Long-term keys only: temporary credentials would
//! also need a signed `X-Amz-Security-Token` header.
//!
//! Without the variables, the example prints what it would do and sends nothing.

use std::time::Duration;

use engine::call::{Body, Output};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};
use engine::policy::{
    Caller, CallerRequest, Destination, FieldSpec, Injection, Method, Operation, Policy, QueryRule,
    Return, Send,
};
use engine::record::Record;
use engine::request::Request;
use transport::TlsTransport;

const HOST: &str = "sts.amazonaws.com";
const REGION: &str = "us-east-1";
const SERVICE: &str = "sts";
const PATH: &str = "/?Action=GetCallerIdentity&Version=2011-06-15";

/// The two header templates of SigV4 (headers `host` and `x-amz-date` signed).
fn sigv4_headers() -> [Injection; 2] {
    let date = r#"time($unix, "%Y%m%d")"#;
    let stamp = r#"time($unix, "%Y%m%dT%H%M%SZ")"#;
    let scope = format!("{REGION}/{SERVICE}/aws4_request");
    let key = format!(
        r#"hmac_sha256(hmac_sha256(hmac_sha256(hmac_sha256("AWS4" + secret_key, {date}), "{REGION}"), "{SERVICE}"), "aws4_request")"#
    );
    let canonical = format!(
        r#"$method + "\n" + $pathname + "\n" + canonical_query($query) + "\nhost:" + $host + "\nx-amz-date:" + {stamp} + "\n\nhost;x-amz-date\n" + hex(sha256($body))"#
    );
    let to_sign = format!(
        r#""AWS4-HMAC-SHA256\n" + {stamp} + "\n" + {date} + "/{scope}\n" + hex(sha256({canonical}))"#
    );
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={{{{access_key}}}}/{{{{ {date} }}}}/{scope}, SignedHeaders=host;x-amz-date, Signature={{{{ hex(hmac_sha256({key}, {to_sign})) }}}}"
    );
    [
        Injection::header("X-Amz-Date", &format!("{{{{ {stamp} }}}}")),
        Injection::header("Authorization", &authorization),
    ]
}

fn policy(app: &CallerKey) -> Policy {
    let [date, authorization] = sigv4_headers();
    Policy::new()
        .with_field(FieldSpec::public("access_key"))
        .with_field(FieldSpec::secret("secret_key"))
        .with_operation(
            Operation::https("sts", Destination::https(HOST))
                .then(
                    Send::caller(
                        CallerRequest::new([Method::Get])
                            .paths(["/"])
                            .headers(["Accept"])
                            .query(QueryRule::fixed("Action", "GetCallerIdentity"))
                            .query(QueryRule::fixed("Version", "2011-06-15")),
                    )
                    .inject(date)
                    .inject(authorization),
                )
                .then(Return::status().json("/GetCallerIdentityResponse/GetCallerIdentityResult")),
        )
        .with_caller(Caller::new("app", app.public(), ["sts"]))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = CallerKey::generate();
    let policy = policy(&app);
    policy.validate()?;
    for line in policy.summary() {
        println!("policy: {line}");
    }
    let (Ok(access_key), Ok(secret_key)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) else {
        println!("would: GET https://{HOST}{PATH}, signed with SigV4 ({REGION}/{SERVICE})");
        println!("set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to run it");
        return Ok(());
    };

    // On the owner's device.
    let device = DeviceKey::generate();
    let user_key = UserKey::generate();
    let mut values = Fields::new();
    values.insert("access_key", access_key.into_bytes())?;
    values.insert("secret_key", secret_key.into_bytes())?;
    let signed = device.sign_policy(policy)?;
    let record = Record::seal(&user_key, "aws", "me", signed, &values)?;
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let terms = GrantTerms::new("me", Duration::from_secs(600)).pin(&record);
    node.grant(&device.grant(&user_key, &node.identity(), terms)?)?;

    // In the application.
    let mut request = Request::new(Method::Get, Destination::https(HOST), PATH);
    request.headers = vec![("Accept".into(), "application/json".into())];
    let call = app.sign_call(
        "app",
        &node.public_key(),
        record,
        "sts",
        Body::http(request),
    )?;
    let Output::Http(response) = node.run(&call, &mut TlsTransport::new()).result? else {
        return Err("an HTTP operation hands back an HTTP response".into());
    };
    println!("status {}", response.status());
    println!("{}", String::from_utf8_lossy(response.body()));
    Ok(())
}
