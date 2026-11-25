//! Signs a JWT (RS256) with an RSA key the caller never sees.
//!
//! ```sh
//! JWT_KEY_FILE=service-account.pem JWT_CLAIMS='{"iss":"svc@example.iam","aud":"https://oauth2.example.com/token"}' \
//!     cargo run -p transport --example jwt_derive
//! ```
//!
//! An operation with no connection renders one template and hands its output back: here the
//! header, the claims the caller sends as `$input`, and an RS256 signature, each
//! base64url-encoded. The input schema bounds what the key signs: `iss` and `aud` are fixed,
//! `iat` and `exp` are written by the node from its clock (an hour of validity), and no other
//! member is accepted. The template is analysed before the policy is signed: the output carries a signature of the
//! key, never the key. A derivation sends nothing, so this example needs no network.
//!
//! `JWT_KEY_FILE` is a PKCS#8 PEM RSA private key. Without it, the example uses the public
//! test key of `crates/engine/tests/fixtures/rsa2048.pem`, which protects nothing.

use std::time::Duration;

use engine::call::{Body, Output};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};
use engine::policy::{
    Caller, FieldSpec, Input, JsonInput, JsonType, Member, NodeTime, Operation, Policy,
};
use engine::record::Record;
use transport::TlsTransport;

/// A key for this example only; it is public by being in the repository.
const TEST_KEY: &str = include_str!("../../engine/tests/fixtures/rsa2048.pem");

const DEFAULT_CLAIMS: &str =
    r#"{"iss":"svc@example.iam","aud":"https://oauth2.example.com/token"}"#;

fn policy(app: &CallerKey) -> Policy {
    let head = r#"b64urlraw("{\"alg\":\"RS256\",\"typ\":\"JWT\"}") + "." + b64urlraw($input)"#;
    let jwt =
        format!("{{{{ {head} + \".\" + b64urlraw(rsa_sign_pkcs1_sha256(pem(key), {head})) }}}}");
    Policy::new()
        .with_field(FieldSpec::secret("key"))
        .with_operation(Operation::derive("jwt", &jwt).input(Input::Json(JsonInput {
            members: vec![
                Member::equals("/iss", "svc@example.iam").of(JsonType::String),
                Member::equals("/aud", "https://oauth2.example.com/token").of(JsonType::String),
                Member::time("/iat", NodeTime::Unix, 0),
                Member::time("/exp", NodeTime::Unix, 3600),
            ],
        })))
        .with_caller(Caller::new("app", app.public(), ["jwt"]))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem = match std::env::var("JWT_KEY_FILE") {
        Ok(path) => std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?,
        Err(_) => {
            println!("JWT_KEY_FILE not set: using the public test key of the repository");
            TEST_KEY.as_bytes().to_vec()
        }
    };
    let claims = std::env::var("JWT_CLAIMS").unwrap_or_else(|_| DEFAULT_CLAIMS.into());

    // On the owner's device.
    let device = DeviceKey::generate();
    let user_key = UserKey::generate();
    let app = CallerKey::generate();
    let policy = policy(&app);
    for line in policy.summary() {
        println!("policy: {line}");
    }
    let mut values = Fields::new();
    values.insert("key", pem)?;
    let signed = device.sign_policy(policy)?;
    let record = Record::seal(&user_key, "signer", "me", signed, &values)?;
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let terms = GrantTerms::new("me", Duration::from_secs(600)).pin(&record);
    node.grant(&device.grant(&user_key, &node.identity(), terms)?)?;

    // In the application: it sends the claims and gets the signed token back.
    println!("signing claims {claims} with RS256");
    let body = Body::derive(claims.as_bytes());
    let call = app.sign_call("app", &node.public_key(), record, "jwt", body)?;
    // A derivation opens no connection; `run` takes a transport for the other kinds.
    let Output::Derive(token) = node.run(&call, &mut TlsTransport::new()).result? else {
        return Err("a derive operation hands back its output".into());
    };
    println!("{}", String::from_utf8(token)?);
    Ok(())
}
