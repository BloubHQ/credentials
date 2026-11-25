//! Logs into an IMAP server with a password the caller never sees, then runs the caller's
//! commands on the authenticated connection.
//!
//! ```sh
//! IMAP_HOST=imap.example.com IMAP_USER=me@example.com IMAP_PASSWORD=... \
//!     cargo run -p transport --example imap_stream
//! ```
//!
//! A TLS operation is a send/receive script on one TLS connection (port 993 here): wait for
//! the greeting, send `a1 LOGIN` with the values of the record, read the tagged answer. Then
//! the caller's exchanges run on the same connection (`a2 NOOP`, `a3 LOGOUT`): its `return`
//! relays only sends that match one of its patterns whole, here `NOOP`, `LOGOUT` and
//! `CAPABILITY`, so the caller cannot use the session for anything else. Each read is
//! checked for the password before it goes back. The script does not quote the values, so a
//! user name or password with spaces or quotes needs a different template.
//!
//! Without the variables, the example prints what it would do and connects nowhere.

use std::time::Duration;

use engine::call::{Body, Output};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{CallerExchange, Node, SystemClock};
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy, Receive, Return, Send};
use engine::record::Record;
use transport::TlsTransport;

const PORT: u16 = 993;

fn policy(host: &str, app: &CallerKey) -> Policy {
    Policy::new()
        .with_field(FieldSpec::public("user"))
        .with_field(FieldSpec::secret("password"))
        .with_operation(
            Operation::tls("imap", Destination::new(host, PORT))
                .then(Receive::until(["\r\n"]))
                .then(Send::write("a1 LOGIN {{user}} {{password}}\r\n"))
                .then(Receive::until(["a1 OK", "a1 NO", "a1 BAD"]))
                .then(Return::relay([r"a[0-9]{1,4} (NOOP|LOGOUT|CAPABILITY)\r\n"])),
        )
        .with_caller(Caller::new("app", app.public(), ["imap"]))
}

/// One command of the caller, read up to its tagged answer.
fn command(tag: &str, line: &str) -> CallerExchange {
    CallerExchange {
        send: format!("{tag} {line}\r\n").into_bytes(),
        until: ["OK", "NO", "BAD"]
            .iter()
            .map(|status| format!("{tag} {status}").into_bytes())
            .collect(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("IMAP_HOST").unwrap_or_else(|_| "imap.example.com".into());
    let app = CallerKey::generate();
    let policy = policy(&host, &app);
    policy.validate()?;
    for line in policy.summary() {
        println!("policy: {line}");
    }
    let (Ok(user), Ok(password)) = (std::env::var("IMAP_USER"), std::env::var("IMAP_PASSWORD"))
    else {
        println!("would: connect to {host}:{PORT}, log in, then run a2 NOOP and a3 LOGOUT");
        println!("set IMAP_HOST, IMAP_USER and IMAP_PASSWORD to run it");
        return Ok(());
    };

    // On the owner's device.
    let device = DeviceKey::generate();
    let user_key = UserKey::generate();
    let mut values = Fields::new();
    values.insert("user", user.into_bytes())?;
    values.insert("password", password.into_bytes())?;
    let signed = device.sign_policy(policy)?;
    let record = Record::seal(&user_key, "mail", "me", signed, &values)?;
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let terms = GrantTerms::new("me", Duration::from_secs(600)).pin(&record);
    node.grant(&device.grant(&user_key, &node.identity(), terms)?)?;

    // In the application: its own commands, after the node logged in.
    let body = Body::Stream {
        destination: Destination::new(&host, PORT),
        exchanges: vec![command("a2", "NOOP"), command("a3", "LOGOUT")],
    };
    let call = app.sign_call("app", &node.public_key(), record, "imap", body)?;
    let Output::Stream(output) = node.run(&call, &mut TlsTransport::new()).result? else {
        return Err("a stream operation hands back its reads".into());
    };
    for read in &output.reads {
        print!("{}", String::from_utf8_lossy(read));
    }
    println!();
    if let Some(error) = output.error {
        return Err(format!("the exchanges stopped: {error}").into());
    }
    Ok(())
}
