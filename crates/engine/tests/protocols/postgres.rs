//! PostgreSQL: TLS required, SCRAM-SHA-256 only, queries bound, rows projected and searched.

use engine::policy::FieldSpec;
use serde_json::{Value, json};

use super::fake_pg::{PgAuth, PgServer};
use super::*;

const PASSWORD: &[u8] = b"s3cret-db-pass";

fn pg_operation(limits: Value) -> Operation {
    operation(json!({"name": "db", "steps": [
        {"do": "open", "connection": "postgres",
         "destinations": [{"host": "db.example.com", "port": 5432}],
         "login": {"user": "app", "password": "{{password}}", "database": "shop"},
         "limits": limits},
        {"do": "return", "relay": {"commands": [
            {"name": "order", "text": "SELECT id, total, secret_note FROM orders WHERE id = $1",
             "params": [{"pattern": "[0-9]{1,9}"}], "columns": ["id", "total"]},
            {"name": "find", "text": "SELECT id FROM orders WHERE note = $1",
             "params": [{"max_len": 64}]},
            {"name": "notes", "text": "SELECT note FROM notes"}
        ]}}
    ]}))
}

fn pg_setup(limits: Value) -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![pg_operation(limits)],
    )
}

fn pg_server() -> PgServer {
    let mut server = PgServer::new(PASSWORD);
    server.answer = |sql, params| {
        if sql.starts_with(b"SELECT id, total") {
            Ok((
                vec!["id", "total", "secret_note"],
                vec![vec![
                    Some(params[0].clone()),
                    Some(b"12.50".to_vec()),
                    Some(b"internal".to_vec()),
                ]],
            ))
        } else if sql.starts_with(b"SELECT note") {
            Ok((
                vec!["note"],
                vec![vec![Some(b"remember s3cret-db-pass".to_vec())]],
            ))
        } else if params.first().is_some_and(|p| p == b"boom") {
            Err(("42601", "syntax error".into()))
        } else {
            Ok((vec!["id"], vec![vec![None]]))
        }
    };
    server
}

/// A transport whose plain prelude answers `S` (TLS taken).
fn fake(server: PgServer) -> Fake<PgServer> {
    let mut fake = Fake::new(server);
    fake.plain.push_back(b"S".to_vec());
    fake
}

fn run(
    s: &Setup,
    fake: &mut Fake<PgServer>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "db",
        session("db.example.com", 5432, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

#[test]
fn scram_sign_in_and_a_bound_query_with_projected_columns() {
    let s = pg_setup(json!({}));
    let mut fake = fake(pg_server());
    let out = session_output(run(&s, &mut fake, vec![command("order", &["42"])]));
    assert!(out.error.is_none());
    assert_eq!(fake.opened, ["starttls"]);
    assert_eq!(fake.plain_written, [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]);
    let rows: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(
        rows,
        json!({"columns": ["id", "total"], "rows": [["42", "12.50"]], "tag": "SELECT 1"})
    );
    assert_eq!(out.results[0].status, Some(0));
    assert!(fake.peer.signed_in);
    assert!(
        !holds(&fake.peer.received, PASSWORD),
        "no password on the wire"
    );
    assert_eq!(last_closed(&s), (true, "done".into()));
}

#[test]
fn sql_injection_through_a_parameter_stays_a_value() {
    let s = pg_setup(json!({}));
    let mut fake = fake(pg_server());
    let evil = "x'; DROP TABLE orders; --";
    let out = session_output(run(&s, &mut fake, vec![command("find", &[evil])]));
    assert!(out.error.is_none());
    let (sql, params) = &fake.peer.queries[0];
    assert_eq!(sql, b"SELECT id FROM orders WHERE note = $1");
    assert_eq!(params, &[evil.as_bytes().to_vec()]);
}

#[test]
fn a_query_outside_its_shape_is_refused_before_anything_is_written() {
    let s = pg_setup(json!({}));
    for commands in [
        vec![command("drop", &[])],
        vec![command("order", &["1 OR 1=1"])],
        vec![command("order", &[])],
        vec![command("find", &[&"x".repeat(65)])],
    ] {
        let mut fake = fake(pg_server());
        let result = run(&s, &mut fake, commands);
        assert!(matches!(result, Err(engine::Error::RequestInvalid { .. })));
        assert!(fake.opened.is_empty());
    }
}

#[test]
fn a_server_without_tls_or_injecting_before_tls_is_refused() {
    let s = pg_setup(json!({}));
    let mut no_tls = Fake::new(pg_server());
    no_tls.plain.push_back(b"N".to_vec());
    let result = run(&s, &mut no_tls, vec![command("order", &["1"])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(no_tls.peer.received.is_empty(), "nothing sent");

    let mut injecting = fake(pg_server());
    injecting.plain_extra = b"R\0\0\0\x08\0\0\0\0".to_vec();
    let result = run(&s, &mut injecting, vec![command("order", &["1"])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(injecting.peer.received.is_empty(), "nothing sent");
}

#[test]
fn every_mechanism_weaker_than_scram_is_refused() {
    let s = pg_setup(json!({}));
    for auth in [
        PgAuth::Cleartext,
        PgAuth::Md5,
        PgAuth::OkFirst,
        PgAuth::BadSignature,
        PgAuth::FewIterations,
    ] {
        let mut server = pg_server();
        server.auth = auth;
        let mut fake = fake(server);
        let result = run(&s, &mut fake, vec![command("order", &["1"])]);
        assert!(
            matches!(result, Err(engine::Error::ServerUntrusted { .. })),
            "downgrade refused"
        );
        assert!(!holds(&fake.peer.received, PASSWORD), "password never sent");
        assert!(fake.peer.queries.is_empty(), "no query ran");
    }
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    let s = pg_setup(json!({}));
    let mut fake = fake(PgServer::new(b"another"));
    let result = run(&s, &mut fake, vec![command("order", &["1"])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
}

#[test]
fn a_secret_in_a_row_never_goes_back() {
    let s = pg_setup(json!({}));
    let mut fake = fake(pg_server());
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("order", &["7"]), command("notes", &[])],
    ));
    assert_eq!(out.results.len(), 1);
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
    assert!(out.results.iter().all(|r| !holds(&r.data, PASSWORD)));
    assert_eq!(last_closed(&s), (false, "reflection".into()));
}

#[test]
fn a_server_error_is_a_result_not_a_failure() {
    let s = pg_setup(json!({}));
    let mut fake = fake(pg_server());
    let out = session_output(run(&s, &mut fake, vec![command("find", &["boom"])]));
    assert!(out.error.is_none());
    assert_eq!(out.results[0].status, Some(1));
    let body: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(body["error"]["code"], "42601");
}

#[test]
fn the_byte_limit_ends_the_connection() {
    let s = pg_setup(json!({"bytes": 300}));
    let mut fake = fake(pg_server());
    let result = run(
        &s,
        &mut fake,
        vec![
            command("order", &["1"]),
            command("order", &["2"]),
            command("order", &["3"]),
        ],
    );
    let budget = match result {
        Err(engine::Error::Budget { .. }) => true,
        Ok(Output::Session(out)) => matches!(out.error, Some(engine::Error::Budget { .. })),
        _ => false,
    };
    assert!(budget, "bytes limit");
}

#[test]
fn an_approved_session_runs_the_commands_it_was_signed_with() {
    same_after_approval(
        &pg_setup(json!({})),
        "db",
        session(
            "db.example.com",
            5432,
            vec![command("order", &["42"])],
            Vec::new(),
        ),
        || fake(pg_server()),
    );
}
