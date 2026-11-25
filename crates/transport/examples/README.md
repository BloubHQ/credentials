# Examples

Each example is one program that plays every part in one process: the owner's device seals
the secrets into a record and grants a node, an application signs a call
(`CallerKey::sign_call`), and the node runs it (`Node::run`) through the TLS transport. In a
deployment each part runs where it belongs.

Run one with:

```sh
cargo run -p transport --example <name>
```

Secrets come from environment variables and are never printed. An example that needs the
network prints its policy and what it would do, and sends nothing, until its variables are
set.

| Example | What it shows | Environment | Network |
| --- | --- | --- | --- |
| [`github_user`](github_user.rs) | A bearer token injected into `GET https://api.github.com/user`; the log and the owner's details. The README quick start quotes this file. | `GITHUB_TOKEN` (required) | yes |
| [`oauth_refresh`](oauth_refresh.rs) | A fixed `POST` to a token endpoint; `json` captures into fields; the new record from `Outcome::record` replaces the old one, which is then refused. | `OAUTH_HOST`, `OAUTH_PATH`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_REFRESH_TOKEN` | yes, when set |
| [`aws_sigv4`](aws_sigv4.rs) | AWS Signature Version 4 as two header templates; calls STS `GetCallerIdentity`. Long-term keys only. | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | yes, when set |
| [`jwt_derive`](jwt_derive.rs) | A derive operation that signs an RS256 JWT with a PEM key. | `JWT_KEY_FILE` (PKCS#8 PEM; default: the public test key in `crates/engine/tests/fixtures`), `JWT_CLAIMS` (optional JSON) | no |
| [`imap_stream`](imap_stream.rs) | A stream operation: the node logs into IMAP (port 993), then the caller runs `NOOP` and `LOGOUT` on the connection. | `IMAP_HOST`, `IMAP_USER`, `IMAP_PASSWORD` | yes, when set |
| [`node_restore`](node_restore.rs) | A checkpoint, a restart with `Node::restore_anchored`, a saved grant and an old call refused, a cut log refused, and the owner checking its own entries. | none | no |

The owner can check the log of a node offline with `credentials verify` (see `--help`):

```sh
credentials verify log.jsonl <node-public-key> --head head.json
credentials verify alice.jsonl <node-public-key> --owner alice --user-key key.txt --json
```
