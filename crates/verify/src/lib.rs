//! Independent verifier of a node log, run as `credentials verify`.
//!
//! ```text
//! credentials verify <log.jsonl> <node-public-key> [--head <file>] [--owner <name>]
//!                    [--user-key <file>] [--next <log.jsonl>]... [--json]
//! ```
//!
//! Every line of the file is one signed entry. The verifier reads the file as a stream and
//! checks the chain from its first entry, then prints the number of entries and the hash of the
//! head. With `--head`, the chain must end exactly at that signed checkpoint of the node (a cut
//! tail is found). With `--owner`, the file holds only the entries of one owner, as a node hands
//! them to that owner (`engine::log::owner_entries`), and the verifier checks the chain of that
//! owner. With `--user-key` (a file that holds the user key of the owner as unpadded URL-safe
//! base64), it also prints every entry with its detail (where a value went), which only the
//! owner can read. With `--next`, the chain goes on in the log of the node the first one
//! handed over to (node continuity, `docs/design.md` section 10): one chain across nodes, the
//! key switching at each hand-over entry to the successor it names. `--help` lists every
//! option and the exit codes.
//!
//! [`run`] takes the arguments after `verify`, writes to stdout and stderr, and returns the
//! exit code.

use std::fs::File;
use std::io::{BufRead, BufReader};

use engine::encoding::to_b64;
use engine::keys::{NodePublicKey, UserKey};
use engine::log::{ChainVerifier, Event, SignedEntry, SignedHead, open_detail, verify_owner_chain};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Exit code of a valid log.
pub const EXIT_VALID: u8 = 0;
/// Exit code of an invalid log.
pub const EXIT_INVALID: u8 = 1;
/// Exit code of a usage error, or of a file or key that cannot be read.
pub const EXIT_USAGE: u8 = 2;

const USAGE: &str = "usage: credentials verify <log.jsonl> <node-public-key> [--head <file>] [--owner <name>] [--user-key <file>] [--next <log.jsonl>]... [--json]";

/// The help text of `credentials verify`.
pub const HELP: &str = "\
credentials verify: check the signed log of a credentials node, offline.

Usage:
  credentials verify <log.jsonl> <node-public-key> [options]

Arguments:
  <log.jsonl>          The log: one signed entry (JSON) per line. Blank lines are skipped.
  <node-public-key>    The log key of the node, unpadded URL-safe base64
                       (`credentials pubkey node --key <node key file>` prints it).

Options (in any order, before or after the arguments):
  --head <file>        The chain must end exactly at this signed checkpoint of the node
                       (Node::checkpoint), so a cut tail is found. With --owner, the
                       checkpoint must be signed by the node and cover every entry of
                       the file; when it goes past the owner's last entry, a cut tail
                       of the owner's chain cannot be found: a warning says so and
                       --json sets \"owner_tail_unchecked\": true.
  --owner <name>       The file holds the entries of one owner only, as a node hands
                       them to that owner; check the chain of that owner. An entry of
                       another owner is an error.
  --user-key <file>    With --owner: a file with the user key of the owner (unpadded
                       URL-safe base64). Every entry is printed with its detail (where
                       a value went, what was sent), one JSON object per line.
  --next <log.jsonl>   The log of the node this one handed over to (repeat it for each
                       later hand-over, in order). The chain goes on across the nodes:
                       the first log must end with a hand-over entry, the next must
                       start with the successor's continue entry naming its hash, and
                       the key switches to the successor's. Not with --owner. --head is
                       then a checkpoint of the last node.
  --json               Print the result as one JSON object on the last line of stdout:
                       {\"valid\": bool, \"entries\": n, \"head\": ..., \"owner\": ...,
                        \"checkpoint\": ..., \"owner_tail_unchecked\": bool,
                        \"hand_overs\": [...], \"error\": ...}
  -h, --help           Print this help.

Times are printed in milliseconds since the Unix epoch and as RFC 3339 UTC.

Examples:
  credentials verify log.jsonl <node-public-key>
  credentials verify log.jsonl <node-public-key> --head head.json
  credentials verify --owner alice alice.jsonl <node-public-key>
  credentials verify alice.jsonl <node-public-key> --owner alice --user-key key.txt --json
  credentials verify alice.jsonl <node-public-key> --head head.json --owner alice
  credentials verify old.jsonl <old-node-public-key> --next new.jsonl --head new-head.json

Exit codes:
  0  the log is valid
  1  the log is invalid (broken chain, bad signature, unreadable entry, cut tail,
     entry of another owner)
  2  usage error, or a file or key that cannot be read";

/// Said when the first entry does not verify: most often the key is not the right one.
const KEY_HINT: &str =
    "is this the node's log public key? `credentials pubkey node --key <node key file>` prints it";

/// What the command line asks for.
#[derive(Debug, Default)]
struct Options {
    log: String,
    node_key: String,
    head: Option<String>,
    owner: Option<String>,
    user_key: Option<String>,
    next: Vec<String>,
    json: bool,
}

/// Why the verifier stopped.
enum Failure {
    /// The command line or an input other than the log is wrong, or a file cannot be read.
    Usage(String),
    /// The log does not verify.
    Invalid(String),
}

impl Failure {
    fn code(&self) -> u8 {
        match self {
            Failure::Invalid(_) => EXIT_INVALID,
            Failure::Usage(_) => EXIT_USAGE,
        }
    }

    fn message(&self) -> &str {
        match self {
            Failure::Usage(m) | Failure::Invalid(m) => m,
        }
    }
}

/// Parses the arguments; `Ok(None)` asks for the help.
/// True for the shape of a key on the command line: 32 bytes in URL-safe base64 without
/// padding, 43 characters. No option name has that shape.
fn is_key(arg: &str) -> bool {
    arg.len() == 43
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn parse(args: &[String]) -> Result<Option<Options>, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(None);
    }
    let mut options = Options::default();
    let mut positional = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--" {
            positional.extend(rest.by_ref().cloned());
            break;
        }
        // Only `--name` is an option: keys are URL-safe base64 and may start with `-`, or
        // with `--` (one key in 4,096), which no option name has the shape of (#99).
        if !arg.starts_with("--") || is_key(arg) {
            positional.push(arg.clone());
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (arg.as_str(), None),
        };
        if name == "--json" {
            if inline.is_some() {
                return Err("--json takes no value".into());
            }
            options.json = true;
            continue;
        }
        let mut next = None;
        let slot = match name {
            "--next" => &mut next,
            "--head" => &mut options.head,
            "--owner" => &mut options.owner,
            "--user-key" => &mut options.user_key,
            _ => return Err(format!("unknown option {name}")),
        };
        let value = match inline {
            Some(value) => value,
            None => match rest.next() {
                Some(value) if !value.starts_with("--") || is_key(value) => value.clone(),
                _ => return Err(format!("{name} needs a value")),
            },
        };
        if value.is_empty() {
            return Err(format!("{name} needs a value"));
        }
        if slot.replace(value).is_some() {
            return Err(format!("{name} given twice"));
        }
        options.next.extend(next);
    }
    let mut positional = positional.into_iter();
    match (positional.next(), positional.next(), positional.next()) {
        (Some(log), Some(node_key), None) => {
            options.log = log;
            options.node_key = node_key;
        }
        (_, _, Some(extra)) => return Err(format!("unexpected argument {extra}")),
        _ => return Err("expected <log.jsonl> and <node-public-key>".into()),
    }
    if options.user_key.is_some() && options.owner.is_none() {
        return Err("--user-key needs --owner".into());
    }
    if !options.next.is_empty() && options.owner.is_some() {
        return Err("--next checks the whole chain across nodes: not with --owner".into());
    }
    Ok(Some(options))
}

/// The entries of the file, one per non-empty line, with the line number of each.
fn entries(
    path: &str,
) -> Result<impl Iterator<Item = Result<(usize, SignedEntry), Failure>>, Failure> {
    let file = File::open(path).map_err(|e| Failure::Usage(format!("read {path}: {e}")))?;
    Ok(BufReader::new(file)
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let number = i + 1;
            match line {
                Err(e) => Some(Err(Failure::Usage(format!("line {number}: {e}")))),
                Ok(line) if line.trim().is_empty() => None,
                Ok(line) => Some(
                    serde_json::from_str::<SignedEntry>(&line)
                        .map(|entry| (number, entry))
                        .map_err(|e| Failure::Invalid(format!("line {number}: {e}"))),
                ),
            }
        }))
}

fn read_head(path: &str) -> Result<SignedHead, Failure> {
    let text =
        std::fs::read_to_string(path).map_err(|e| Failure::Usage(format!("read {path}: {e}")))?;
    serde_json::from_str(&text)
        .map_err(|e| Failure::Usage(format!("{path}: not a signed head: {e}")))
}

/// What the verifier found, filled as it goes so a failure still reports how far it got.
#[derive(Default)]
struct Summary {
    entries: u64,
    head: Option<[u8; 32]>,
    checkpoint: Option<SignedHead>,
    /// With --owner and --head: the checkpoint goes past the last entry of the file, so
    /// later entries of the owner, cut from the file, would not be noticed.
    owner_tail_unchecked: bool,
    /// The hand-overs the chain went through.
    hand_overs: Vec<Value>,
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The message of a failed entry, with a hint when the first entry's signature fails.
fn entry_error(error: &engine::Error, first_seq: u64) -> String {
    match error {
        engine::Error::EntrySignature { seq } if *seq == first_seq => {
            format!("{error} ({KEY_HINT})")
        }
        _ => error.to_string(),
    }
}

/// Checks the whole chain of the node.
fn check_chain(
    options: &Options,
    key: NodePublicKey,
    summary: &mut Summary,
) -> Result<(), Failure> {
    let mut verifier = ChainVerifier::new(key);
    let files = std::iter::once(&options.log).chain(&options.next);
    for (index, path) in files.enumerate() {
        if index > 0 && !verifier.awaits_successor() {
            return Err(Failure::Invalid(format!(
                "{path}: the log before it does not end with a hand-over entry"
            )));
        }
        for item in entries(path)? {
            let (line, signed) = item?;
            verifier.push(&signed).map_err(|e| {
                let at = if options.next.is_empty() {
                    format!("line {line}")
                } else {
                    format!("{path}, line {line}")
                };
                Failure::Invalid(format!("{at}: {}", entry_error(&e, 0)))
            })?;
            if let Event::HandOver {
                successor,
                release,
                statement_sha256,
                owners,
                grants,
                ..
            } = &signed.entry.event
            {
                summary.hand_overs.push(json!({
                    "seq": signed.entry.seq,
                    "successor": successor.log_key.to_b64(),
                    "release": release,
                    "statement_sha256": hex(&statement_sha256[..]),
                    "owners": owners,
                    "grants": grants,
                }));
            }
            summary.entries = verifier.len();
        }
    }
    if verifier.awaits_successor() && !options.next.is_empty() {
        return Err(Failure::Invalid(
            "the last log ends with a hand-over: give the successor's log with --next, or leave \
             out the logs after the one that handed over"
                .into(),
        ));
    }
    summary.head = Some(verifier.head());
    if let Some(path) = &options.head {
        let head = read_head(path)?;
        verifier
            .matches(&head)
            .map_err(|e| Failure::Invalid(format!("signed head: {e}")))?;
        summary.checkpoint = Some(head);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Checks the chain of one owner and returns its entries.
fn check_owner(
    options: &Options,
    owner: &str,
    key: NodePublicKey,
    summary: &mut Summary,
) -> Result<Vec<SignedEntry>, Failure> {
    let mut all = Vec::new();
    for item in entries(&options.log)? {
        let (line, signed) = item?;
        if signed.entry.owner != owner {
            return Err(Failure::Invalid(format!(
                "entry {} (line {line}) belongs to owner {:?}, not {owner:?}",
                signed.entry.seq, signed.entry.owner
            )));
        }
        all.push(signed);
    }
    let first_seq = all.first().map_or(0, |signed| signed.entry.seq);
    let head = verify_owner_chain(&all, owner, &key)
        .map_err(|e| Failure::Invalid(entry_error(&e, first_seq)))?;
    summary.entries = count(all.len());
    summary.head = Some(head);
    if let Some(path) = &options.head {
        let checkpoint = read_head(path)?;
        checkpoint
            .verify(&key)
            .map_err(|e| Failure::Invalid(format!("signed head: {e}")))?;
        let covered = all
            .last()
            .map_or(0, |last| last.entry.seq.saturating_add(1));
        summary.owner_tail_unchecked = checkpoint.len > covered;
        if let Some(last) = all.last() {
            let seq = last.entry.seq;
            let after = seq.saturating_add(1);
            if checkpoint.len < after {
                return Err(Failure::Invalid(format!(
                    "signed head: it ends at {} entries, before entry {seq} of the file",
                    checkpoint.len
                )));
            }
            if checkpoint.len == after && checkpoint.head != head {
                return Err(Failure::Invalid(format!(
                    "signed head: its last entry is not entry {seq} of the file"
                )));
            }
        }
        summary.checkpoint = Some(checkpoint);
    }
    Ok(all)
}

/// The entries with their details, for the owner.
fn details(path: &str, entries: &[SignedEntry]) -> Result<Vec<Value>, Failure> {
    let text = std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| Failure::Usage(format!("read {path}: {e}")))?;
    let user_key =
        UserKey::from_b64(&text).map_err(|_| Failure::Usage(format!("{path}: not a user key")))?;
    entries
        .iter()
        .map(|signed| {
            let detail = open_detail(&user_key, &signed.entry).map_err(|e| {
                Failure::Usage(format!(
                    "entry {}: the user key does not open its detail ({e})",
                    signed.entry.seq
                ))
            })?;
            Ok(json!({ "entry": signed.entry, "detail": detail }))
        })
        .collect()
}

fn check(options: &Options, summary: &mut Summary) -> Result<Vec<Value>, Failure> {
    let key = NodePublicKey::from_b64(&options.node_key)
        .map_err(|e| Failure::Usage(format!("node public key: {e}")))?;
    match (&options.owner, &options.user_key) {
        (None, _) => check_chain(options, key, summary).map(|()| Vec::new()),
        (Some(owner), user_key) => {
            let all = check_owner(options, owner, key, summary)?;
            match user_key {
                Some(path) => details(path, &all),
                None => Ok(Vec::new()),
            }
        }
    }
}

/// Splits days since 1970-01-01 into a civil (proleptic Gregorian) year, month and day.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Milliseconds since the Unix epoch as RFC 3339 UTC, such as `2026-11-25T09:30:00.250Z`.
pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1_000;
    let millis = ms % 1_000;
    // At most u64::MAX / 86_400_000 (about 2.1e11) days, well inside i64.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

fn summary_json(options: &Options, summary: &Summary, error: Option<&str>) -> Value {
    json!({
        "valid": error.is_none(),
        "entries": summary.entries,
        "head": summary.head.as_ref().map(|h| to_b64(h)),
        "owner": options.owner,
        "checkpoint": summary.checkpoint.as_ref().map(|c| json!({
            "len": c.len,
            "time_ms": c.time_ms,
            "time": rfc3339(c.time_ms),
        })),
        "owner_tail_unchecked": summary.owner_tail_unchecked,
        "hand_overs": summary.hand_overs,
        "error": error,
    })
}

fn summary_text(options: &Options, summary: &Summary) -> String {
    let head = summary.head.as_ref().map(|h| to_b64(h)).unwrap_or_default();
    let mut text = match &options.owner {
        Some(owner) => format!("ok: {} entries of {owner}, head {head}", summary.entries),
        None => format!("ok: {} entries, head {head}", summary.entries),
    };
    for hand_over in &summary.hand_overs {
        text.push_str(&format!(
            ", handed over at entry {} to release {} (statement sha256 {})",
            hand_over["seq"], hand_over["release"], hand_over["statement_sha256"]
        ));
    }
    if let Some(checkpoint) = &summary.checkpoint {
        text.push_str(&format!(
            ", signed head of {} entries at {} ms ({})",
            checkpoint.len,
            checkpoint.time_ms,
            rfc3339(checkpoint.time_ms)
        ));
    }
    text
}

/// Runs the verifier on the arguments that follow `verify` on the command line. Writes the
/// result to stdout and errors to stderr, and returns the exit code: [`EXIT_VALID`],
/// [`EXIT_INVALID`] or [`EXIT_USAGE`].
pub fn run(args: &[String]) -> u8 {
    let options = match parse(args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{HELP}");
            return EXIT_VALID;
        }
        Err(message) => {
            eprintln!("error: {message}\n{USAGE}\n(see --help)");
            return EXIT_USAGE;
        }
    };
    let mut summary = Summary::default();
    let result = check(&options, &mut summary);
    if let Ok(lines) = &result {
        for line in lines {
            println!("{line}");
        }
    }
    let error = result.as_ref().err();
    if error.is_none()
        && summary.owner_tail_unchecked
        && let Some(checkpoint) = &summary.checkpoint
    {
        eprintln!(
            "warning: the signed head covers {} entries of the node, past the last entry of {} in the file: entries of that owner after it would not be noticed if they were cut (ask for a checkpoint taken right after the owner's last entry)",
            checkpoint.len,
            options.owner.as_deref().unwrap_or_default()
        );
    }
    if options.json {
        println!(
            "{}",
            summary_json(&options, &summary, error.map(Failure::message))
        );
    }
    match error {
        None => {
            if !options.json {
                println!("{}", summary_text(&options, &summary));
            }
            EXIT_VALID
        }
        Some(failure) => {
            eprintln!("error: {}", failure.message());
            failure.code()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_come_in_any_order() {
        let a = parse(&args(&[
            "--json",
            "--owner",
            "alice",
            "log",
            "--head=h.json",
            "key",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!((a.log.as_str(), a.node_key.as_str()), ("log", "key"));
        assert_eq!(a.owner.as_deref(), Some("alice"));
        assert_eq!(a.head.as_deref(), Some("h.json"));
        assert!(a.json);
        let b = parse(&args(&["log", "key", "--next", "n1", "--next=n2"]))
            .unwrap()
            .unwrap();
        assert_eq!(b.next, ["n1", "n2"]);
    }

    /// #99: one key in 4,096 starts with `--` in URL-safe base64; it is still a key, as a
    /// positional argument and as the value of an option.
    #[test]
    fn a_key_that_starts_with_two_dashes_is_a_key() {
        let key = format!("--{}", "A".repeat(41));
        let a = parse(&args(&["log", &key, "--next", "n1"]))
            .unwrap()
            .unwrap();
        assert_eq!(a.node_key, key);
        assert_eq!(a.next, ["n1"]);
        let b = parse(&args(&[
            "log",
            "key",
            "--owner",
            "alice",
            "--user-key",
            &key,
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(b.user_key.as_deref(), Some(key.as_str()));
        // A real node key with that start goes through the whole command.
        let node = loop {
            let k = engine::keys::NodeKey::generate();
            if k.public().to_b64().starts_with("--") {
                break k;
            }
        };
        let a = parse(&args(&["log", &node.public().to_b64()]))
            .unwrap()
            .unwrap();
        assert!(NodePublicKey::from_b64(&a.node_key).is_ok());
        // An unknown option of another shape is still refused.
        assert!(parse(&args(&["log", "key", "--nope"])).is_err());
    }

    #[test]
    fn bad_command_lines_are_refused() {
        for bad in [
            &["log"][..],
            &["log", "key", "extra"],
            &["log", "key", "--owner"],
            &["log", "key", "--owner", "--json"],
            &["log", "key", "--user-key", "k"],
            &["log", "key", "--owner", "a", "--owner", "b"],
            &["log", "key", "--wat"],
            &["log", "key", "--json=1"],
            &["log", "key", "--next"],
            &["log", "key", "--owner", "a", "--next", "n"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
        assert!(parse(&args(&["log", "-h"])).unwrap().is_none());
    }

    #[test]
    fn a_key_may_start_with_a_dash() {
        // URL-safe base64: one key in 64 starts with `-`.
        let options = parse(&args(&["log", "-Ab3", "--owner", "-x"]))
            .unwrap()
            .unwrap();
        assert_eq!(options.node_key, "-Ab3");
        assert_eq!(options.owner.as_deref(), Some("-x"));
        assert!(parse(&args(&["log", "-Ab3", "--json"])).unwrap().is_some());
    }

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(951_868_799_999), "2000-02-29T23:59:59.999Z");
        assert_eq!(rfc3339(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(rfc3339(4_102_444_800_000), "2100-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
        // The largest time does not panic.
        assert!(rfc3339(u64::MAX).ends_with('Z'));
    }
}
