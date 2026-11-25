//! Independent verifier of a node log.
//!
//! ```text
//! verify <log.jsonl> <node-public-key> [--head <signed-head.json>]
//! verify <log.jsonl> <node-public-key> --owner <owner> [--user-key <file>]
//! ```
//!
//! Every line of the file is one signed entry. The tool reads the file as a stream and checks
//! the chain from its first entry, then prints the number of entries and the hash of the head.
//! With `--head`, the chain must end exactly at that signed checkpoint of the node (a cut tail
//! is found). With `--owner`, the file holds only the entries of one owner, as a node hands them
//! to that owner, and the tool checks the chain of that owner. With `--user-key` (a file that
//! holds the user key of the owner as unpadded URL-safe base64), it also prints every entry
//! with its detail (where a value went), which only the owner can read.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use engine::encoding::{array_from_b64, to_b64};
use engine::keys::{NodePublicKey, UserKey};
use engine::log::{ChainVerifier, SignedEntry, SignedHead, open_detail, verify_owner_chain};

const USAGE: &str = "usage: verify <log.jsonl> <node-public-key> [--head <signed-head.json> | --owner <owner> [--user-key <file>]]";

enum Mode {
    Chain(Option<String>),
    Owner(String, Option<String>),
}

struct Args {
    path: String,
    key: String,
    mode: Mode,
}

fn parse(args: &[String]) -> Result<Option<Args>, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(None);
    }
    match args {
        [path, key] => Ok(Some(Args {
            path: path.clone(),
            key: key.clone(),
            mode: Mode::Chain(None),
        })),
        [path, key, flag, value] if flag == "--head" => Ok(Some(Args {
            path: path.clone(),
            key: key.clone(),
            mode: Mode::Chain(Some(value.clone())),
        })),
        [path, key, flag, value] if flag == "--owner" => Ok(Some(Args {
            path: path.clone(),
            key: key.clone(),
            mode: Mode::Owner(value.clone(), None),
        })),
        [path, key, flag, value, key_flag, key_file]
            if flag == "--owner" && key_flag == "--user-key" =>
        {
            Ok(Some(Args {
                path: path.clone(),
                key: key.clone(),
                mode: Mode::Owner(value.clone(), Some(key_file.clone())),
            }))
        }
        _ => Err(USAGE.to_string()),
    }
}

/// The entries of the file, one per non-empty line, with the line number of each.
fn entries(path: &str) -> Result<impl Iterator<Item = Result<SignedEntry, String>>, String> {
    let file = File::open(path).map_err(|e| format!("read {path}: {e}"))?;
    Ok(BufReader::new(file)
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let number = i + 1;
            match line {
                Err(e) => Some(Err(format!("line {number}: {e}"))),
                Ok(line) if line.trim().is_empty() => None,
                Ok(line) => Some(
                    serde_json::from_str::<SignedEntry>(&line)
                        .map_err(|e| format!("line {number}: {e}")),
                ),
            }
        }))
}

fn run(args: Args) -> Result<String, String> {
    let key = NodePublicKey::from_b64(&args.key).map_err(|e| format!("node public key: {e}"))?;
    match args.mode {
        Mode::Chain(head) => {
            let mut verifier = ChainVerifier::new(key);
            for entry in entries(&args.path)? {
                verifier.push(&entry?).map_err(|e| e.to_string())?;
            }
            if let Some(path) = head {
                let text =
                    std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
                let head: SignedHead =
                    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
                verifier
                    .matches(&head)
                    .map_err(|e| format!("signed head: {e}"))?;
            }
            Ok(format!(
                "ok: {} entries, head {}",
                verifier.len(),
                to_b64(&verifier.head())
            ))
        }
        Mode::Owner(owner, user_key) => {
            let all = entries(&args.path)?.collect::<Result<Vec<_>, _>>()?;
            let head = verify_owner_chain(&all, &owner, &key).map_err(|e| e.to_string())?;
            if let Some(file) = user_key {
                let text =
                    std::fs::read_to_string(&file).map_err(|e| format!("read {file}: {e}"))?;
                let mut bytes: [u8; 32] =
                    array_from_b64(text.trim()).map_err(|_| format!("{file}: not a user key"))?;
                let user_key = UserKey::from_bytes(&mut bytes);
                for signed in &all {
                    let detail = open_detail(&user_key, &signed.entry)
                        .map_err(|e| format!("seq {}: {e}", signed.entry.seq))?;
                    let line = serde_json::json!({ "entry": signed.entry, "detail": detail });
                    println!("{line}");
                }
            }
            Ok(format!(
                "ok: {} entries of {owner}, head {}",
                all.len(),
                to_b64(&head)
            ))
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse(&args) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    match run(parsed) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
