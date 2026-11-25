//! Independent verifier of a node log.
//!
//! Usage: `verify <log.jsonl> <node-public-key>`. Every line of the file is one signed entry.
//! The tool checks the chain from its first entry and prints the hash of its head.

use std::process::ExitCode;
use std::{env, fs};

use engine::encoding::to_b64;
use engine::keys::NodePublicKey;
use engine::log::{SignedEntry, verify_chain};

fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let [path, key] = args.as_slice() else {
        return Err("usage: verify <log.jsonl> <node-public-key>".to_string());
    };
    let key = NodePublicKey::from_b64(key).map_err(|e| format!("node public key: {e}"))?;
    let text = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let entries = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str::<SignedEntry>(line).map_err(|e| format!("line {}: {e}", i + 1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let head = verify_chain(&entries, &key).map_err(|e| e.to_string())?;
    Ok(format!(
        "ok: {} entries, head {}",
        entries.len(),
        to_b64(&head)
    ))
}

fn main() -> ExitCode {
    match run() {
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
