//! Reads arbitrary bytes as what reaches a node about owner controls: a delegation with its
//! record (`POST /delegate`), a delegation change (`POST /delegation/change`), and a delegated
//! policy checked against itself; and as the expiry a vending operation reads, in every
//! format. Each must be taken or refused with an error, never a panic, and a node with no
//! grant and no device takes no delegation and no change.

#![no_main]

use engine::delegation::{DelegationChange, DelegationRequest, check_narrower};
use engine::keys::NodeKey;
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};
use engine::policy::Policy;
use engine::policy::vend::{TimeFormat, parse_rfc3339, parse_time};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_800_000_000_000;

fuzz_target!(|data: &[u8]| {
    // A fixed key keeps runs reproducible.
    let node = Node::new(
        NodeKey::from_bytes(&mut [9u8; 32]),
        MemorySink::new(),
        SystemClock,
    );
    if let Ok(request) = serde_json::from_slice::<DelegationRequest>(data) {
        let _ = request.delegation.validate();
        assert!(
            node.delegate(&request.delegation, &request.record).is_err(),
            "no device is known, so no delegation"
        );
    }
    if let Ok(change) = serde_json::from_slice::<DelegationChange>(data) {
        assert!(node.change_delegation(&change).is_err());
    }
    // Never a panic; a policy that captures into a field is refused with an error.
    if let Ok(policy) = serde_json::from_slice::<Policy>(data)
        && policy.validate().is_ok()
    {
        let _ = check_narrower(&policy, &policy);
    }
    // The bytes as an expiry.
    if let Some(ms) = parse_rfc3339(data) {
        assert_eq!(parse_time(data, TimeFormat::Rfc3339, NOW), Some(ms));
    }
    for format in [TimeFormat::Unix, TimeFormat::UnixMs] {
        let _ = parse_time(data, format, NOW);
    }
    if let Some(ms) = parse_time(data, TimeFormat::Seconds, NOW) {
        assert!(ms >= NOW, "a duration ends at or after now");
    }
});
