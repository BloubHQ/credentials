//! Reads arbitrary bytes as what reaches a node about operations that wait: a sealed answer to
//! a challenge (`POST /answer`), an approval (`POST /approve`), spending limits
//! (`POST /limits`), a pending operation and a resume call; and as the code a device seals.
//! Each must be taken or refused with an error, never a panic, and a node with nothing
//! waiting takes no answer and no approval.

#![no_main]

use engine::Error;
use engine::approval::Approval;
use engine::call::SignedCall;
use engine::keys::{DeviceKey, NodeKey};
use engine::limits::SpendingLimits;
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};
use engine::session::{Pending, SealedAnswer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A fixed key keeps runs reproducible.
    let node = Node::new(
        NodeKey::from_bytes(&mut [9u8; 32]),
        MemorySink::new(),
        SystemClock,
    );
    if let Ok(sealed) = serde_json::from_slice::<SealedAnswer>(data) {
        assert!(node.answer(&sealed).is_err());
    }
    if let Ok(approval) = serde_json::from_slice::<Approval>(data) {
        assert_eq!(node.approve(&approval), Err(Error::ParkedUnknown));
    }
    if let Ok(limits) = serde_json::from_slice::<SpendingLimits>(data) {
        let _ = limits.validate();
        assert!(node.set_limits(&limits).is_err(), "no grant, no limits");
    }
    if let Ok(pending) = serde_json::from_slice::<Pending>(data) {
        let text = serde_json::to_string(&pending).unwrap_or_default();
        assert_eq!(serde_json::from_str::<Pending>(&text).ok(), Some(pending));
    }
    if let Ok(call) = serde_json::from_slice::<SignedCall>(data) {
        let _ = node.run(&call, &mut NoNetwork).result;
    }
    // The bytes as a code: sealed by a device to this node, which has no such challenge.
    let device = DeviceKey::from_bytes(&mut [7u8; 32]);
    let code = data.get(..data.len().min(300)).unwrap_or_default();
    match device.answer_challenge(&node.identity(), "alice", [1; 16], code, 0) {
        Ok(sealed) => assert!(node.answer(&sealed).is_err()),
        Err(error) => assert!(matches!(error, Error::AnswerInvalid { .. })),
    }
});

/// Sends nothing: no grant is in force, so no call gets that far.
struct NoNetwork;

impl engine::egress::Transport for NoNetwork {
    fn send(
        &mut self,
        _: &engine::policy::Destination,
        _: Option<&engine::egress::ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        Err(Error::RateLimited)
    }
}
