//! Reads arbitrary bytes as a key backup blob, a transfer offer and a sealed transfer: none
//! opens without the right key or code, and nothing panics.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// A fixed backup key (32 bytes of 1, base64url).
const BACKUP_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = client::unwrap_keys(BACKUP_KEY.into(), "alice".into(), text.into());
    if let Ok(receiver) = client::join_transfer("123456".into(), text.into()) {
        let _ = receiver.answer();
        let _ = receiver.open(text.into());
    }
    let sender = client::start_transfer();
    if let Ok(sender) = sender
        && sender.offer().is_ok()
    {
        assert!(
            sender
                .seal(text.into(), "alice".into(), Vec::new())
                .is_err(),
            "a transfer sealed without keys"
        );
    }
});
