//! Browser fills (`docs/design.md`, section 6): a `browser` connection is a WebSocket to a
//! Chrome DevTools Protocol endpoint the policy fixes, and each `send` after its handshake is
//! a [`Fill`]: the node, not the caller, puts values into the fields of a page at the origin
//! the policy names, submits, and blanks what it filled when the page stays.
//!
//! What the policy fixes, and the caller cannot change: the endpoint (the `open`
//! destinations), the page's origin, the frame origin of each field, the selectors, the
//! values (templates), what submits, and how long the node waits. The caller chooses at most
//! the handshake path within its contract (which browser session), and gets back only the
//! outcome and the origin of the page at the end ([`crate::call::Output::Fill`]); it can
//! issue no CDP command through the node.

use serde::{Deserialize, Serialize};

use super::{Checked, Kinds, Policy, ensure, fail, path_fault};
use crate::cdp::WebOrigin;
use crate::template::Var;

/// Most fields one fill puts values into.
pub const MAX_FILL_FIELDS: usize = 16;
/// Most fills of one operation.
pub const MAX_FILLS: usize = 8;
/// Longest selector, in bytes.
pub const MAX_SELECTOR: usize = 256;
/// Longest path a fill navigates to, in bytes.
pub const MAX_NAVIGATE: usize = 2048;
/// Default and longest wait of a fill, in milliseconds: for an element to appear, and for the
/// page to leave after the submit.
pub const FILL_WAIT_MS: (u64, u64) = (5_000, 30_000);
/// Default and longest duration of a browser connection, in milliseconds.
pub const BROWSER_DURATION_MS: (u64, u64) = (60_000, 300_000);
/// Default idle time of a browser connection, in milliseconds (at most 120 s, as for any
/// open connection).
pub const BROWSER_IDLE_MS: u64 = 10_000;
/// Default byte count of a browser connection (both ways).
pub const BROWSER_BYTES: u64 = 16 << 20;

/// An element of the page: a CSS selector, in the top frame or in a child frame of an origin
/// the policy names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Element {
    /// A CSS selector (1 to 256 bytes of printable ASCII). It must match exactly one element
    /// of its frame. It is passed to the page as data, never as code.
    pub selector: String,
    /// The origin (`https://host[:port]`) of the frame the element is in: a frame that is a
    /// direct child of the top frame. Without it, the element is in the top frame. A summary
    /// flags a frame of another origin than the page's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<String>,
}

/// A field a fill puts a value into.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillField {
    /// A CSS selector, as for [`Element::selector`]: an `input` (not `hidden`) or a
    /// `textarea`.
    pub selector: String,
    /// The frame origin, as for [`Element::frame`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<String>,
    /// The value: a template over the fields and temporary values (secrets allowed). It must
    /// render to UTF-8.
    pub template: String,
}

impl FillField {
    /// The element the value goes into.
    pub fn element(&self) -> Element {
        Element {
            selector: self.selector.clone(),
            frame: self.frame.clone(),
        }
    }
}

/// A browser fill: the `send` of a `browser` connection after its handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fill {
    /// The origin of the page (`https://host[:port]`): the top frame must be there, from the
    /// choice of the page to the end of the fill.
    pub origin: String,
    /// A path on `origin` the node loads the page at before it fills, so that nothing a
    /// script planted in the document before (an earlier client of the browser, say) is
    /// still there. Without it the node fills the document as it finds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub navigate: Option<String>,
    /// The fields: 1 to 16.
    pub fields: Vec<FillField>,
    /// What submits: a form (`requestSubmit()`) or an element the node clicks.
    pub submit: Element,
    /// How long the node waits for each element to appear and for the page to leave after
    /// the submit, in milliseconds: default 5000, at most 30000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
}

impl Fill {
    /// The wait in force.
    pub fn wait(&self) -> u64 {
        self.wait_ms.unwrap_or(FILL_WAIT_MS.0)
    }

    /// The page's origin, parsed. A checked policy always has one.
    pub fn page(&self) -> Option<WebOrigin> {
        WebOrigin::parse(&self.origin)
    }

    /// True when a field or the submit is in a frame of another origin than the page.
    pub fn other_frames(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let frames = self
            .fields
            .iter()
            .filter_map(|f| f.frame.as_ref())
            .chain(self.submit.frame.as_ref());
        for frame in frames {
            if *frame != self.origin && !out.contains(frame) {
                out.push(frame.clone());
            }
        }
        out
    }
}

/// True for a selector the node passes to the page: 1 to 256 bytes of printable ASCII.
fn is_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector.len() <= MAX_SELECTOR
        && selector.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn check_element(at: &str, selector: &str, frame: Option<&String>) -> Checked {
    ensure(
        is_selector(selector),
        || format!("{at}.selector"),
        "a selector is 1 to 256 bytes of printable ASCII",
    )?;
    if let Some(frame) = frame {
        ensure(
            WebOrigin::parse(frame).is_some(),
            || format!("{at}.frame"),
            "a frame origin is https://host or https://host:port, lowercase, with no path",
        )?;
    }
    Ok(())
}

impl Policy {
    /// Checks a fill: its origin, elements, path, wait and templates.
    pub(super) fn check_fill(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        fill: &Fill,
        known: &[&str],
    ) -> Checked {
        ensure(
            WebOrigin::parse(&fill.origin).is_some(),
            || format!("{at}.origin"),
            "the page origin is https://host or https://host:port, lowercase, with no path",
        )?;
        if let Some(path) = &fill.navigate {
            ensure(
                path.len() <= MAX_NAVIGATE
                    && path_fault(path, false).is_none()
                    && !path.contains(['{', '}', '#']),
                || format!("{at}.navigate"),
                "navigate is a path of at most 2048 bytes: it starts with /, holds no dot segment, encoded separator, placeholder or fragment",
            )?;
        }
        ensure(
            fill.wait_ms.is_none_or(|w| w <= FILL_WAIT_MS.1),
            || format!("{at}.wait_ms"),
            "wait_ms is at most 30000",
        )?;
        ensure(
            !fill.fields.is_empty() && fill.fields.len() <= MAX_FILL_FIELDS,
            || format!("{at}.fields"),
            "a fill puts values into 1 to 16 fields",
        )?;
        for (i, field) in fill.fields.iter().enumerate() {
            let at = format!("{at}.fields[{i}]");
            check_element(&at, &field.selector, field.frame.as_ref())?;
            ensure(
                !fill
                    .fields
                    .iter()
                    .take(i)
                    .any(|f| f.element() == field.element()),
                || at.clone(),
                "each field of a fill is a different element",
            )?;
            self.check_template(
                &format!("{at}.template"),
                kinds,
                &field.template,
                known,
                Var::in_stream,
            )?;
        }
        check_element(
            &format!("{at}.submit"),
            &fill.submit.selector,
            fill.submit.frame.as_ref(),
        )
    }
}

/// Checks the bounds of the `limits` of a browser connection: those of any open connection,
/// and a duration of at most five minutes.
pub(super) fn check_browser_limits(at: &str, limits: &super::StreamLimits) -> Checked {
    if limits
        .duration_ms
        .is_some_and(|d| d > BROWSER_DURATION_MS.1)
    {
        return fail(
            format!("{at}.limits"),
            "a browser connection lasts at most 300000 ms",
        );
    }
    Ok(())
}

/// The limits in force on a browser connection: given ones, else the defaults of a fill.
pub fn browser_limits(limits: Option<&super::StreamLimits>) -> super::StreamLimits {
    let given = limits.copied().unwrap_or_default();
    super::StreamLimits {
        idle_ms: Some(given.idle_ms.unwrap_or(BROWSER_IDLE_MS)),
        duration_ms: Some(given.duration_ms.unwrap_or(BROWSER_DURATION_MS.0)),
        bytes: Some(given.bytes.unwrap_or(BROWSER_BYTES)),
    }
}
