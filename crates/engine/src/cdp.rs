//! The Chrome DevTools Protocol (CDP), as much of it as a browser fill needs: the commands the
//! node writes and a strict reader of what the browser answers.
//!
//! CDP is JSON over a WebSocket. A command is `{"id": n, "method": "...", "params": {...}}`,
//! with `"sessionId"` when it goes to a page the connection attached to; the browser answers
//! with the same `id` and either `result` or `error`, and sends events
//! (`{"method": "...", "params": {...}}`) whenever a domain is enabled.
//!
//! The node issues a fixed set of commands ([`Method`]) and never `Runtime.evaluate`: the
//! only code it runs in a page is the four functions of this module ([`FIND`], [`FILL`],
//! [`SUBMIT`], [`CLEAR`]), called with `Runtime.callFunctionOn` in an isolated world of its
//! own, with the policy's selector, origins and the value as arguments (data, never code).
//!
//! The reader ([`parse`]) takes one message and tells an answer from an event. An event's
//! parameters are skipped unread, so nothing a page put there is kept; an answer's `result`
//! stays a borrowed slice of the message, read by the typed readers ([`targets`],
//! [`frame_tree`], [`session_id`], [`context_id`], [`remote`], [`navigated`]), each bounded
//! (ids, URLs, counts and the depth of the frame tree). Duplicate members, a message that is
//! both an answer and an event, and ids or URLs with control characters are refused.

use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// Largest CDP message the node reads, in bytes.
pub const MAX_MESSAGE: usize = 4 << 20;
/// Most targets a `Target.getTargets` answer may list.
pub const MAX_TARGETS: usize = 1024;
/// Most frames of a page.
pub const MAX_FRAMES: usize = 256;
/// Deepest frame tree (the top frame is depth 0).
pub const MAX_DEPTH: usize = 32;
/// Longest id (target, session, frame, loader, remote object).
pub const MAX_ID: usize = 256;
/// Longest URL the node reads.
pub const MAX_URL: usize = 8192;
/// Longest method name of an event.
const MAX_METHOD: usize = 256;

/// The name of the isolated world the node's functions run in.
pub const WORLD: &str = "credentials-fill";
/// The object group the node's remote objects belong to, released at the end.
pub const GROUP: &str = "credentials-fill";

/// Finds the one element `selector` matches in the frame, after checking that the frame is
/// at `origin` and its ancestors at `ancestors` (`location.ancestorOrigins`, nearest first).
/// Returns the element, `null` when nothing matches, or a reason: `origin`, `ancestors`,
/// `many`.
pub const FIND: &str = "function credentialsFind(selector, origin, ancestors) {\n  \"use strict\";\n  if (location.origin !== origin) return \"origin\";\n  var a = location.ancestorOrigins, i;\n  if (!a || a.length !== ancestors.length) return \"ancestors\";\n  for (i = 0; i < a.length; i++) if (a[i] !== ancestors[i]) return \"ancestors\";\n  var all = document.querySelectorAll(selector);\n  if (all.length === 0) return null;\n  if (all.length !== 1) return \"many\";\n  return all[0];\n}";

/// Sets the value of the element it is called on (an `input` other than `hidden`, or a
/// `textarea`) with the native setter of this world, then dispatches `input` and `change`.
/// Checks the frame's origin and ancestors again in the same task, so no navigation can come
/// between the check and the value. Returns `ok` or a reason: `origin`, `ancestors`,
/// `detached`, `kind`.
pub const FILL: &str = "function credentialsFill(value, origin, ancestors) {\n  \"use strict\";\n  if (location.origin !== origin) return \"origin\";\n  var a = location.ancestorOrigins, i, p;\n  if (!a || a.length !== ancestors.length) return \"ancestors\";\n  for (i = 0; i < a.length; i++) if (a[i] !== ancestors[i]) return \"ancestors\";\n  if (!this.isConnected || this.ownerDocument !== document) return \"detached\";\n  if (this instanceof HTMLInputElement) { if (this.type === \"hidden\") return \"kind\"; p = HTMLInputElement.prototype; }\n  else if (this instanceof HTMLTextAreaElement) p = HTMLTextAreaElement.prototype;\n  else return \"kind\";\n  Object.getOwnPropertyDescriptor(p, \"value\").set.call(this, value);\n  this.dispatchEvent(new Event(\"input\", {bubbles: true}));\n  this.dispatchEvent(new Event(\"change\", {bubbles: true}));\n  return \"ok\";\n}";

/// Submits: `requestSubmit()` on a form, `click()` on any other element, after the same
/// checks as [`FILL`]. Returns `ok` or a reason.
pub const SUBMIT: &str = "function credentialsSubmit(origin, ancestors) {\n  \"use strict\";\n  if (location.origin !== origin) return \"origin\";\n  var a = location.ancestorOrigins, i;\n  if (!a || a.length !== ancestors.length) return \"ancestors\";\n  for (i = 0; i < a.length; i++) if (a[i] !== ancestors[i]) return \"ancestors\";\n  if (!this.isConnected || this.ownerDocument !== document) return \"detached\";\n  if (this instanceof HTMLFormElement) { this.requestSubmit(); return \"ok\"; }\n  if (this instanceof HTMLElement) { this.click(); return \"ok\"; }\n  return \"kind\";\n}";

/// Blanks the element it is called on (no event: the page is not asked to react), after the
/// same checks as [`FILL`]. Returns `ok` or a reason.
pub const CLEAR: &str = "function credentialsClear(origin, ancestors) {\n  \"use strict\";\n  if (location.origin !== origin) return \"origin\";\n  var a = location.ancestorOrigins, i, p;\n  if (!a || a.length !== ancestors.length) return \"ancestors\";\n  for (i = 0; i < a.length; i++) if (a[i] !== ancestors[i]) return \"ancestors\";\n  if (!this.isConnected || this.ownerDocument !== document) return \"detached\";\n  if (this instanceof HTMLInputElement) p = HTMLInputElement.prototype;\n  else if (this instanceof HTMLTextAreaElement) p = HTMLTextAreaElement.prototype;\n  else return \"kind\";\n  Object.getOwnPropertyDescriptor(p, \"value\").set.call(this, \"\");\n  return \"ok\";\n}";

/// Why a CDP message was refused. The text is fixed: nothing of the message is in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CdpError {
    /// The message is not what the protocol or the node's bounds allow; the text says how.
    #[error("CDP message invalid: {0}")]
    Invalid(&'static str),
    /// The message, or a list in it, is larger than the node reads.
    #[error("CDP message too large")]
    TooLarge,
}

fn invalid<T>(rule: &'static str) -> Result<T, CdpError> {
    Err(CdpError::Invalid(rule))
}

/// The commands the node issues. There is no other way to write one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `Target.getTargets`.
    GetTargets,
    /// `Target.attachToTarget` (flattened sessions).
    AttachToTarget,
    /// `Target.detachFromTarget`.
    DetachFromTarget,
    /// `Page.navigate`.
    Navigate,
    /// `Page.getFrameTree`.
    GetFrameTree,
    /// `Page.createIsolatedWorld`.
    CreateIsolatedWorld,
    /// `Runtime.callFunctionOn`.
    CallFunctionOn,
    /// `Runtime.releaseObjectGroup`.
    ReleaseObjectGroup,
}

impl Method {
    /// The method name on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::GetTargets => "Target.getTargets",
            Method::AttachToTarget => "Target.attachToTarget",
            Method::DetachFromTarget => "Target.detachFromTarget",
            Method::Navigate => "Page.navigate",
            Method::GetFrameTree => "Page.getFrameTree",
            Method::CreateIsolatedWorld => "Page.createIsolatedWorld",
            Method::CallFunctionOn => "Runtime.callFunctionOn",
            Method::ReleaseObjectGroup => "Runtime.releaseObjectGroup",
        }
    }
}

/// Writes `text` as a JSON string (quotes included) into `out`, which is zeroized when
/// dropped: the value of a fill passes through here.
pub fn push_json_string(out: &mut Zeroizing<Vec<u8>>, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for byte in text.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            // Control characters, and `<`, `>`, `&` escaped too, so the text never reads as
            // markup wherever a log or a proxy shows it.
            0x00..=0x1f | b'<' | b'>' | b'&' | 0x7f => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
                out.push(HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0'));
            }
            other => out.push(other),
        }
    }
    out.push(b'"');
}

/// One command, as the bytes of a text message: `{"id":..,"method":..,"sessionId":..,
/// "params":..}`. `params` is a JSON object the node wrote.
pub fn command(
    id: u64,
    method: Method,
    session: Option<&str>,
    params: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(params.len() + 128));
    out.extend_from_slice(b"{\"id\":");
    out.extend_from_slice(id.to_string().as_bytes());
    out.extend_from_slice(b",\"method\":");
    push_json_string(&mut out, method.as_str());
    if let Some(session) = session {
        out.extend_from_slice(b",\"sessionId\":");
        push_json_string(&mut out, session);
    }
    out.extend_from_slice(b",\"params\":");
    out.extend_from_slice(params);
    out.push(b'}');
    out
}

/// One message from the browser.
#[derive(Debug)]
pub enum Incoming<'a> {
    /// The answer to the command `id`, sent to `session` (none for the browser itself).
    Answer {
        /// The id of the command.
        id: u64,
        /// The session of the command, when it went to an attached target.
        session: Option<&'a str>,
        /// `result` as raw JSON, or the code of `error`.
        result: Result<&'a str, i64>,
    },
    /// An event; its parameters were skipped unread.
    Event {
        /// The method, such as `Page.frameNavigated`.
        method: &'a str,
        /// The session it came from.
        session: Option<&'a str>,
    },
}

#[derive(Deserialize)]
struct Wire<'a> {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default, borrow)]
    method: Option<&'a str>,
    #[serde(default, rename = "sessionId", borrow)]
    session_id: Option<&'a str>,
    #[serde(default, borrow)]
    result: Option<&'a RawValue>,
    #[serde(default)]
    error: Option<WireError>,
    #[serde(default)]
    params: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct WireError {
    code: i64,
    // The message may echo what the command carried: it is skipped unread.
    #[serde(default)]
    #[allow(dead_code)]
    message: Option<IgnoredAny>,
    #[serde(default)]
    #[allow(dead_code)]
    data: Option<IgnoredAny>,
}

/// True for 1 to `max` bytes of visible ASCII (an id).
fn is_id(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Reads one message. `bytes` is one text message of the WebSocket.
pub fn parse(bytes: &[u8]) -> Result<Incoming<'_>, CdpError> {
    if bytes.len() > MAX_MESSAGE {
        return Err(CdpError::TooLarge);
    }
    let wire: Wire<'_> =
        serde_json::from_slice(bytes).map_err(|_| CdpError::Invalid("not a CDP JSON object"))?;
    if let Some(session) = wire.session_id
        && !is_id(session, MAX_ID)
    {
        return invalid("session id");
    }
    match (wire.id, wire.method) {
        (Some(id), None) => {
            if wire.params.is_some() {
                return invalid("an answer with params");
            }
            let result = match (wire.result, wire.error) {
                (Some(result), None) => Ok(result.get()),
                (None, Some(error)) => Err(error.code),
                _ => return invalid("an answer has either result or error"),
            };
            Ok(Incoming::Answer {
                id,
                session: wire.session_id,
                result,
            })
        }
        (None, Some(method)) => {
            if wire.result.is_some() || wire.error.is_some() {
                return invalid("an event with result or error");
            }
            if !is_id(method, MAX_METHOD) {
                return invalid("event method");
            }
            Ok(Incoming::Event {
                method,
                session: wire.session_id,
            })
        }
        _ => invalid("a message is an answer (id) or an event (method)"),
    }
}

/// A target of the browser (`Target.TargetInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Its id.
    pub id: String,
    /// `page`, `iframe`, `worker`, ...
    pub kind: String,
    /// Its URL.
    pub url: String,
    /// True when a client is attached to it.
    pub attached: bool,
}

#[derive(Deserialize)]
struct TargetsWire {
    #[serde(rename = "targetInfos")]
    target_infos: Vec<TargetWire>,
}

#[derive(Deserialize)]
struct TargetWire {
    #[serde(rename = "targetId")]
    target_id: String,
    #[serde(rename = "type")]
    kind: String,
    url: String,
    attached: bool,
}

fn check_url(url: &str) -> Result<(), CdpError> {
    if url.len() > MAX_URL || url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return invalid("URL");
    }
    Ok(())
}

/// The targets of a `Target.getTargets` result.
pub fn targets(result: &str) -> Result<Vec<Target>, CdpError> {
    let wire: TargetsWire = serde_json::from_str(result)
        .map_err(|_| CdpError::Invalid("not a Target.getTargets result"))?;
    if wire.target_infos.len() > MAX_TARGETS {
        return Err(CdpError::TooLarge);
    }
    wire.target_infos
        .into_iter()
        .map(|t| {
            if !is_id(&t.target_id, MAX_ID) || !is_id(&t.kind, 64) {
                return invalid("target id or type");
            }
            check_url(&t.url)?;
            Ok(Target {
                id: t.target_id,
                kind: t.kind,
                url: t.url,
                attached: t.attached,
            })
        })
        .collect()
}

#[derive(Deserialize)]
struct SessionWire {
    #[serde(rename = "sessionId")]
    session_id: String,
}

/// The session id of a `Target.attachToTarget` result.
pub fn session_id(result: &str) -> Result<String, CdpError> {
    let wire: SessionWire = serde_json::from_str(result)
        .map_err(|_| CdpError::Invalid("not a Target.attachToTarget result"))?;
    if !is_id(&wire.session_id, MAX_ID) {
        return invalid("session id");
    }
    Ok(wire.session_id)
}

/// A frame of a page (`Page.Frame`), with its parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Its id.
    pub id: String,
    /// The id of its parent; `None` for the top frame.
    pub parent: Option<String>,
    /// The id of the loader of its current document: it changes on every navigation.
    pub loader: String,
    /// The URL of its document.
    pub url: String,
    /// The security origin the browser reports, when it does.
    pub security_origin: Option<String>,
    /// Its depth: 0 for the top frame.
    pub depth: usize,
}

#[derive(Deserialize)]
struct FrameTreeResult {
    #[serde(rename = "frameTree")]
    frame_tree: FrameTreeWire,
}

#[derive(Deserialize)]
struct FrameTreeWire {
    frame: FrameWire,
    #[serde(default, rename = "childFrames")]
    child_frames: Vec<FrameTreeWire>,
}

#[derive(Deserialize)]
struct FrameWire {
    id: String,
    #[serde(default, rename = "parentId")]
    parent_id: Option<String>,
    #[serde(rename = "loaderId")]
    loader_id: String,
    url: String,
    #[serde(default, rename = "securityOrigin")]
    security_origin: Option<String>,
}

/// The frames of a `Page.getFrameTree` result, top frame first, each after its parent. A
/// frame whose `parentId` is not the frame it is listed under, a repeated id, more than
/// [`MAX_FRAMES`] frames or a tree deeper than [`MAX_DEPTH`] is refused.
pub fn frame_tree(result: &str) -> Result<Vec<Frame>, CdpError> {
    let wire: FrameTreeResult = serde_json::from_str(result)
        .map_err(|_| CdpError::Invalid("not a Page.getFrameTree result"))?;
    let mut out: Vec<Frame> = Vec::new();
    let mut queue: Vec<(FrameTreeWire, Option<String>, usize)> = vec![(wire.frame_tree, None, 0)];
    while let Some((node, parent, depth)) = queue.pop() {
        if depth > MAX_DEPTH {
            return Err(CdpError::TooLarge);
        }
        if out.len() >= MAX_FRAMES {
            return Err(CdpError::TooLarge);
        }
        let frame = node.frame;
        if !is_id(&frame.id, MAX_ID) || !is_id(&frame.loader_id, MAX_ID) {
            return invalid("frame or loader id");
        }
        check_url(&frame.url)?;
        if let Some(origin) = &frame.security_origin {
            check_url(origin)?;
        }
        if frame.parent_id != parent {
            return invalid("a frame's parentId is not the frame it is listed under");
        }
        if out.iter().any(|f| f.id == frame.id) {
            return invalid("a frame id is listed twice");
        }
        for child in node.child_frames.into_iter().rev() {
            queue.push((child, Some(frame.id.clone()), depth + 1));
        }
        out.push(Frame {
            id: frame.id,
            parent,
            loader: frame.loader_id,
            url: frame.url,
            security_origin: frame.security_origin,
            depth,
        });
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ContextWire {
    #[serde(rename = "executionContextId")]
    execution_context_id: i64,
}

/// The execution context of a `Page.createIsolatedWorld` result.
pub fn context_id(result: &str) -> Result<i64, CdpError> {
    let wire: ContextWire = serde_json::from_str(result)
        .map_err(|_| CdpError::Invalid("not a Page.createIsolatedWorld result"))?;
    Ok(wire.execution_context_id)
}

/// What a function call returned (`Runtime.RemoteObject`), as far as the node reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Remote {
    /// An object (an element), by its id.
    Object(String),
    /// A string: a reason, or `ok`.
    Text(String),
    /// `null` or `undefined`.
    Nothing,
    /// A thrown exception (its details unread), or any other value.
    Other,
}

#[derive(Deserialize)]
struct CallWire<'a> {
    #[serde(borrow)]
    result: RemoteWire<'a>,
    #[serde(default, rename = "exceptionDetails")]
    exception_details: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct RemoteWire<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(default)]
    subtype: Option<&'a str>,
    #[serde(default, rename = "objectId")]
    object_id: Option<String>,
    #[serde(default, borrow)]
    value: Option<&'a RawValue>,
}

/// Longest string a function of the node returns.
const MAX_TEXT: usize = 16;

/// The result of a `Runtime.callFunctionOn`. Only short strings are read (the node's
/// functions return `ok` or a reason word); anything longer is [`Remote::Other`].
pub fn remote(result: &str) -> Result<Remote, CdpError> {
    let wire: CallWire<'_> = serde_json::from_str(result)
        .map_err(|_| CdpError::Invalid("not a Runtime.callFunctionOn result"))?;
    if wire.exception_details.is_some() {
        return Ok(Remote::Other);
    }
    let r = wire.result;
    Ok(match (r.kind, r.subtype) {
        ("object", Some("null")) | ("undefined", _) => Remote::Nothing,
        ("object", _) => match r.object_id {
            Some(id) if is_id(&id, MAX_ID) => Remote::Object(id),
            _ => return invalid("remote object id"),
        },
        ("string", _) => {
            let text = r
                .value
                .map(RawValue::get)
                .and_then(|raw| serde_json::from_str::<&str>(raw).ok());
            match text {
                Some(t) if t.len() <= MAX_TEXT && t.bytes().all(|b| b.is_ascii_lowercase()) => {
                    Remote::Text(t.to_string())
                }
                _ => Remote::Other,
            }
        }
        _ => Remote::Other,
    })
}

#[derive(Deserialize)]
struct NavigateWire {
    #[serde(rename = "frameId")]
    frame_id: String,
    #[serde(default, rename = "loaderId")]
    loader_id: Option<String>,
    #[serde(default, rename = "errorText")]
    error_text: Option<IgnoredAny>,
}

/// What a `Page.navigate` result says: the frame, the new loader (none for a navigation
/// within the document), and whether it failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Navigated {
    /// The frame navigated.
    pub frame: String,
    /// The loader of the new document.
    pub loader: Option<String>,
    /// True when the browser reported an error.
    pub failed: bool,
}

/// Reads a `Page.navigate` result.
pub fn navigated(result: &str) -> Result<Navigated, CdpError> {
    let wire: NavigateWire = serde_json::from_str(result)
        .map_err(|_| CdpError::Invalid("not a Page.navigate result"))?;
    if !is_id(&wire.frame_id, MAX_ID)
        || wire.loader_id.as_deref().is_some_and(|l| !is_id(l, MAX_ID))
    {
        return invalid("frame or loader id");
    }
    Ok(Navigated {
        frame: wire.frame_id,
        loader: wire.loader_id,
        failed: wire.error_text.is_some(),
    })
}

/// A web origin: `https`, a host and a port. Only `https` origins exist here: a fill never
/// goes into a page without TLS.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebOrigin {
    /// The host: lowercase labels of `a-z 0-9 -`, as a browser writes it (an internationalized
    /// name in its `xn--` form).
    pub host: String,
    /// The port.
    pub port: u16,
}

fn is_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl WebOrigin {
    /// Parses an origin as a policy writes it: exactly `https://host` or `https://host:port`,
    /// with no path, user or trailing slash.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("https://")?;
        Self::authority(rest)
    }

    /// The origin of a URL a browser reports: `None` unless it is an `https` URL with a host
    /// (no user part, no IP literal in brackets).
    pub fn of_url(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("https://")?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        Self::authority(rest.get(..end)?)
    }

    fn authority(authority: &str) -> Option<Self> {
        if authority.contains('@') {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                if port.is_empty()
                    || port.len() > 5
                    || !port.bytes().all(|b| b.is_ascii_digit())
                    || port.starts_with('0')
                {
                    return None;
                }
                (host, port.parse::<u16>().ok()?)
            }
            None => (authority, 443),
        };
        (is_host(host) && port != 0).then(|| WebOrigin {
            host: host.to_string(),
            port,
        })
    }

    /// The origin as a browser serializes it (`location.origin`): the port only when it is
    /// not 443.
    pub fn serialize(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    #[test]
    fn answers_and_events_are_told_apart() {
        let answer = parse(br#"{"id":3,"sessionId":"S1","result":{"a":1}}"#).unwrap();
        assert!(matches!(
            answer,
            Incoming::Answer { id: 3, session: Some("S1"), result: Ok(r) } if r == r#"{"a":1}"#
        ));
        let error = parse(br#"{"id":4,"error":{"code":-32000,"message":"x"}}"#).unwrap();
        assert!(matches!(
            error,
            Incoming::Answer {
                id: 4,
                result: Err(-32000),
                ..
            }
        ));
        let event = parse(br#"{"method":"Page.frameNavigated","params":{"x":"y"}}"#).unwrap();
        assert!(matches!(
            event,
            Incoming::Event {
                method: "Page.frameNavigated",
                session: None
            }
        ));
    }

    #[test]
    fn ambiguous_messages_are_refused() {
        for bad in [
            &br#"{"id":1,"method":"X","result":{}}"#[..],
            br#"{"id":1}"#,
            br#"{"id":1,"result":{},"error":{"code":1}}"#,
            br#"{"id":1,"id":2,"result":{}}"#,
            br#"{"method":"X","result":{}}"#,
            br#"{"id":1,"result":{},"params":{}}"#,
            br#"{"id":1,"sessionId":"a b","result":{}}"#,
            br#"[1]"#,
            b"{",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert_eq!(
            parse(&vec![b' '; MAX_MESSAGE + 1]).unwrap_err(),
            CdpError::TooLarge
        );
    }

    #[test]
    fn frame_trees_are_checked() {
        let tree = r#"{"frameTree":{"frame":{"id":"F","loaderId":"L","url":"https://a.example/x"},
            "childFrames":[{"frame":{"id":"C","parentId":"F","loaderId":"L2","url":"https://b.example/"}}]}}"#;
        let frames = frame_tree(tree).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].parent.as_deref(), Some("F"));
        assert_eq!(frames[1].depth, 1);
        let lying = tree.replace("\"parentId\":\"F\"", "\"parentId\":\"Z\"");
        assert!(frame_tree(&lying).is_err());
        let twice = tree.replace("\"id\":\"C\"", "\"id\":\"F\"");
        assert!(frame_tree(&twice).is_err());
        let mut deep =
            String::from(r#"{"frame":{"id":"f0","loaderId":"l","url":"https://a.example/"}}"#);
        for i in 1..=MAX_DEPTH + 1 {
            deep = format!(
                r#"{{"frame":{{"id":"f{i}","loaderId":"l","url":"https://a.example/"}},"childFrames":[{}]}}"#,
                deep.replace(
                    &format!("\"id\":\"f{}\"", i - 1),
                    &format!("\"id\":\"f{}\",\"parentId\":\"f{i}\"", i - 1)
                )
            );
        }
        assert_eq!(
            frame_tree(&format!(r#"{{"frameTree":{deep}}}"#)).unwrap_err(),
            CdpError::TooLarge
        );
    }

    #[test]
    fn remote_values() {
        assert_eq!(
            remote(r#"{"result":{"type":"object","subtype":"node","objectId":"1.2.3"}}"#).unwrap(),
            Remote::Object("1.2.3".into())
        );
        assert_eq!(
            remote(r#"{"result":{"type":"string","value":"ok"}}"#).unwrap(),
            Remote::Text("ok".into())
        );
        assert_eq!(
            remote(r#"{"result":{"type":"object","subtype":"null","value":null}}"#).unwrap(),
            Remote::Nothing
        );
        assert_eq!(
            remote(
                r#"{"result":{"type":"string","value":"a much longer string than any reason"}}"#
            )
            .unwrap(),
            Remote::Other
        );
        assert_eq!(
            remote(r#"{"result":{"type":"string","value":"ok"},"exceptionDetails":{}}"#).unwrap(),
            Remote::Other
        );
    }

    #[test]
    fn origins() {
        let o = WebOrigin::parse("https://login.example.com").unwrap();
        assert_eq!(o.port, 443);
        assert_eq!(o.serialize(), "https://login.example.com");
        assert_eq!(
            WebOrigin::of_url("https://login.example.com:8443/a?b#c")
                .unwrap()
                .serialize(),
            "https://login.example.com:8443"
        );
        for bad in [
            "http://login.example.com",
            "https://login.example.com/",
            "https://user@login.example.com",
            "https://Login.example.com",
            "https://[::1]",
            "https://login.example.com:0",
            "https://login.example.com:080",
            "https://",
        ] {
            assert_eq!(WebOrigin::parse(bad), None, "{bad}");
        }
        assert_eq!(WebOrigin::of_url("about:blank"), None);
        assert_eq!(WebOrigin::of_url("https://a@b.example/"), None);
    }

    #[test]
    fn strings_are_escaped() {
        let mut out = Zeroizing::new(Vec::new());
        push_json_string(&mut out, "a\"b\\c\n<");
        assert_eq!(out.as_slice(), br#""a\"b\\c\u000a\u003c""#);
        let parsed: String = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed, "a\"b\\c\n<");
    }
}
