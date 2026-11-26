//! Browser fills (`docs/design.md`, section 6): the node connects to the CDP endpoint the
//! policy fixes, over TLS, and puts the values into the page itself.
//!
//! Why the node connects, and the caller does not relay: CDP carries the value of a fill in
//! the clear inside its WebSocket. Through a relay of the caller, the caller would read every
//! value the node types, and could answer for the browser (a page at the right origin that
//! is not). Connected by the node, the bytes go over TLS that ends at the endpoint the owner
//! signed, so the caller sees neither the values nor the answers, and has no CDP command of
//! its own: the node issues a fixed list ([`cdp::Method`]) and never `Runtime.evaluate`.
//!
//! The order of one fill, and what each check stops:
//! 1. the one page target at the policy's origin, with no other client attached, is chosen
//!    and attached to (flattened session);
//! 2. optionally the page is loaded again at a path the policy fixes, so that nothing an
//!    earlier client planted in the document is still there;
//! 3. for each field: the frame tree is read, the top frame must be at the origin; the
//!    element's frame is the top frame or a direct child at the frame origin the policy
//!    names (a cross-origin frame is never used otherwise); an isolated world of the node's
//!    own is made in it, and [`cdp::FIND`] looks the element up there after checking
//!    `location.origin` and `location.ancestorOrigins` in the page itself;
//! 4. the frame tree is read again: the same top frame and frame, with the same loaders
//!    (a navigation changes the loader, a frame swap the id);
//! 5. [`cdp::FILL`] sets the value on the element found, checking the origins again in the
//!    same task, so no navigation can come between that check and the value; a document
//!    that changed makes the element's id unknown and the call fail;
//! 6. the frame tree is read again after the fill, as in 4;
//! 7. the submit element is found the same way and [`cdp::SUBMIT`] runs on it; the node waits
//!    for the top frame to leave the document, and blanks the fields ([`cdp::CLEAR`]) when it
//!    stays.
//!
//! Every message from the browser is read strictly ([`cdp::parse`]): an answer to a command
//! the node did not send, or from another session, ends the fill; events are counted and
//! dropped unread. Nothing of the browser reaches the caller but the outcome and the final
//! origin, searched for secrets like any response.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::live::{self, End, Meter, POLL, READ};
use super::{Clock, Node, Run, compute_vars, stream_vars};
use crate::cdp::{self, CdpError, Frame, Incoming, Method, Remote, WebOrigin};
use crate::egress::{Arrived, Stream, Transport, Versions, dispatch_streamed};
use crate::error::TransportKind;
use crate::log::LogSink;
use crate::policy::{Element, Fill, FrameKind, Open, Step, browser_limits};
use crate::record::Record;
use crate::reflection::{self, Secrets};
use crate::request::{Request, Wire};
use crate::response::{self, MAX_HEAD};
use crate::template::{Context, Template};
use crate::websocket::{self, Decoder, Message};
use crate::{Error, Result};

/// Most events the node reads (and drops) during one browser connection.
pub const MAX_CDP_EVENTS: usize = 10_000;
/// Most commands the node issues on one browser connection.
pub const MAX_CDP_COMMANDS: usize = 2_000;
/// How long the node waits between two looks at the page.
const RETRY: Duration = Duration::from_millis(100);

/// What a browser operation hands back: the outcome and where the page is, nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filled {
    /// `navigated` when the top frame left the document after the last submit; `submitted`
    /// when it stayed (the fields were blanked).
    pub outcome: String,
    /// The origin of the top frame at the end, as a browser serializes it
    /// (`https://host[:port]`), or `null` when it is not an `https` origin.
    pub origin: String,
    /// How many fields were filled.
    pub fields: u64,
    /// How long the connection was open, in milliseconds.
    pub duration_ms: u64,
    /// The sequence numbers of the log entries of the operation (the handshake).
    pub log_seqs: Vec<u64>,
}

/// Now plus `wait`, or now when that does not fit an `Instant`.
fn deadline(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait).unwrap_or(now)
}

fn refused(rule: &'static str) -> Error {
    Error::FillRefused { rule }
}

fn cdp_error(error: CdpError) -> Error {
    match error {
        CdpError::Invalid(rule) => Error::ResponseInvalid { rule },
        CdpError::TooLarge => Error::transport(TransportKind::TooLarge, true),
    }
}

/// The CDP connection: one command at a time, every message read strictly.
struct Cdp<'s> {
    stream: &'s mut dyn Stream,
    decoder: Decoder,
    meter: Meter,
    next_id: u64,
    events: usize,
    commands: usize,
}

impl Cdp<'_> {
    /// The next text message, answering pings. A binary message or a close ends the fill.
    fn next(&mut self, until: Option<Instant>) -> Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            while let Some(message) = self.decoder.message().map_err(live::ws_error)? {
                match message {
                    Message::Text(data) => return Ok(Some(data)),
                    Message::Binary(_) => {
                        return Err(Error::ResponseInvalid {
                            rule: "a binary message on a CDP connection",
                        });
                    }
                    Message::Ping(payload) => live::pong(self.stream, &payload, &mut self.meter)?,
                    Message::Pong(_) => {}
                    Message::Close(_) => return Err(Error::transport(TransportKind::Closed, true)),
                }
            }
            self.meter.check()?;
            let wait = match until {
                Some(until) => {
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Ok(None);
                    }
                    left.min(POLL)
                }
                None => POLL,
            };
            match self.stream.read_some(READ, wait)? {
                Arrived::Bytes(bytes) => {
                    self.meter.received(bytes.len());
                    self.decoder.push(&bytes).map_err(live::ws_error)?;
                }
                Arrived::Nothing => {}
                Arrived::End => return Err(Error::transport(TransportKind::Closed, true)),
            }
        }
    }

    fn event(&mut self) -> Result<()> {
        self.events += 1;
        if self.events > MAX_CDP_EVENTS {
            return Err(Error::Budget { what: "CDP events" });
        }
        Ok(())
    }

    /// Issues one command and reads its answer with `read`; `Err(code)` inside is the
    /// browser's error. Events before the answer are dropped unread.
    fn call<T>(
        &mut self,
        method: Method,
        session: Option<&str>,
        params: &[u8],
        read: impl FnOnce(&str) -> std::result::Result<T, CdpError>,
    ) -> Result<std::result::Result<T, i64>> {
        self.commands += 1;
        if self.commands > MAX_CDP_COMMANDS {
            return Err(Error::Budget {
                what: "CDP commands",
            });
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let bytes = cdp::command(id, method, session, params);
        live::write_message(self.stream, FrameKind::Text, &bytes, &mut self.meter)?;
        drop(bytes);
        loop {
            let Some(message) = self.next(None)? else {
                continue;
            };
            match cdp::parse(&message).map_err(cdp_error)? {
                Incoming::Event { .. } => self.event()?,
                Incoming::Answer {
                    id: got,
                    session: from,
                    result,
                } => {
                    if got != id {
                        return Err(refused(
                            "the browser answered a command the node did not send",
                        ));
                    }
                    if from != session {
                        return Err(refused("the browser answered from another session"));
                    }
                    return match result {
                        Ok(raw) => read(raw).map(Ok).map_err(cdp_error),
                        Err(code) => Ok(Err(code)),
                    };
                }
            }
        }
    }

    /// [`Cdp::call`] where an error of the browser refuses the fill with `rule`.
    fn must<T>(
        &mut self,
        method: Method,
        session: Option<&str>,
        params: &[u8],
        read: impl FnOnce(&str) -> std::result::Result<T, CdpError>,
        rule: &'static str,
    ) -> Result<T> {
        self.call(method, session, params, read)?
            .map_err(|_| refused(rule))
    }

    /// Waits `wait`, reading and dropping events. An answer now is to no command.
    fn pause(&mut self, wait: Duration) -> Result<()> {
        let until = deadline(wait);
        while let Some(message) = self.next(Some(until))? {
            match cdp::parse(&message).map_err(cdp_error)? {
                Incoming::Event { .. } => self.event()?,
                Incoming::Answer { .. } => {
                    return Err(refused(
                        "the browser answered a command the node did not send",
                    ));
                }
            }
        }
        Ok(())
    }

    fn frames(&mut self, session: &str) -> Result<Vec<Frame>> {
        self.must(
            Method::GetFrameTree,
            Some(session),
            b"{}",
            cdp::frame_tree,
            "the browser did not give the page's frames",
        )
    }
}

/// The page the fills go into: its target and the session attached to it, and the sessions
/// attached to its out-of-process frames.
struct Page {
    session: String,
    frames: Vec<(String, String)>,
}

/// An element found: where, and the frames as they were when it was found.
struct Found {
    session: String,
    object: String,
    frame_id: String,
    frame_loader: String,
    top_id: String,
    top_loader: String,
    /// The frame's origin, as the page serializes it.
    origin: String,
    /// `location.ancestorOrigins` the frame must have: none for the top frame, the page's
    /// origin for a child.
    ancestors: Vec<String>,
}

fn json_string(text: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    cdp::push_json_string(&mut out, text);
    out
}

fn json_strings(items: &[String]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![b'[']);
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        cdp::push_json_string(&mut out, item);
    }
    out.push(b']');
    out
}

/// `{"value": <json>}` arguments, in order.
fn arguments(values: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(b"[".to_vec());
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"value\":");
        out.extend_from_slice(value);
        out.push(b'}');
    }
    out.push(b']');
    out
}

/// The params of a `Runtime.callFunctionOn` of one of the node's functions on an object.
fn call_on(function: &str, object: &str, args: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(b"{\"functionDeclaration\":".to_vec());
    cdp::push_json_string(&mut out, function);
    out.extend_from_slice(b",\"objectId\":");
    cdp::push_json_string(&mut out, object);
    out.extend_from_slice(b",\"arguments\":");
    out.extend_from_slice(&arguments(args));
    out.extend_from_slice(b",\"returnByValue\":true,\"silent\":true,\"awaitPromise\":false}");
    out
}

/// True when the frame's document is at `origin`: its URL, and the security origin the
/// browser reports, when it reports one.
fn frame_at(frame: &Frame, origin: &WebOrigin) -> bool {
    WebOrigin::of_url(&frame.url).as_ref() == Some(origin)
        && frame
            .security_origin
            .as_deref()
            .is_none_or(|s| WebOrigin::parse(s).as_ref() == Some(origin))
}

fn top(frames: &[Frame]) -> Result<&Frame> {
    frames
        .first()
        .filter(|f| f.depth == 0 && f.parent.is_none())
        .ok_or(Error::ResponseInvalid {
            rule: "a frame tree without its top frame",
        })
}

/// The reason a function of the node gave, as a refusal.
fn reason(remote: &Remote) -> Error {
    match remote {
        Remote::Text(t) if t == "origin" || t == "ancestors" => {
            refused("the frame is not at the policy's origin")
        }
        Remote::Text(t) if t == "detached" => refused("the element left the page"),
        Remote::Text(t) if t == "kind" => refused("the element is not of the kind the step needs"),
        Remote::Text(t) if t == "many" => refused("a selector matches more than one element"),
        _ => refused("the browser's answer to a function of the node is not valid"),
    }
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// Runs a `browser` operation: the handshake with the CDP endpoint, then each fill.
    pub(super) fn run_browser<T: Transport>(
        &self,
        run: &mut Run<'_>,
        open: &Open,
        request: Option<&Request>,
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<Filled> {
        let operation = run.operation;
        let steps = &operation.steps;
        let Some((at, handshake)) = steps.iter().enumerate().find_map(|(i, s)| match s {
            Step::Send(send) => Some((i, send)),
            _ => None,
        }) else {
            return Err(operation.unknown());
        };
        for step in steps.iter().take(at) {
            match step {
                Step::Open(_) => {}
                Step::Compute(compute) => run.compute(compute, compute_vars(run.now))?,
                _ => return Err(operation.unknown()),
            }
        }
        let key = websocket::key();
        let prepared = self.prepare(run, open, handshake, request, updated, Wire::Upgrade(&key))?;
        let seq = prepared.seq;
        run.log_seqs.push(seq);
        let offered = memchr::memmem::find(
            &prepared.wire.expose().to_ascii_lowercase(),
            b"\r\nsec-websocket-protocol:",
        )
        .is_some();
        let client = prepared.client;
        let opened = dispatch_streamed(
            prepared.confirmed,
            transport,
            prepared.destination,
            client.as_ref(),
            &prepared.wire,
            Versions::Http1,
        );
        drop(client);
        run.tainted.extend(prepared.tainted);
        let limits = browser_limits(open.limits.as_ref());
        let meter = Meter::new(Some(&limits));
        let mut stream = match opened {
            Ok((_, stream)) => stream,
            Err(error) => return self.ended(run, seq, None, meter, Err(error)),
        };
        let mut status = None;
        let mut cdp = Cdp {
            stream: &mut *stream,
            decoder: Decoder::new(cdp::MAX_MESSAGE),
            meter,
            next_id: 1,
            events: 0,
            commands: 0,
        };
        let result = self.fills(run, &mut cdp, &key, offered, at, &mut status);
        let _ = cdp.stream.write(&websocket::encode(
            websocket::OP_CLOSE,
            &1000u16.to_be_bytes(),
        ));
        let meter = cdp.meter;
        let _ = stream.close();
        self.ended(run, seq, status, meter, result)
    }

    /// Logs how the browser connection ended and builds what goes back.
    fn ended(
        &self,
        run: &mut Run<'_>,
        seq: u64,
        status: Option<u16>,
        meter: Meter,
        result: Result<(String, String, u64)>,
    ) -> Result<Filled> {
        let (end, out) = match result {
            Ok((outcome, origin, fields)) => {
                let reason = if outcome == "navigated" {
                    "navigated"
                } else {
                    "submitted"
                };
                (Ok(End::of(reason, true)), Some((outcome, origin, fields)))
            }
            Err(error) => {
                let reason = match (&error, meter.reached()) {
                    (_, Some(limit)) => limit,
                    (Error::FillRefused { .. }, None) => "refused",
                    (Error::Reflection, None) => "reflection",
                    (Error::Budget { .. }, None) => "limit",
                    _ => "error",
                };
                (Err((reason, error)), None)
            }
        };
        let closed = self.closed(run, seq, status, &meter, end)?;
        let Some((outcome, origin, fields)) = out else {
            return Err(Error::FillRefused {
                rule: "the fill ended without an outcome",
            });
        };
        Ok(Filled {
            outcome,
            origin,
            fields,
            duration_ms: closed.duration_ms,
            log_seqs: closed.log_seqs,
        })
    }

    /// The handshake answer, then the steps after it.
    fn fills(
        &self,
        run: &mut Run<'_>,
        cdp: &mut Cdp<'_>,
        key: &str,
        offered: bool,
        at: usize,
        status_out: &mut Option<u16>,
    ) -> Result<(String, String, u64)> {
        let operation = run.operation;
        let head = Zeroizing::new(cdp.stream.read_until(&[b"\r\n\r\n"], MAX_HEAD + 4)?);
        cdp.meter.received(head.len());
        let (status, headers) = response::parse_upgrade(&head)?;
        *status_out = Some(status);
        live::check_upgrade(status, &headers, key, offered)?;
        let mut page: Option<Page> = None;
        let mut last: Option<(bool, String)> = None;
        let mut fields = 0u64;
        for step in operation.steps.iter().skip(at + 1) {
            match step {
                Step::Compute(compute) => run.compute(compute, compute_vars(run.now))?,
                Step::Send(send) => {
                    let fill = send.fill.as_ref().ok_or_else(|| operation.unknown())?;
                    last = Some(self.fill(run, cdp, &mut page, fill)?);
                    fields = fields.saturating_add(fill.fields.len() as u64);
                }
                Step::Return(_) => {}
                _ => return Err(operation.unknown()),
            }
        }
        if let Some(page) = &page {
            let release = format!("{{\"objectGroup\":\"{}\"}}", cdp::GROUP);
            for session in core::iter::once(&page.session).chain(page.frames.iter().map(|(_, s)| s))
            {
                let _ = cdp.call(
                    Method::ReleaseObjectGroup,
                    Some(session),
                    release.as_bytes(),
                    |_| Ok(()),
                );
            }
            for session in page
                .frames
                .iter()
                .map(|(_, s)| s)
                .chain(core::iter::once(&page.session))
            {
                let params = [
                    &b"{\"sessionId\":"[..],
                    json_string(session).as_slice(),
                    b"}",
                ]
                .concat();
                let _ = cdp.call(Method::DetachFromTarget, None, &params, |_| Ok(()));
            }
        }
        let (navigated, origin) = last.ok_or_else(|| operation.unknown())?;
        // What goes back is searched for secrets like any response.
        reflection::check(
            origin.as_bytes(),
            &Secrets {
                policy: run.policy,
                fields: &run.fields,
                captured: &run.captured.secrets,
                rendered: &run.tainted,
            },
        )?;
        let outcome = if navigated { "navigated" } else { "submitted" };
        Ok((outcome.to_string(), origin, fields))
    }

    /// Chooses the page target at `origin` and attaches to it.
    fn attach(&self, cdp: &mut Cdp<'_>, origin: &WebOrigin) -> Result<Page> {
        let targets = cdp.must(
            Method::GetTargets,
            None,
            b"{}",
            cdp::targets,
            "the browser did not list its targets",
        )?;
        let mut at_origin = targets
            .iter()
            .filter(|t| t.kind == "page" && WebOrigin::of_url(&t.url).as_ref() == Some(origin));
        let Some(target) = at_origin.next() else {
            return Err(refused("no page of the browser is at the policy's origin"));
        };
        if at_origin.next().is_some() {
            return Err(refused(
                "more than one page of the browser is at the policy's origin",
            ));
        }
        if target.attached {
            return Err(refused("another client is attached to the page"));
        }
        let session = self.attach_to(cdp, &target.id)?;
        Ok(Page {
            session,
            frames: Vec::new(),
        })
    }

    fn attach_to(&self, cdp: &mut Cdp<'_>, target: &str) -> Result<String> {
        let params = [
            &b"{\"targetId\":"[..],
            json_string(target).as_slice(),
            b",\"flatten\":true}",
        ]
        .concat();
        cdp.must(
            Method::AttachToTarget,
            None,
            &params,
            cdp::session_id,
            "the browser refused to attach to the page",
        )
    }

    /// One fill. Returns whether the page left the document after the submit, and its origin.
    fn fill(
        &self,
        run: &mut Run<'_>,
        cdp: &mut Cdp<'_>,
        page: &mut Option<Page>,
        fill: &Fill,
    ) -> Result<(bool, String)> {
        let origin = fill.page().ok_or_else(|| run.operation.unknown())?;
        let wait = Duration::from_millis(fill.wait());
        if page.is_none() {
            *page = Some(self.attach(cdp, &origin)?);
        }
        let page = page.as_mut().ok_or_else(|| run.operation.unknown())?;
        if let Some(path) = &fill.navigate {
            self.navigate(cdp, page, &origin, path, wait)?;
        }
        let mut filled: Vec<Found> = Vec::new();
        for field in &fill.fields {
            let found = self.find(cdp, page, &origin, &field.element(), wait)?;
            let template = Template::parse(&field.template)?;
            let ctx = Context {
                fields: &run.fields,
                temps: &run.captured.temps,
                vars: stream_vars(&origin.host, run.now),
                unix: run.now / 1000,
                budget: &run.budget,
            };
            let value = template.render(&ctx)?;
            if template.tainted(&|n| run.kinds.kind(n)) {
                run.tainted.push(value.clone());
            }
            let text = core::str::from_utf8(&value)
                .map_err(|_| refused("a fill value that is not UTF-8"))?;
            // A node that handed over acts no more: no value is typed after its chain ended.
            if self.is_handed_over() {
                return Err(refused("the node handed over"));
            }
            self.unchanged(
                cdp,
                page,
                &origin,
                &found,
                "the page changed before the fill",
            )?;
            let params = call_on(
                cdp::FILL,
                &found.object,
                &[
                    &json_string(text),
                    &json_string(&found.origin),
                    &json_strings(&found.ancestors),
                ],
            );
            let answer = cdp.call(
                Method::CallFunctionOn,
                Some(&found.session),
                &params,
                cdp::remote,
            )?;
            drop(params);
            match answer {
                Ok(Remote::Text(t)) if t == "ok" => {}
                Ok(other) => return Err(reason(&other)),
                Err(_) => return Err(refused("the page changed between the check and the fill")),
            }
            self.unchanged(
                cdp,
                page,
                &origin,
                &found,
                "the page changed during the fill",
            )?;
            filled.push(found);
        }
        let submit = self.find(cdp, page, &origin, &fill.submit, wait)?;
        self.unchanged(
            cdp,
            page,
            &origin,
            &submit,
            "the page changed before the submit",
        )?;
        let params = call_on(
            cdp::SUBMIT,
            &submit.object,
            &[
                &json_string(&submit.origin),
                &json_strings(&submit.ancestors),
            ],
        );
        match cdp.call(
            Method::CallFunctionOn,
            Some(&submit.session),
            &params,
            cdp::remote,
        )? {
            Ok(Remote::Text(t)) if t == "ok" => {}
            Ok(other) => return Err(reason(&other)),
            Err(_) => return Err(refused("the page changed before the submit")),
        }
        // The page leaves (a navigation of the top frame), or stays.
        let until = deadline(wait);
        let navigated = loop {
            let frames = cdp.frames(&page.session)?;
            let first = top(&frames)?;
            if first.id != submit.top_id {
                return Err(refused("the page's top frame was replaced"));
            }
            if first.loader != submit.top_loader {
                break true;
            }
            if Instant::now() >= until {
                break false;
            }
            cdp.pause(RETRY)?;
        };
        if !navigated {
            // The page stayed: blank what was filled, so no later reader of the page (the
            // agent's controller, once it attaches again) finds the values there.
            for found in &filled {
                let params = call_on(
                    cdp::CLEAR,
                    &found.object,
                    &[&json_string(&found.origin), &json_strings(&found.ancestors)],
                );
                match cdp.call(
                    Method::CallFunctionOn,
                    Some(&found.session),
                    &params,
                    cdp::remote,
                )? {
                    // The element left the page, or its document is gone: nothing to blank.
                    Ok(Remote::Text(t)) if t == "ok" || t == "detached" => {}
                    Err(_) => {}
                    Ok(other) => return Err(reason(&other)),
                }
            }
        }
        let frames = cdp.frames(&page.session)?;
        let origin = WebOrigin::of_url(&top(&frames)?.url)
            .map(|o| o.serialize())
            .unwrap_or_else(|| "null".to_string());
        Ok((navigated, origin))
    }

    /// Loads the page at `path` on `origin` and waits for the new document.
    fn navigate(
        &self,
        cdp: &mut Cdp<'_>,
        page: &Page,
        origin: &WebOrigin,
        path: &str,
        wait: Duration,
    ) -> Result<()> {
        let url = format!("{}{path}", origin.serialize());
        let params = [&b"{\"url\":"[..], json_string(&url).as_slice(), b"}"].concat();
        let navigated = cdp.must(
            Method::Navigate,
            Some(&page.session),
            &params,
            cdp::navigated,
            "the browser refused to load the page",
        )?;
        let Some(loader) = navigated.loader.filter(|_| !navigated.failed) else {
            return Err(refused("the browser could not load the page"));
        };
        let until = deadline(wait);
        loop {
            let frames = cdp.frames(&page.session)?;
            let first = top(&frames)?;
            if first.id != navigated.frame {
                return Err(refused("the browser loaded another frame than the top one"));
            }
            if first.loader == loader {
                return if frame_at(first, origin) {
                    Ok(())
                } else {
                    Err(refused("the page loaded is not at the policy's origin"))
                };
            }
            if Instant::now() >= until {
                return Err(refused("the page did not load in time"));
            }
            cdp.pause(RETRY)?;
        }
    }

    /// The session that runs code in `frame`: the page's, or one attached to the frame's own
    /// target when it runs in another process.
    fn frame_session(&self, cdp: &mut Cdp<'_>, page: &mut Page, frame: &str) -> Result<String> {
        if let Some((_, session)) = page.frames.iter().find(|(f, _)| f == frame) {
            return Ok(session.clone());
        }
        let targets = cdp.must(
            Method::GetTargets,
            None,
            b"{}",
            cdp::targets,
            "the browser did not list its targets",
        )?;
        match targets.iter().find(|t| t.kind == "iframe" && t.id == frame) {
            None => Ok(page.session.clone()),
            Some(target) if target.attached => {
                Err(refused("another client is attached to the frame"))
            }
            Some(target) => {
                let session = self.attach_to(cdp, &target.id)?;
                page.frames.push((frame.to_string(), session.clone()));
                Ok(session)
            }
        }
    }

    /// Finds the one element `element` names: in the top frame at `origin`, or in a direct
    /// child frame at the frame origin the policy names. Looks again until `wait` is over
    /// while nothing matches.
    fn find(
        &self,
        cdp: &mut Cdp<'_>,
        page: &mut Page,
        origin: &WebOrigin,
        element: &Element,
        wait: Duration,
    ) -> Result<Found> {
        let frame_origin = match &element.frame {
            Some(frame) => {
                Some(WebOrigin::parse(frame).ok_or(refused("the frame origin is not valid"))?)
            }
            None => None,
        };
        let selector = json_string(&element.selector);
        let until = deadline(wait);
        loop {
            let frames = cdp.frames(&page.session)?;
            let first = top(&frames)?;
            if !frame_at(first, origin) {
                return Err(refused("the page is not at the policy's origin"));
            }
            let (top_id, top_loader) = (first.id.clone(), first.loader.clone());
            let candidates: Vec<(Frame, Vec<String>, String)> = match &frame_origin {
                None => vec![(first.clone(), Vec::new(), origin.serialize())],
                Some(wanted) => frames
                    .iter()
                    .filter(|f| {
                        f.depth == 1
                            && f.parent.as_deref() == Some(top_id.as_str())
                            && frame_at(f, wanted)
                    })
                    .map(|f| (f.clone(), vec![origin.serialize()], wanted.serialize()))
                    .collect(),
            };
            let mut found: Vec<Found> = Vec::new();
            for (frame, ancestors, frame_text) in candidates {
                let session = self.frame_session(cdp, page, &frame.id)?;
                let params = [
                    &b"{\"frameId\":"[..],
                    json_string(&frame.id).as_slice(),
                    b",\"worldName\":",
                    json_string(cdp::WORLD).as_slice(),
                    b",\"grantUniveralAccess\":false}",
                ]
                .concat();
                // A frame that went away since the tree was read has no world: not here.
                let Ok(context) = cdp.call(
                    Method::CreateIsolatedWorld,
                    Some(&session),
                    &params,
                    cdp::context_id,
                )?
                else {
                    continue;
                };
                let mut params = Zeroizing::new(b"{\"functionDeclaration\":".to_vec());
                cdp::push_json_string(&mut params, cdp::FIND);
                params.extend_from_slice(b",\"executionContextId\":");
                params.extend_from_slice(context.to_string().as_bytes());
                params.extend_from_slice(b",\"arguments\":");
                params.extend_from_slice(&arguments(&[
                    &selector,
                    &json_string(&frame_text),
                    &json_strings(&ancestors),
                ]));
                params.extend_from_slice(b",\"objectGroup\":");
                cdp::push_json_string(&mut params, cdp::GROUP);
                params.extend_from_slice(b",\"returnByValue\":false,\"silent\":true}");
                let answer =
                    cdp.call(Method::CallFunctionOn, Some(&session), &params, cdp::remote)?;
                match answer {
                    Ok(Remote::Object(object)) => found.push(Found {
                        session,
                        object,
                        frame_id: frame.id.clone(),
                        frame_loader: frame.loader.clone(),
                        top_id: top_id.clone(),
                        top_loader: top_loader.clone(),
                        origin: frame_text,
                        ancestors,
                    }),
                    Ok(Remote::Nothing) => {}
                    Ok(other) => return Err(reason(&other)),
                    Err(_) => return Err(refused("the browser refused the element lookup")),
                }
            }
            let mut found = found.into_iter();
            match (found.next(), found.next()) {
                (Some(one), None) => return Ok(one),
                (Some(_), Some(_)) => {
                    return Err(refused("the element is in more than one frame"));
                }
                (None, _) if Instant::now() >= until => {
                    return Err(refused("no element of the page matches the selector"));
                }
                (None, _) => cdp.pause(RETRY)?,
            }
        }
    }

    /// Reads the frame tree again: the same top frame and element frame, with the same
    /// loaders, at their origins.
    fn unchanged(
        &self,
        cdp: &mut Cdp<'_>,
        page: &Page,
        origin: &WebOrigin,
        found: &Found,
        rule: &'static str,
    ) -> Result<()> {
        let frames = cdp.frames(&page.session)?;
        let first = top(&frames)?;
        let top_same =
            first.id == found.top_id && first.loader == found.top_loader && frame_at(first, origin);
        let frame_same = found.frame_id == found.top_id
            || frames.iter().any(|f| {
                f.id == found.frame_id
                    && f.loader == found.frame_loader
                    && f.depth == 1
                    && f.parent.as_deref() == Some(found.top_id.as_str())
                    && WebOrigin::parse(&found.origin).is_some_and(|o| frame_at(f, &o))
            });
        if top_same && frame_same {
            Ok(())
        } else {
            Err(refused(rule))
        }
    }
}
