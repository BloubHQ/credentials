//! Operations that wait, at run time: the owner's approval and the spending limits before an
//! operation sends anything, challenges at an `await`, sessions renewed before an operation
//! reads them, and the acts of the owner's device that let a waiting operation go on.

use super::park::{Given, LIMITS, Parked, SPEND, Saved, Wait};
use super::{
    Captured, Clock, Error, Event, Fields, Flow, MAX_FUTURE_MS, MAX_SKEW_MS, Node, Output, Payload,
    Record, Result, Run, State, Step, Transport,
};
use crate::approval::{Amount, Approval, ApprovalSummary, MAX_APPROVAL_MS, MAX_LINE, MAX_LINES};
use crate::item::Origin;
use crate::limits::{LimitRule, Spend, SpendingLimits, StateKey, Verdict, decimal, from_minor};
use crate::log::LogSink;
use crate::policy::{
    AmountSource, Connection, Destination, MAX_AMOUNT, Operation, Payment, Renew, parse_query,
    read_amount,
};
use crate::request::{Outbound, Request};
use crate::session::{Pending, SealedAnswer};
use crate::template::Budget;

use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    UnwrapErr(SysRng).fill_bytes(&mut id);
    id
}

/// What the caller gave, kept while the operation waits: exactly what it signed, run as
/// signed when the operation goes on (a resume carries none).
fn given_of(payload: Payload<'_>, input: &[u8]) -> Result<Given> {
    Ok(match payload {
        Payload::Http(request) => Given::Http(request.cloned()),
        Payload::Derive(given) => Given::Derive {
            given: given.to_vec(),
            input: input.to_vec(),
        },
        Payload::Stream {
            destination,
            exchanges,
        } => Given::Stream {
            destination: destination.clone(),
            exchanges: exchanges.to_vec(),
        },
        Payload::Session {
            destination,
            commands,
            mail,
        } => Given::Session {
            destination: destination.clone(),
            commands: commands.to_vec(),
            mail: mail.to_vec(),
        },
        // A WebSocket holds the caller's streaming call; nothing else waits.
        Payload::Describe | Payload::Resume(_) | Payload::Socket(_) => {
            return Err(Error::RequestInvalid { rule: NO_WAIT });
        }
    })
}

/// Why an operation on a streaming call does not wait.
const NO_WAIT: &str = "an operation that streams does not wait for the owner's approval";

/// Where the first request of the operation goes.
fn first_destination(operation: &Operation, request: Option<&Request>) -> Option<Destination> {
    let open = operation.open()?;
    operation.steps.iter().find_map(|step| match step {
        Step::Send(send) => Outbound::of(send, &open.destinations, request)
            .ok()
            .map(|o| o.destination.clone()),
        _ => None,
    })
}

/// The page of the first fill of a browser operation: where its values go (a card's
/// merchant), as opposed to the CDP endpoint it connects to.
fn first_page(operation: &Operation) -> Option<Destination> {
    crate::policy::flow::walk(&operation.steps)
        .into_iter()
        .find_map(|step| match step {
            Step::Send(send) => send.fill.as_ref().and_then(crate::policy::Fill::page),
            _ => None,
        })
        .map(|o| Destination::new(&o.host, o.port))
}

/// The amount of a payment, read only from what the node checked against the contract: a
/// query parameter of the caller's request or a member of the checked input, or the policy.
fn spend_of(
    operation: &Operation,
    payment: &Payment,
    request: Option<&Request>,
    input: &[u8],
    merchant: Option<String>,
) -> Result<Spend> {
    let missing = || Error::RequestInvalid {
        rule: "the amount of the payment is not in the checked request or input",
    };
    let integer = |text: &str| -> Result<u64> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(missing());
        }
        text.parse().map_err(|_| missing())
    };
    let minor = match &payment.amount {
        AmountSource::Fixed { value } => integer(value)?,
        AmountSource::Query { name } => {
            let request = request.ok_or_else(missing)?;
            let query = request.path.split_once('?').map_or("", |(_, q)| q);
            // Some servers also split a query at `;`: `amount=1&note=x;amount=9` would carry
            // a second amount past the one counted.
            if query.contains(';') {
                return Err(Error::RequestInvalid {
                    rule: "a query that carries the amount of a payment holds no ; (write %3B)",
                });
            }
            let params = parse_query(query).map_err(|_| missing())?;
            let mut found = params.iter().filter(|p| p.name == name.as_bytes());
            let param = found.next().ok_or_else(missing)?;
            if found.next().is_some() {
                return Err(missing());
            }
            integer(core::str::from_utf8(&param.value).map_err(|_| missing())?)?
        }
        AmountSource::Input { pointer } => {
            let value: serde_json::Value = serde_json::from_slice(input).map_err(|_| missing())?;
            value
                .pointer(pointer)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(missing)?
        }
        // The body the contract checked and wrote again is the one the node sends: the amount
        // is read from those bytes, by the parser that wrote them.
        AmountSource::Body {
            pointer: at,
            format,
            currency_at,
        }
        | AmountSource::Form {
            name: at,
            format,
            currency_at,
        } => {
            let request = request.ok_or_else(missing)?;
            let contract = operation
                .caller_sends()
                .find_map(|(contract, _)| contract.body.as_ref())
                .ok_or_else(missing)?;
            if let Some(currency_at) = currency_at {
                let (currency, _) = contract
                    .scalar(&request.body, currency_at)
                    .ok_or_else(missing)?;
                if currency != payment.currency {
                    return Err(Error::RequestInvalid {
                        rule: "the currency in the body is not the payment's",
                    });
                }
            }
            let (text, number) = contract.scalar(&request.body, at).ok_or_else(missing)?;
            read_amount(&text, number, *format, payment.exponent).ok_or(Error::RequestInvalid {
                rule: "the amount in the body is not an amount in the form the policy names",
            })?
        }
    };
    if minor > MAX_AMOUNT {
        return Err(missing());
    }
    let scaled = from_minor(minor, payment.exponent).ok_or_else(missing)?;
    Ok(Spend {
        currency: payment.currency.clone(),
        merchant,
        scaled: scaled.to_string(),
        minor,
        exponent: payment.exponent,
    })
}

/// A line of a summary, cut to the length a summary allows.
fn fit(mut line: String) -> String {
    if line.len() > MAX_LINE {
        let mut end = MAX_LINE.saturating_sub(3);
        while !line.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        line.truncate(end);
        line.push_str("...");
    }
    line
}

/// Counts a payment against the limits of its record: logged (sealed), then kept.
fn count<S: LogSink>(
    state: &mut State<S>,
    key: &StateKey,
    now: u64,
    who: (&str, &str, &str),
    operation: &str,
    generation: u64,
    spend: Spend,
) -> Result<()> {
    let sealed = key.seal(who.0, who.1, SPEND, &spend)?;
    state.commit(
        now,
        who,
        Event::Spend {
            operation: operation.to_string(),
            generation,
            sealed,
        },
    )?;
    state
        .limits
        .entry((who.0.to_string(), who.1.to_string()))
        .or_default()
        .record(spend, now);
    Ok(())
}

/// The expiry the node wrote for a session, or none.
fn session_live(fields: &Fields, expires: &str, now: u64) -> bool {
    fields
        .get(expires)
        .and_then(|v| core::str::from_utf8(v).ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|expires| expires > now)
}

/// What a poll of an external challenge found.
enum Polled {
    Success,
    Failure,
    Waiting,
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// How many operations wait on this node now: none once its state was lost to a panic
    /// ([`Node::is_state_lost`]), as none of them goes on.
    pub fn waiting(&self) -> usize {
        let now = self.clock.checked_now_ms().unwrap_or(0);
        self.lock().map_or(0, |mut state| state.parked.len(now))
    }

    /// The owner's approval and the spending limits, before the operation sends anything. A
    /// payment within the limits is counted here, under the same lock as the check, so
    /// payments made at once cannot each fit a limit they exceed together.
    pub(super) fn gate(
        &self,
        run: &mut Run<'_>,
        payload: Payload<'_>,
        input: &[u8],
    ) -> Result<Option<Pending>> {
        let (operation, policy, now) = (run.operation, run.policy, run.now);
        let kind_approval = policy
            .item
            .as_ref()
            .and_then(|b| b.schema().ok())
            .is_some_and(|k| k.shape.approval);
        let mut approval = operation.approval || kind_approval;
        let mut lines = Vec::new();
        if operation.approval {
            lines.push("the policy asks for approval of every use".to_string());
        }
        if kind_approval {
            lines.push("every use of an item of this kind waits for approval".to_string());
        }
        let request = match payload {
            Payload::Http(request) => request,
            _ => None,
        };
        let destination = first_destination(operation, request);
        // A browser fill pays at the page it fills, not at the CDP endpoint.
        let page = first_page(operation);
        let spend = match &operation.payment {
            None => None,
            Some(payment) => {
                let merchant = page
                    .clone()
                    .or_else(|| destination.clone())
                    .map(|destination| {
                        Origin {
                            https: true,
                            destination,
                        }
                        .text()
                    });
                Some(spend_of(operation, payment, request, input, merchant)?)
            }
        };
        if let Some(spend) = &spend {
            let mut state = self.lock()?;
            let verdict = state
                .limits
                .entry((run.record.owner.clone(), run.record.id.clone()))
                .or_default()
                .verdict(spend, now);
            match verdict {
                Verdict::Within if !approval => {
                    count(
                        &mut state,
                        &self.state_key,
                        now,
                        run.who,
                        run.name,
                        run.record.generation,
                        spend.clone(),
                    )?;
                    return Ok(None);
                }
                Verdict::Within => {}
                Verdict::Above(why) => {
                    approval = true;
                    lines.extend(why);
                }
            }
        }
        if !approval {
            return Ok(None);
        }
        // Refused when the policy is signed; checked again so a streaming call never parks.
        if operation.streams() {
            return Err(Error::RequestInvalid { rule: NO_WAIT });
        }
        let given = given_of(payload, input)?;
        let mut lines: Vec<String> = lines.into_iter().map(fit).collect();
        lines.truncate(MAX_LINES);
        let item = match policy.item {
            Some(_) => Some(crate::item::describe(policy, &run.fields)?),
            None => None,
        };
        let origin = spend
            .as_ref()
            .and_then(|s| s.merchant.clone())
            .or_else(|| {
                page.clone().map(|destination| {
                    Origin {
                        https: true,
                        destination,
                    }
                    .text()
                })
            })
            .or_else(|| {
                policy
                    .item
                    .as_ref()
                    .and_then(|b| b.origin())
                    .map(|o| o.text())
            })
            .map(fit);
        let id = random_id();
        let expires_ms = now.saturating_add(MAX_APPROVAL_MS);
        let (delegate, caller) = super::split_label(run.who.2);
        let summary = ApprovalSummary {
            id,
            node: self.public,
            owner: run.record.owner.clone(),
            record_id: run.record.id.clone(),
            generation: run.record.generation,
            caller: caller.to_string(),
            delegate: delegate.map(str::to_string),
            operation: run.name.to_string(),
            destination: destination.map(|d| fit(format!("{}:{}", d.host, d.port))),
            origin,
            amount: spend.as_ref().map(|s| Amount {
                value: decimal(s.minor, s.exponent),
                currency: s.currency.clone(),
            }),
            item,
            lines,
            created_ms: now,
            expires_ms,
        };
        summary.validate()?;
        let pending = Pending::ApprovalRequired {
            id,
            summary: Box::new(summary.clone()),
        };
        let parked = Parked {
            owner: run.record.owner.clone(),
            record: run.record.clone(),
            caller: run.who.2.to_string(),
            operation: run.name.to_string(),
            created_ms: now,
            expires_ms,
            at: 0,
            wait: Wait::Approval {
                summary: Box::new(summary),
                approved: false,
            },
            given,
            spend,
            saved: None,
            pending: pending.clone(),
        };
        self.lock()?
            .parked
            .insert(id, parked, now, &self.holds, run.reserved.take())?;
        Ok(Some(pending))
    }

    /// Parks the operation of `run` at the `await` of index `at`: its values stay in the
    /// memory of the node, and the caller is told the challenge.
    pub(super) fn park_challenge(
        &self,
        run: &mut Run<'_>,
        at: usize,
        payload: Payload<'_>,
        input: &[u8],
        updated: &Option<Record>,
    ) -> Result<Pending> {
        let Some(Step::Await(wait)) = run.operation.steps.get(at) else {
            return Err(run.operation.unknown());
        };
        let challenge = &wait.challenge;
        let now = run.now;
        let state = match &challenge.poll {
            Some(poll) => Wait::External {
                next_poll_ms: now.saturating_add(poll.every_ms),
            },
            None => Wait::Code {
                into: challenge
                    .into
                    .clone()
                    .ok_or_else(|| run.operation.unknown())?,
                pattern: challenge.code_pattern().to_string(),
                answer: None,
            },
        };
        let id = random_id();
        let expires_ms = now.saturating_add(challenge.timeout());
        let pending = Pending::Challenge {
            id,
            challenge: challenge.kind,
            hint: challenge.hint.clone(),
            expires_ms,
        };
        let parked = Parked {
            owner: run.record.owner.clone(),
            record: updated.clone().unwrap_or_else(|| run.record.clone()),
            caller: run.who.2.to_string(),
            operation: run.name.to_string(),
            created_ms: now,
            expires_ms,
            at,
            wait: state,
            given: given_of(payload, input)?,
            spend: None,
            saved: Some(save(run)),
            pending: pending.clone(),
        };
        self.lock()?
            .parked
            .insert(id, parked, now, &self.holds, run.reserved.take())?;
        Ok(pending)
    }

    /// Goes on with the operation that waits under `id`, for the caller that started it, on
    /// the record it was left with. While it still waits, the caller is told again.
    pub(super) fn resume<T: Transport>(
        &self,
        record: &Record,
        name: &str,
        auth: &crate::caller::Authorization,
        id: &[u8; 16],
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<Output> {
        let now = self.now()?;
        let delegated = self.delegation_of(record, auth)?;
        let (policy, operation, checked) = self.check_call(
            record,
            delegated.as_deref(),
            name,
            auth,
            &Payload::Resume(id),
            now,
        )?;
        // A protocol connection or a browser is open for the whole call: the call that goes
        // on takes one of the bounded slots, as the one that started it did. Taken before the
        // waiting operation is, so a full node leaves it waiting.
        let _slot = match operation.connection() {
            Some(c) if c.is_protocol() || c == Connection::Browser => {
                Some(self.live.take(&record.owner, &checked.caller, policy)?)
            }
            _ => None,
        };
        let (parked, reserved) = {
            let mut state = self.lock()?;
            let Some(parked) = state.parked.get_mut(id, now) else {
                return Err(Error::ParkedUnknown);
            };
            // Only the caller that started it, on the same record and operation: anyone else
            // learns nothing, not even that the id exists.
            if parked.owner != record.owner
                || parked.record != *record
                || parked.operation != name
                || parked.caller != checked.caller
            {
                return Err(Error::ParkedUnknown);
            }
            let ready = match &parked.wait {
                Wait::Code { answer, .. } => answer.is_some(),
                Wait::Approval { approved, .. } => *approved,
                Wait::External { next_poll_ms } => now >= *next_poll_ms,
            };
            if !ready {
                return Ok(Output::Pending(parked.pending.clone()));
            }
            let parked = state.parked.remove(id).ok_or(Error::ParkedUnknown)?;
            // The slot it leaves stays held while it runs, so it can wait again (on the same
            // challenge, or at a later `await`) without losing the race to another call.
            let reserved = state.parked.reserve(&self.holds, &record.owner, now)?;
            (parked, reserved)
        };
        let Parked {
            at,
            wait,
            given,
            spend,
            saved,
            pending,
            created_ms,
            expires_ms,
            ..
        } = parked;
        let user_key = checked.keys;
        let who = (
            record.owner.as_str(),
            record.id.as_str(),
            checked.caller.as_str(),
        );
        let mut run = match saved {
            Some(saved) => Run {
                record,
                name,
                who,
                policy,
                operation,
                kinds: policy.kinds(operation),
                fields: saved.fields,
                user_key,
                budget: saved.budget,
                captured: saved.captured,
                tainted: saved.tainted,
                now,
                start: at.saturating_add(1),
                last: saved.last,
                log_seqs: saved.log_seqs,
                reserved: Some(reserved),
            },
            None => {
                let fields = self.open(record, &user_key)?;
                Run {
                    record,
                    name,
                    who,
                    policy,
                    operation,
                    kinds: policy.kinds(operation),
                    fields,
                    user_key,
                    budget: Budget::default(),
                    captured: Captured::default(),
                    tainted: Vec::new(),
                    now,
                    start: 0,
                    last: None,
                    log_seqs: Vec::new(),
                    reserved: Some(reserved),
                }
            }
        };
        match wait {
            Wait::Code { into, answer, .. } => {
                let answer = answer.ok_or(Error::ParkedUnknown)?;
                // The code is a secret temporary value: redacted from what is handed back.
                run.captured.secrets.push(answer.clone());
                run.captured.temps_len = run.captured.temps_len.saturating_add(answer.len());
                run.captured.temps.insert(into, answer);
            }
            Wait::Approval { .. } => {
                if let Some(spend) = spend {
                    let mut state = self.lock()?;
                    count(
                        &mut state,
                        &self.state_key,
                        now,
                        who,
                        name,
                        record.generation,
                        spend,
                    )?;
                }
            }
            Wait::External { .. } => match self.poll(&mut run, at, transport, updated)? {
                Polled::Success => {}
                Polled::Failure => {
                    return Err(Error::ChallengeFailed {
                        rule: "the site refused the challenge",
                    });
                }
                Polled::Waiting => {
                    let every = match operation.steps.get(at) {
                        Some(Step::Await(wait)) => {
                            wait.challenge.poll.as_ref().map_or(0, |p| p.every_ms)
                        }
                        _ => 0,
                    };
                    let parked = Parked {
                        owner: record.owner.clone(),
                        record: updated.clone().unwrap_or_else(|| record.clone()),
                        caller: checked.caller.clone(),
                        operation: name.to_string(),
                        created_ms,
                        expires_ms,
                        at,
                        wait: Wait::External {
                            next_poll_ms: now.saturating_add(every),
                        },
                        given,
                        spend: None,
                        saved: Some(save(&mut run)),
                        pending: pending.clone(),
                    };
                    self.lock()?.parked.insert(
                        *id,
                        parked,
                        now,
                        &self.holds,
                        run.reserved.take(),
                    )?;
                    return Ok(Output::Pending(pending));
                }
            },
        }
        let (payload, input) = match &given {
            Given::Http(request) => (Payload::Http(request.as_ref()), &[][..]),
            Given::Derive { given, input } => (Payload::Derive(given), input.as_slice()),
            Given::Stream {
                destination,
                exchanges,
            } => (
                Payload::Stream {
                    destination,
                    exchanges,
                },
                &[][..],
            ),
            Given::Session {
                destination,
                commands,
                mail,
            } => (
                Payload::Session {
                    destination,
                    commands,
                    mail,
                },
                &[][..],
            ),
        };
        self.proceed(&mut run, payload, input, transport, updated)
    }

    /// Sends the status request of an external challenge and reads its conditions.
    fn poll<T: Transport>(
        &self,
        run: &mut Run<'_>,
        at: usize,
        transport: &mut T,
        updated: &Option<Record>,
    ) -> Result<Polled> {
        let operation = run.operation;
        let Some(Step::Await(wait)) = operation.steps.get(at) else {
            return Err(operation.unknown());
        };
        let poll = wait
            .challenge
            .poll
            .as_ref()
            .ok_or_else(|| operation.unknown())?;
        let open = operation.open().ok_or_else(|| operation.unknown())?;
        let (seq, http) = self.https_send(run, open, &poll.send, None, transport, updated)?;
        let read = |condition: &crate::policy::Condition| -> Result<bool> {
            let value = http.capture(&condition.source)?;
            Ok(condition.holds(value.as_deref().map(Vec::as_slice)))
        };
        let outcome = read(&poll.success).and_then(|success| {
            let failure = match &poll.failure {
                Some(failure) => read(failure)?,
                None => false,
            };
            Ok((success, failure))
        });
        self.done(run.now, run.who, seq, Some(http.status), outcome.is_ok());
        let (success, failure) = outcome?;
        run.log_seqs.push(seq);
        Ok(if success {
            // The steps after the `await` read the status response.
            run.last = Some(http);
            Polled::Success
        } else if failure {
            Polled::Failure
        } else {
            Polled::Waiting
        })
    }

    /// Renews the sessions the operation reads that lapsed: by the operation their rule names
    /// (whose response fills the session again), or not at all when the owner renews them.
    pub(super) fn renew_sessions<T: Transport>(
        &self,
        run: &mut Run<'_>,
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<()> {
        let policy = run.policy;
        let reads = run.operation.field_reads(policy);
        for spec in &policy.fields {
            let Some(rule) = &spec.session else {
                continue;
            };
            if !reads.contains(&spec.name) || session_live(&run.fields, &rule.expires, run.now) {
                continue;
            }
            let expired = || Error::SessionExpired {
                field: spec.name.clone(),
            };
            let Renew::Operation { name } = &rule.renew else {
                return Err(expired());
            };
            let renew = policy.operation(name)?;
            let mut nested = Run {
                record: run.record,
                name: name.as_str(),
                who: run.who,
                policy,
                operation: renew,
                kinds: policy.kinds(renew),
                fields: core::mem::replace(&mut run.fields, Fields::new()),
                user_key: run.user_key.clone(),
                budget: Budget::default(),
                captured: Captured::default(),
                tainted: Vec::new(),
                now: run.now,
                start: 0,
                last: None,
                log_seqs: Vec::new(),
                reserved: None,
            };
            let flow = self.run_https(&mut nested, None, transport, updated);
            run.fields = core::mem::replace(&mut nested.fields, Fields::new());
            run.captured.secrets.append(&mut nested.captured.secrets);
            run.tainted.append(&mut nested.tainted);
            if !matches!(flow?, Flow::Done(_)) {
                return Err(renew.unknown());
            }
            if !session_live(&run.fields, &rule.expires, run.now) {
                return Err(expired());
            }
        }
        Ok(())
    }

    /// Takes a code a device of the owner signed and sealed to this node for the challenge it
    /// names. The code is kept in memory with the waiting operation and logged nowhere.
    pub fn answer(&self, sealed: &SealedAnswer) -> Result<()> {
        let opened = sealed.open(&self.seal, &self.public)?;
        let now = self.now()?;
        let mut state = self.lock()?;
        if !state.devices(&opened.owner).contains(&opened.device) {
            return Err(Error::GrantDenied);
        }
        opened.verify(&self.public)?;
        let invalid = |rule| Error::AnswerInvalid { rule };
        let Some(parked) = state.parked.get_mut(&opened.id, now) else {
            return Err(Error::ParkedUnknown);
        };
        if parked.owner != opened.owner {
            return Err(Error::ParkedUnknown);
        }
        let Wait::Code {
            pattern, answer, ..
        } = &parked.wait
        else {
            return Err(invalid("the operation waits for no code"));
        };
        if answer.is_some() {
            return Err(invalid("the challenge was answered before"));
        }
        if opened.issued_ms.saturating_add(MAX_FUTURE_MS) < parked.created_ms
            || opened.issued_ms > now.saturating_add(MAX_FUTURE_MS)
        {
            return Err(invalid("answered outside the time the challenge was open"));
        }
        let matches =
            crate::extract::compile_whole(pattern).is_some_and(|re| re.is_match(&opened.code));
        if !matches {
            return Err(invalid(
                "the code does not match the pattern of the challenge",
            ));
        }
        let who = (
            parked.owner.clone(),
            parked.record.id.clone(),
            parked.caller.clone(),
        );
        let operation = parked.operation.clone();
        state.commit(
            now,
            (&who.0, &who.1, &who.2),
            Event::Answer {
                operation,
                device: opened.device,
            },
        )?;
        if let Some(Parked {
            wait: Wait::Code { answer, .. },
            ..
        }) = state.parked.get_mut(&opened.id, now)
        {
            *answer = Some(opened.code);
        }
        Ok(())
    }

    /// Takes the owner's approval of the summary of a waiting operation: signed by a known
    /// device of the owner over exactly the summary this node built, while it is open.
    pub fn approve(&self, approval: &Approval) -> Result<()> {
        let now = self.now()?;
        let mut state = self.lock()?;
        let summary = match state.parked.get_mut(&approval.id, now).map(|p| &p.wait) {
            Some(Wait::Approval {
                summary,
                approved: false,
            }) => (**summary).clone(),
            Some(Wait::Approval { .. }) => {
                return Err(Error::ApprovalInvalid {
                    rule: "the summary was approved before",
                });
            }
            _ => return Err(Error::ParkedUnknown),
        };
        let devices = state.devices(&summary.owner);
        approval.verify(&summary, &self.public, &devices, now)?;
        state.commit(
            now,
            (&summary.owner, &summary.record_id, &summary.caller),
            Event::Approve {
                operation: summary.operation.clone(),
                generation: summary.generation,
                device: approval.device,
                summary_sha256: approval.summary_sha256,
            },
        )?;
        if let Some(Parked {
            wait: Wait::Approval { approved, .. },
            ..
        }) = state.parked.get_mut(&approval.id, now)
        {
            *approved = true;
        }
        Ok(())
    }

    /// Sets the spending limits of a record, as a known device of the owner signed for this
    /// node. They replace the limits the node held; payments counted so far still count.
    pub fn set_limits(&self, limits: &SpendingLimits) -> Result<()> {
        let invalid = |rule| Error::LimitsInvalid { rule };
        if limits.node != self.public {
            return Err(invalid("limits for another node"));
        }
        limits.validate()?;
        let now = self.now()?;
        let (owner, record_id) = (limits.owner.as_str(), limits.record_id.as_str());
        let mut state = self.lock()?;
        state.grant_of(owner, now)?;
        if !state.devices(owner).contains(&limits.device) {
            return Err(Error::GrantDenied);
        }
        limits.verify()?;
        if limits.issued_ms.abs_diff(now) > MAX_SKEW_MS || limits.issued_ms < state.since(now) {
            return Err(invalid("issued too long ago or in the future"));
        }
        let key = (owner.to_string(), record_id.to_string());
        if state
            .limits
            .get(&key)
            .is_some_and(|l| limits.issued_ms <= l.issued_ms)
        {
            return Err(invalid("not newer than the limits the node holds"));
        }
        let rules: &[LimitRule] = &limits.rules;
        let sealed = self.state_key.seal(owner, record_id, LIMITS, &rules)?;
        state.commit(
            now,
            (owner, record_id, ""),
            Event::Limits {
                issued_ms: limits.issued_ms,
                device: limits.device,
                sealed,
            },
        )?;
        state
            .limits
            .entry(key)
            .or_default()
            .set(limits.rules.clone(), limits.issued_ms);
        Ok(())
    }
}

/// Takes the values of `run` out, to keep while it waits.
fn save(run: &mut Run<'_>) -> Saved {
    Saved {
        fields: core::mem::replace(&mut run.fields, Fields::new()),
        captured: core::mem::take(&mut run.captured),
        tainted: core::mem::take(&mut run.tainted),
        budget: core::mem::take(&mut run.budget),
        last: run.last.take(),
        log_seqs: core::mem::take(&mut run.log_seqs),
    }
}
