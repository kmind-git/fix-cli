#![forbid(unsafe_code)]

use bytes::Bytes;
use fix_protocol::{
    CompiledDictionary, Field, FrameDecoder, ParseDictionary, ParsedMessage, encode_message,
    parse_frame,
};
use fix_store::{
    AuditEvent, CommandRecord, EventRecord, InboundCommit, MarkOutboundWritten, OutboundCommit,
    OutboundRange, StoreHandle, StoreOp, StoreReply,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, split};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{Duration, Instant, MissedTickBehavior};

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub begin_string: String,
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub heartbeat_interval_secs: u64,
    pub default_appl_ver_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Disconnected,
    Connecting,
    LogonSent,
    Synchronizing,
    Established,
    Recovering,
    LogoutSent,
    Blocked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionStatus {
    pub phase: SessionPhase,
    pub next_out: u64,
    pub next_in: u64,
    pub test_request_outstanding: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationRequest {
    pub request_id: String,
    pub fingerprint: String,
    pub cl_ord_id: String,
    pub msg_type: String,
    pub fields: Vec<Field>,
}

pub trait TimeSource: Send + Sync + 'static {
    fn sending_time(&self) -> String;
}

#[derive(Clone, Debug)]
pub struct StaticTimeSource {
    value: String,
}

impl StaticTimeSource {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl TimeSource for StaticTimeSource {
    fn sending_time(&self) -> String {
        self.value.clone()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn sending_time(&self) -> String {
        let now = OffsetDateTime::now_utc();
        format!(
            "{:04}{:02}{:02}-{:02}:{:02}:{:02}.{:03}",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            now.millisecond(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    PhaseChanged(SessionPhase),
    TransportClosed,
    ProtocolError(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    #[error("session actor stopped")]
    ActorStopped,
    #[error("store error: {0}")]
    Store(String),
    #[error("FIX codec error: {0}")]
    Codec(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("FIX session protocol error: {0}")]
    Protocol(String),
    #[error("session is not established")]
    NotEstablished,
    #[error("invalid application request: {0}")]
    InvalidApplication(String),
}

enum ActorCommand {
    Status,
    Submit(ApplicationRequest),
    Logout(Option<String>),
}

enum ActorReply {
    Status(SessionStatus),
    Command(CommandRecord),
    Ack,
}

struct Envelope {
    command: ActorCommand,
    reply: oneshot::Sender<Result<ActorReply, SessionError>>,
}

#[derive(Clone)]
pub struct SessionHandle {
    commands: mpsc::Sender<Envelope>,
    events: broadcast::Sender<SessionEvent>,
}

impl SessionHandle {
    pub async fn status(&self) -> Result<SessionStatus, SessionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Envelope {
                command: ActorCommand::Status,
                reply: reply_tx,
            })
            .await
            .map_err(|_| SessionError::ActorStopped)?;

        match reply_rx.await.map_err(|_| SessionError::ActorStopped)?? {
            ActorReply::Status(status) => Ok(status),
            ActorReply::Command(_) | ActorReply::Ack => Err(SessionError::ActorStopped),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }

    pub async fn logout(&self, text: Option<String>) -> Result<(), SessionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Envelope {
                command: ActorCommand::Logout(text),
                reply: reply_tx,
            })
            .await
            .map_err(|_| SessionError::ActorStopped)?;
        match reply_rx.await.map_err(|_| SessionError::ActorStopped)?? {
            ActorReply::Ack => Ok(()),
            ActorReply::Status(_) | ActorReply::Command(_) => Err(SessionError::ActorStopped),
        }
    }

    pub async fn submit(&self, request: ApplicationRequest) -> Result<CommandRecord, SessionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Envelope {
                command: ActorCommand::Submit(request),
                reply: reply_tx,
            })
            .await
            .map_err(|_| SessionError::ActorStopped)?;

        match reply_rx.await.map_err(|_| SessionError::ActorStopped)?? {
            ActorReply::Command(command) => Ok(command),
            ActorReply::Status(_) | ActorReply::Ack => Err(SessionError::ActorStopped),
        }
    }
}

pub fn spawn_initiator<T>(
    io: T,
    config: SessionConfig,
    store: StoreHandle,
    time_source: Arc<dyn TimeSource>,
) -> SessionHandle
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_initiator_internal(io, config, None, Vec::new(), store, time_source)
}

pub fn spawn_initiator_with_dictionary<T>(
    io: T,
    config: SessionConfig,
    dictionary: Arc<CompiledDictionary>,
    store: StoreHandle,
    time_source: Arc<dyn TimeSource>,
) -> SessionHandle
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_initiator_internal(io, config, Some(dictionary), Vec::new(), store, time_source)
}

pub fn spawn_initiator_with_dictionary_and_logon_fields<T>(
    io: T,
    config: SessionConfig,
    dictionary: Arc<CompiledDictionary>,
    logon_fields: Vec<Field>,
    store: StoreHandle,
    time_source: Arc<dyn TimeSource>,
) -> SessionHandle
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_initiator_internal(
        io,
        config,
        Some(dictionary),
        logon_fields,
        store,
        time_source,
    )
}

fn spawn_initiator_internal<T>(
    io: T,
    config: SessionConfig,
    dictionary: Option<Arc<CompiledDictionary>>,
    logon_fields: Vec<Field>,
    store: StoreHandle,
    time_source: Arc<dyn TimeSource>,
) -> SessionHandle
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (commands_tx, commands_rx) = mpsc::channel(128);
    let (events, _) = broadcast::channel(256);
    let handle = SessionHandle {
        commands: commands_tx,
        events: events.clone(),
    };
    let (reader, writer) = split(io);

    tokio::spawn(async move {
        let recovery = match store.recover().await {
            Ok(recovery) => recovery,
            Err(error) => {
                let _ = events.send(SessionEvent::PhaseChanged(SessionPhase::Blocked));
                let _ = events.send(SessionEvent::ProtocolError(error.to_string()));
                return;
            }
        };
        let mut actor = SessionActor {
            config,
            store,
            time_source,
            writer,
            commands: commands_rx,
            events,
            phase: SessionPhase::Connecting,
            next_out: recovery.next_out,
            next_in: recovery.next_in,
            next_event: recovery.next_event,
            decoder: FrameDecoder::new(1024 * 1024),
            parse_dictionary: dictionary
                .as_ref()
                .map_or_else(ParseDictionary::new, |value| value.parse_dictionary()),
            dictionary,
            logon_fields,
            gap_buffer: BTreeMap::new(),
            last_outbound: Instant::now(),
            last_inbound: Instant::now(),
            test_request: None,
        };

        if let Err(error) = actor.run(reader).await {
            actor.phase = SessionPhase::Blocked;
            let _ = actor
                .events
                .send(SessionEvent::PhaseChanged(SessionPhase::Blocked));
            let _ = actor
                .events
                .send(SessionEvent::ProtocolError(error.to_string()));
        }
    });

    handle
}

struct SessionActor<W> {
    config: SessionConfig,
    store: StoreHandle,
    time_source: Arc<dyn TimeSource>,
    writer: W,
    commands: mpsc::Receiver<Envelope>,
    events: broadcast::Sender<SessionEvent>,
    phase: SessionPhase,
    next_out: u64,
    next_in: u64,
    next_event: u64,
    decoder: FrameDecoder,
    parse_dictionary: ParseDictionary,
    dictionary: Option<Arc<CompiledDictionary>>,
    logon_fields: Vec<Field>,
    gap_buffer: BTreeMap<u64, Bytes>,
    last_outbound: Instant,
    last_inbound: Instant,
    test_request: Option<TestRequestOutstanding>,
}

struct TestRequestOutstanding {
    id: String,
    deadline: Instant,
}

impl<W> SessionActor<W>
where
    W: AsyncWrite + Unpin,
{
    async fn run<R>(&mut self, mut reader: ReadHalf<R>) -> Result<(), SessionError>
    where
        R: AsyncRead + AsyncWrite + Unpin,
    {
        self.send_logon().await?;
        self.set_phase(SessionPhase::LogonSent);
        let mut input = vec![0_u8; 8192];
        let heartbeat_interval = Duration::from_secs(self.config.heartbeat_interval_secs.max(1));
        let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
        heartbeat_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        heartbeat_timer.tick().await;

        loop {
            tokio::select! {
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    self.handle_command(command).await;
                }
                read = reader.read(&mut input) => {
                    let count = read.map_err(|error| SessionError::Transport(error.to_string()))?;
                    if count == 0 {
                        self.set_phase(SessionPhase::Disconnected);
                        let _ = self.events.send(SessionEvent::TransportClosed);
                        return Ok(());
                    }
                    let frames = self.decoder
                        .ingest(&input[..count])
                        .map_err(|error| SessionError::Codec(error.to_string()))?;
                    for frame in frames {
                        self.handle_inbound(&frame).await?;
                    }
                }
                _ = heartbeat_timer.tick() => {
                    if self.phase == SessionPhase::Established
                        && self.last_outbound.elapsed() >= heartbeat_interval
                    {
                        self.send_heartbeat().await?;
                    }
                    if let Some(outstanding) = &self.test_request {
                        if Instant::now() >= outstanding.deadline {
                            self.send_logout(Some("TestRequest response timeout".to_owned()))
                                .await?;
                            return Err(SessionError::Protocol(
                                "TestRequest response timeout".to_owned(),
                            ));
                        }
                    } else if self.phase == SessionPhase::Established
                        && self.last_inbound.elapsed() >= heartbeat_interval + heartbeat_interval
                    {
                        self.send_test_request(heartbeat_interval).await?;
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, envelope: Envelope) {
        let result = match envelope.command {
            ActorCommand::Status => Ok(ActorReply::Status(SessionStatus {
                phase: self.phase,
                next_out: self.next_out,
                next_in: self.next_in,
                test_request_outstanding: self
                    .test_request
                    .as_ref()
                    .map(|outstanding| outstanding.id.clone()),
            })),
            ActorCommand::Submit(request) => self
                .submit_application(request)
                .await
                .map(ActorReply::Command),
            ActorCommand::Logout(text) => self.send_logout(text).await.map(|()| ActorReply::Ack),
        };
        let _ = envelope.reply.send(result);
    }

    async fn send_logon(&mut self) -> Result<(), SessionError> {
        let mut custom_tags = std::collections::BTreeSet::new();
        for field in &self.logon_fields {
            if matches!(
                field.tag,
                0 | 8 | 9 | 10 | 34 | 35 | 43 | 49 | 52 | 56 | 98 | 108 | 1137 | 122
            ) || field.value.contains(&0x01)
                || !custom_tags.insert(field.tag)
            {
                return Err(SessionError::Protocol(format!(
                    "invalid custom Logon field {}",
                    field.tag
                )));
            }
        }
        let mut fields = self.standard_header("A");
        fields.push(Field::new(98, Bytes::from_static(b"0")));
        fields.push(Field::new(
            108,
            Bytes::from(self.config.heartbeat_interval_secs.to_string()),
        ));
        if let Some(default_appl_ver_id) = &self.config.default_appl_ver_id {
            fields.push(Field::new(
                1137,
                Bytes::copy_from_slice(default_appl_ver_id.as_bytes()),
            ));
        }
        fields.extend(self.logon_fields.iter().cloned());

        let wire = self.encode_outbound(&fields)?;
        let journal_fields = fields
            .iter()
            .map(|field| {
                if matches!(field.tag, 553 | 554 | 925)
                    || self
                        .dictionary
                        .as_ref()
                        .is_some_and(|dictionary| dictionary.sensitive_tags.contains(&field.tag))
                {
                    Field::new(field.tag, Bytes::from_static(b"<redacted>"))
                } else {
                    field.clone()
                }
            })
            .collect::<Vec<_>>();
        let journal_wire = self.encode_outbound(&journal_fields)?;
        let request_id = format!("session:logon:{}", self.next_out);
        let audit = AuditEvent {
            kind: "session_logon_journaled".to_owned(),
            details: BTreeMap::from([("msg_seq_num".to_owned(), self.next_out.to_string())]),
        };
        let reply = self
            .store
            .apply(StoreOp::CommitOutbound(OutboundCommit {
                request_id: request_id.clone(),
                fingerprint: format!("admin:A:{}", self.next_out),
                cl_ord_id: String::new(),
                msg_seq_num: self.next_out,
                wire: journal_wire.to_vec(),
                audit,
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Command(command) = reply else {
            return Err(SessionError::Store(
                "outbound commit returned an inbound record".to_owned(),
            ));
        };

        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        self.store
            .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
                request_id,
                msg_seq_num: command.msg_seq_num,
                audit: AuditEvent {
                    kind: "session_logon_written".to_owned(),
                    details: BTreeMap::new(),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        self.next_out = command.msg_seq_num + 1;
        Ok(())
    }

    async fn handle_inbound(&mut self, frame: &[u8]) -> Result<(), SessionError> {
        let message = self.parse_inbound(frame)?;
        self.last_inbound = Instant::now();
        let msg_seq_num = required_u64(&message, 34)?;
        if msg_seq_num > self.next_in {
            if self.gap_buffer.len() >= 1024 {
                return Err(SessionError::Protocol(
                    "inbound gap buffer limit exceeded".to_owned(),
                ));
            }
            self.gap_buffer
                .entry(msg_seq_num)
                .or_insert_with(|| Bytes::copy_from_slice(frame));
            if self.phase != SessionPhase::Recovering {
                self.send_resend_request(self.next_in).await?;
                self.set_phase(SessionPhase::Recovering);
            }
            return Ok(());
        }
        if msg_seq_num < self.next_in {
            if message.values(43).next() == Some(b"Y".as_slice()) {
                self.verify_possdup(&message, msg_seq_num).await?;
                return Ok(());
            }
            return Err(SessionError::Protocol(format!(
                "expected inbound sequence {}, got {msg_seq_num}",
                self.next_in
            )));
        }

        self.commit_expected(message, frame).await?;
        while let Some(buffered) = self.gap_buffer.remove(&self.next_in) {
            let message = self.parse_inbound(&buffered)?;
            self.commit_expected(message, &buffered).await?;
        }
        if self.phase == SessionPhase::Recovering && self.gap_buffer.is_empty() {
            self.set_phase(SessionPhase::Established);
        }

        Ok(())
    }

    async fn verify_possdup(
        &mut self,
        replay: &ParsedMessage,
        msg_seq_num: u64,
    ) -> Result<(), SessionError> {
        if replay.values(43).count() != 1
            || replay.values(52).count() != 1
            || replay.values(122).count() != 1
        {
            return Err(SessionError::Protocol(
                "PossDup requires exactly one PossDupFlag, SendingTime and OrigSendingTime"
                    .to_owned(),
            ));
        }
        let orig_sending_time = required_value(replay, 122)?;
        let sending_time = required_value(replay, 52)?;
        if orig_sending_time > sending_time {
            return Err(SessionError::Protocol(
                "OrigSendingTime is later than SendingTime".to_owned(),
            ));
        }

        let reply = self
            .store
            .apply(StoreOp::LoadInbound(msg_seq_num))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::StoredInbound(Some(original)) = reply else {
            return Err(SessionError::Protocol(format!(
                "PossDup sequence {msg_seq_num} has no committed original"
            )));
        };
        let original = parse_frame(&original.wire, &self.parse_dictionary)
            .map_err(|error| SessionError::Codec(error.to_string()))?;
        let original_sending_time = required_value(&original, 52)?;
        if original_sending_time != orig_sending_time
            || original.begin_string != replay.begin_string
            || !same_replay_payload(&original, replay)
        {
            return Err(SessionError::Protocol(format!(
                "PossDup payload mismatch for sequence {msg_seq_num}"
            )));
        }
        Ok(())
    }

    fn parse_inbound(&self, frame: &[u8]) -> Result<ParsedMessage, SessionError> {
        let message = parse_frame(frame, &self.parse_dictionary)
            .map_err(|error| SessionError::Codec(error.to_string()))?;
        if message.begin_string.as_ref() != self.config.begin_string.as_bytes() {
            return Err(SessionError::Protocol("BeginString mismatch".to_owned()));
        }
        if required_value(&message, 49)? != self.config.target_comp_id.as_bytes() {
            return Err(SessionError::Protocol(
                "inbound SenderCompID does not match TargetCompID".to_owned(),
            ));
        }
        if required_value(&message, 56)? != self.config.sender_comp_id.as_bytes() {
            return Err(SessionError::Protocol(
                "inbound TargetCompID does not match SenderCompID".to_owned(),
            ));
        }
        if let Some(dictionary) = &self.dictionary {
            dictionary
                .validate(message.clone())
                .map_err(|error| SessionError::Protocol(error.to_string()))?;
        }
        Ok(message)
    }

    async fn commit_expected(
        &mut self,
        message: ParsedMessage,
        frame: &[u8],
    ) -> Result<(), SessionError> {
        let msg_seq_num = required_u64(&message, 34)?;
        if msg_seq_num != self.next_in {
            return Err(SessionError::Protocol(format!(
                "expected inbound sequence {}, got {msg_seq_num}",
                self.next_in
            )));
        }
        let msg_type = message
            .msg_type()
            .ok_or_else(|| SessionError::Protocol("MsgType is missing".to_owned()))?;
        let msg_type = std::str::from_utf8(msg_type)
            .map_err(|_| SessionError::Protocol("MsgType is not ASCII".to_owned()))?
            .to_owned();
        let requested_resend = if msg_type == "2" {
            Some((required_u64(&message, 7)?, required_u64(&message, 16)?))
        } else {
            None
        };
        let heartbeat_response = if msg_type == "1" {
            Some(required_value(&message, 112)?.to_vec())
        } else {
            None
        };
        let next_in_after = if msg_type == "4" {
            if required_value(&message, 123)? != b"Y" {
                return Err(SessionError::Protocol(
                    "non-GapFill SequenceReset is disabled".to_owned(),
                ));
            }
            let new_seq_num = required_u64(&message, 36)?;
            if new_seq_num <= self.next_in {
                return Err(SessionError::Protocol(format!(
                    "SequenceReset NewSeqNo {new_seq_num} must be greater than {}",
                    self.next_in
                )));
            }
            new_seq_num
        } else {
            self.next_in + 1
        };

        self.store
            .apply(StoreOp::CommitInbound(InboundCommit {
                msg_seq_num,
                next_in_after,
                msg_type: msg_type.clone(),
                wire: frame.to_vec(),
                event: EventRecord {
                    id: self.next_event,
                    kind: event_kind(&msg_type).to_owned(),
                    details: BTreeMap::from([
                        ("msg_type".to_owned(), msg_type.clone()),
                        ("msg_seq_num".to_owned(), msg_seq_num.to_string()),
                    ]),
                },
                audit: AuditEvent {
                    kind: "inbound_committed".to_owned(),
                    details: BTreeMap::from([
                        ("msg_type".to_owned(), msg_type.clone()),
                        ("msg_seq_num".to_owned(), msg_seq_num.to_string()),
                    ]),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        self.next_in = next_in_after;
        self.next_event += 1;

        if msg_type == "A" {
            let heartbeat = required_u64(&message, 108)?;
            if heartbeat != self.config.heartbeat_interval_secs {
                return Err(SessionError::Protocol(format!(
                    "peer HeartBtInt {heartbeat} does not match configured {}",
                    self.config.heartbeat_interval_secs
                )));
            }
            if self.phase == SessionPhase::LogonSent {
                self.set_phase(SessionPhase::Established);
            }
        }
        if msg_type == "0"
            && let (Some(outstanding), Some(test_req_id)) =
                (&self.test_request, message.values(112).next())
            && outstanding.id.as_bytes() == test_req_id
        {
            self.test_request = None;
        }
        if msg_type == "5" {
            if self.phase != SessionPhase::LogoutSent {
                self.send_logout(None).await?;
            }
            self.set_phase(SessionPhase::Disconnected);
        }
        if let Some((begin, end)) = requested_resend {
            self.replay_range(begin, end).await?;
        }
        if let Some(test_request_id) = heartbeat_response {
            self.send_heartbeat_response(Some(&test_request_id)).await?;
        }

        Ok(())
    }

    async fn send_resend_request(&mut self, begin_seq_num: u64) -> Result<(), SessionError> {
        let mut fields = self.standard_header("2");
        fields.push(Field::new(7, Bytes::from(begin_seq_num.to_string())));
        fields.push(Field::new(16, Bytes::from_static(b"0")));
        let wire = self.encode_outbound(&fields)?;
        let request_id = format!("session:resend-request:{}", self.next_out);
        let reply = self
            .store
            .apply(StoreOp::CommitOutbound(OutboundCommit {
                request_id: request_id.clone(),
                fingerprint: format!("admin:2:{}:{}", self.next_out, begin_seq_num),
                cl_ord_id: String::new(),
                msg_seq_num: self.next_out,
                wire: wire.to_vec(),
                audit: AuditEvent {
                    kind: "resend_request_journaled".to_owned(),
                    details: BTreeMap::from([
                        ("msg_seq_num".to_owned(), self.next_out.to_string()),
                        ("begin_seq_num".to_owned(), begin_seq_num.to_string()),
                    ]),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Command(command) = reply else {
            return Err(SessionError::Store(
                "outbound commit returned an inbound record".to_owned(),
            ));
        };

        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        self.store
            .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
                request_id,
                msg_seq_num: command.msg_seq_num,
                audit: AuditEvent {
                    kind: "resend_request_written".to_owned(),
                    details: BTreeMap::new(),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        self.next_out = command.msg_seq_num + 1;
        Ok(())
    }

    async fn submit_application(
        &mut self,
        request: ApplicationRequest,
    ) -> Result<CommandRecord, SessionError> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::NotEstablished);
        }
        if request.msg_type.is_empty()
            || request
                .msg_type
                .as_bytes()
                .iter()
                .any(|byte| matches!(*byte, b'=' | 0x01))
        {
            return Err(SessionError::InvalidApplication(
                "MsgType is empty or contains a delimiter".to_owned(),
            ));
        }
        if request.fields.iter().any(|field| {
            matches!(
                field.tag,
                8 | 9 | 10 | 11 | 34 | 35 | 43 | 49 | 52 | 56 | 60 | 122
            )
        }) {
            return Err(SessionError::InvalidApplication(
                "request contains a daemon-managed tag".to_owned(),
            ));
        }

        let mut fields = self.standard_header(&request.msg_type);
        fields.push(Field::new(
            11,
            Bytes::copy_from_slice(request.cl_ord_id.as_bytes()),
        ));
        let requires_transact_time = matches!(request.msg_type.as_str(), "D" | "F" | "G");
        let mut transact_time_added = false;
        for field in request.fields {
            let is_side = field.tag == 54;
            fields.push(field);
            if requires_transact_time && is_side {
                fields.push(Field::new(60, Bytes::from(self.time_source.sending_time())));
                transact_time_added = true;
            }
        }
        if requires_transact_time && !transact_time_added {
            return Err(SessionError::InvalidApplication(
                "order message is missing Side(54)".to_owned(),
            ));
        }
        let wire = self.encode_outbound(&fields)?;
        let reply = self
            .store
            .apply(StoreOp::CommitOutbound(OutboundCommit {
                request_id: request.request_id.clone(),
                fingerprint: request.fingerprint,
                cl_ord_id: request.cl_ord_id,
                msg_seq_num: self.next_out,
                wire: wire.to_vec(),
                audit: AuditEvent {
                    kind: "application_journaled".to_owned(),
                    details: BTreeMap::from([
                        ("request_id".to_owned(), request.request_id.clone()),
                        ("msg_type".to_owned(), request.msg_type),
                        ("msg_seq_num".to_owned(), self.next_out.to_string()),
                    ]),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Command(command) = reply else {
            return Err(SessionError::Store(
                "outbound commit returned an inbound record".to_owned(),
            ));
        };

        if command.msg_seq_num < self.next_out {
            return Ok(command);
        }
        if command.msg_seq_num != self.next_out {
            return Err(SessionError::Store(format!(
                "store returned future outbound sequence {}",
                command.msg_seq_num
            )));
        }

        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        let reply = self
            .store
            .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
                request_id: request.request_id,
                msg_seq_num: command.msg_seq_num,
                audit: AuditEvent {
                    kind: "application_written".to_owned(),
                    details: BTreeMap::from([(
                        "msg_seq_num".to_owned(),
                        command.msg_seq_num.to_string(),
                    )]),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Command(command) = reply else {
            return Err(SessionError::Store(
                "mark written returned an inbound record".to_owned(),
            ));
        };
        self.next_out = command.msg_seq_num + 1;
        Ok(command)
    }

    async fn send_heartbeat(&mut self) -> Result<(), SessionError> {
        self.send_heartbeat_response(None).await
    }

    async fn send_heartbeat_response(
        &mut self,
        test_request_id: Option<&[u8]>,
    ) -> Result<(), SessionError> {
        let mut fields = self.standard_header("0");
        if let Some(test_request_id) = test_request_id {
            fields.push(Field::new(112, Bytes::copy_from_slice(test_request_id)));
        }
        let wire = self.encode_outbound(&fields)?;
        let request_id = format!("session:heartbeat:{}", self.next_out);
        let reply = self
            .store
            .apply(StoreOp::CommitOutbound(OutboundCommit {
                request_id: request_id.clone(),
                fingerprint: format!("admin:0:{}", self.next_out),
                cl_ord_id: String::new(),
                msg_seq_num: self.next_out,
                wire: wire.to_vec(),
                audit: AuditEvent {
                    kind: "heartbeat_journaled".to_owned(),
                    details: BTreeMap::from([
                        ("msg_seq_num".to_owned(), self.next_out.to_string()),
                        (
                            "test_req_id".to_owned(),
                            test_request_id.map_or_else(String::new, |value| {
                                String::from_utf8_lossy(value).into_owned()
                            }),
                        ),
                    ]),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Command(command) = reply else {
            return Err(SessionError::Store(
                "heartbeat commit returned the wrong record type".to_owned(),
            ));
        };
        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        self.store
            .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
                request_id,
                msg_seq_num: command.msg_seq_num,
                audit: AuditEvent {
                    kind: "heartbeat_written".to_owned(),
                    details: BTreeMap::new(),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        self.next_out = command.msg_seq_num + 1;
        Ok(())
    }

    async fn send_test_request(&mut self, response_timeout: Duration) -> Result<(), SessionError> {
        let test_req_id = format!("TEST-{}", self.next_out);
        let mut fields = self.standard_header("1");
        fields.push(Field::new(
            112,
            Bytes::copy_from_slice(test_req_id.as_bytes()),
        ));
        let wire = self.encode_outbound(&fields)?;
        let request_id = format!("session:test-request:{}", self.next_out);
        let reply = self
            .store
            .apply(StoreOp::CommitOutbound(OutboundCommit {
                request_id: request_id.clone(),
                fingerprint: format!("admin:1:{}:{test_req_id}", self.next_out),
                cl_ord_id: String::new(),
                msg_seq_num: self.next_out,
                wire: wire.to_vec(),
                audit: AuditEvent {
                    kind: "test_request_journaled".to_owned(),
                    details: BTreeMap::from([
                        ("msg_seq_num".to_owned(), self.next_out.to_string()),
                        ("test_req_id".to_owned(), test_req_id.clone()),
                    ]),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Command(command) = reply else {
            return Err(SessionError::Store(
                "TestRequest commit returned the wrong record type".to_owned(),
            ));
        };
        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        self.store
            .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
                request_id,
                msg_seq_num: command.msg_seq_num,
                audit: AuditEvent {
                    kind: "test_request_written".to_owned(),
                    details: BTreeMap::new(),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        self.next_out = command.msg_seq_num + 1;
        self.test_request = Some(TestRequestOutstanding {
            id: test_req_id,
            deadline: Instant::now() + response_timeout,
        });
        Ok(())
    }

    async fn send_logout(&mut self, text: Option<String>) -> Result<(), SessionError> {
        if !matches!(
            self.phase,
            SessionPhase::LogonSent
                | SessionPhase::Synchronizing
                | SessionPhase::Established
                | SessionPhase::Recovering
        ) {
            return Err(SessionError::Protocol(format!(
                "cannot send Logout while session is {:?}",
                self.phase
            )));
        }
        let mut fields = self.standard_header("5");
        if let Some(text) = text {
            fields.push(Field::new(58, Bytes::from(text)));
        }
        let wire = self.encode_outbound(&fields)?;
        let request_id = format!("session:logout:{}", self.next_out);
        let reply = self
            .store
            .apply(StoreOp::CommitOutbound(OutboundCommit {
                request_id: request_id.clone(),
                fingerprint: format!("admin:5:{}", self.next_out),
                cl_ord_id: String::new(),
                msg_seq_num: self.next_out,
                wire: wire.to_vec(),
                audit: AuditEvent {
                    kind: "logout_journaled".to_owned(),
                    details: BTreeMap::from([(
                        "msg_seq_num".to_owned(),
                        self.next_out.to_string(),
                    )]),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Command(command) = reply else {
            return Err(SessionError::Store(
                "Logout commit returned the wrong record type".to_owned(),
            ));
        };
        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        self.store
            .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
                request_id,
                msg_seq_num: command.msg_seq_num,
                audit: AuditEvent {
                    kind: "logout_written".to_owned(),
                    details: BTreeMap::new(),
                },
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        self.next_out = command.msg_seq_num + 1;
        self.set_phase(SessionPhase::LogoutSent);
        Ok(())
    }

    async fn replay_range(
        &mut self,
        begin_seq_num: u64,
        requested_end_seq_num: u64,
    ) -> Result<(), SessionError> {
        let end_seq_num = if requested_end_seq_num == 0 {
            self.next_out.saturating_sub(1)
        } else {
            requested_end_seq_num.min(self.next_out.saturating_sub(1))
        };
        if begin_seq_num == 0 || begin_seq_num > end_seq_num {
            return Err(SessionError::Protocol(format!(
                "invalid ResendRequest range {begin_seq_num}..={requested_end_seq_num}"
            )));
        }

        let reply = self
            .store
            .apply(StoreOp::LoadOutboundRange(OutboundRange {
                begin: begin_seq_num,
                end: end_seq_num,
            }))
            .await
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let StoreReply::Outbound(records) = reply else {
            return Err(SessionError::Store(
                "outbound range query returned the wrong record type".to_owned(),
            ));
        };

        let records = records
            .into_iter()
            .map(|record| (record.command.msg_seq_num, record))
            .collect::<BTreeMap<_, _>>();
        let mut gap_start = None;

        for sequence in begin_seq_num..=end_seq_num {
            match records.get(&sequence) {
                Some(record) if !record.command.cl_ord_id.is_empty() => {
                    if let Some(start) = gap_start.take() {
                        self.write_gap_fill(start, sequence).await?;
                    }
                    self.write_application_replay(&record.wire).await?;
                }
                _ => {
                    gap_start.get_or_insert(sequence);
                }
            }
        }
        if let Some(start) = gap_start {
            self.write_gap_fill(start, end_seq_num + 1).await?;
        }
        Ok(())
    }

    async fn write_application_replay(&mut self, wire: &[u8]) -> Result<(), SessionError> {
        let original = parse_frame(wire, &ParseDictionary::new())
            .map_err(|error| SessionError::Codec(error.to_string()))?;
        let original_sending_time = required_value(&original, 52)?.to_vec();
        let mut replay_fields = Vec::with_capacity(original.fields.len() + 2);
        for field in original.fields {
            match field.tag {
                43 | 122 => {}
                34 => {
                    replay_fields.push(field);
                    replay_fields.push(Field::new(43, Bytes::from_static(b"Y")));
                }
                52 => {
                    replay_fields
                        .push(Field::new(52, Bytes::from(self.time_source.sending_time())));
                    replay_fields.push(Field::new(122, Bytes::from(original_sending_time.clone())));
                }
                _ => replay_fields.push(field),
            }
        }
        let replay = self.encode_outbound(&replay_fields)?;
        self.writer
            .write_all(&replay)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        Ok(())
    }

    async fn write_gap_fill(
        &mut self,
        gap_start: u64,
        new_seq_num: u64,
    ) -> Result<(), SessionError> {
        let now = self.time_source.sending_time();
        let fields = vec![
            Field::new(35, Bytes::from_static(b"4")),
            Field::new(
                49,
                Bytes::copy_from_slice(self.config.sender_comp_id.as_bytes()),
            ),
            Field::new(
                56,
                Bytes::copy_from_slice(self.config.target_comp_id.as_bytes()),
            ),
            Field::new(34, Bytes::from(gap_start.to_string())),
            Field::new(43, Bytes::from_static(b"Y")),
            Field::new(52, Bytes::copy_from_slice(now.as_bytes())),
            Field::new(122, Bytes::from(now)),
            Field::new(123, Bytes::from_static(b"Y")),
            Field::new(36, Bytes::from(new_seq_num.to_string())),
        ];
        let wire = self.encode_outbound(&fields)?;
        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|error| SessionError::Transport(error.to_string()))?;
        self.last_outbound = Instant::now();
        Ok(())
    }

    fn standard_header(&self, msg_type: &str) -> Vec<Field> {
        vec![
            Field::new(35, Bytes::copy_from_slice(msg_type.as_bytes())),
            Field::new(
                49,
                Bytes::copy_from_slice(self.config.sender_comp_id.as_bytes()),
            ),
            Field::new(
                56,
                Bytes::copy_from_slice(self.config.target_comp_id.as_bytes()),
            ),
            Field::new(34, Bytes::from(self.next_out.to_string())),
            Field::new(52, Bytes::from(self.time_source.sending_time())),
        ]
    }

    fn encode_outbound(&self, fields: &[Field]) -> Result<Bytes, SessionError> {
        let wire = encode_message(self.config.begin_string.as_bytes(), fields)
            .map_err(|error| SessionError::Codec(error.to_string()))?;
        if let Some(dictionary) = &self.dictionary {
            let message = parse_frame(&wire, &self.parse_dictionary)
                .map_err(|error| SessionError::Codec(error.to_string()))?;
            dictionary
                .validate(message)
                .map_err(|error| SessionError::Protocol(error.to_string()))?;
        }
        Ok(wire)
    }

    fn set_phase(&mut self, phase: SessionPhase) {
        self.phase = phase;
        let _ = self.events.send(SessionEvent::PhaseChanged(phase));
    }
}

fn required_value(message: &ParsedMessage, tag: u32) -> Result<&[u8], SessionError> {
    message
        .values(tag)
        .next()
        .ok_or_else(|| SessionError::Protocol(format!("required tag {tag} is missing")))
}

fn required_u64(message: &ParsedMessage, tag: u32) -> Result<u64, SessionError> {
    let value = required_value(message, tag)?;
    let value = std::str::from_utf8(value)
        .map_err(|_| SessionError::Protocol(format!("tag {tag} is not ASCII")))?;
    value
        .parse()
        .map_err(|_| SessionError::Protocol(format!("tag {tag} is not an unsigned integer")))
}

fn same_replay_payload(original: &ParsedMessage, replay: &ParsedMessage) -> bool {
    let original = original
        .fields
        .iter()
        .filter(|field| !matches!(field.tag, 43 | 52 | 122))
        .map(|field| (field.tag, field.value.clone()))
        .collect::<Vec<_>>();
    let replay = replay
        .fields
        .iter()
        .filter(|field| !matches!(field.tag, 43 | 52 | 122))
        .map(|field| (field.tag, field.value.clone()))
        .collect::<Vec<_>>();
    original == replay
}

fn event_kind(msg_type: &str) -> &'static str {
    match msg_type {
        "A" => "session_logon",
        "5" => "session_logout",
        "8" => "execution_report",
        _ => "fix_message",
    }
}
