#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::mpsc;
use thiserror::Error;
use tokio::sync::oneshot;

type HmacSha256 = Hmac<Sha256>;

const META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("meta");
const COMMAND_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("commands");
const OUTBOUND_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("outbound");
const TRANSMISSION_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("transmissions");
const INBOUND_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("inbound");
const EVENT_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events");
const AUDIT_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryState {
    pub next_out: u64,
    pub next_in: u64,
    pub next_event: u64,
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            next_out: 1,
            next_in: 1,
            next_event: 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommandPhase {
    Journaled,
    Written,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRecord {
    pub request_id: String,
    pub fingerprint: String,
    pub cl_ord_id: String,
    pub msg_seq_num: u64,
    pub phase: CommandPhase,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundRecord {
    pub command: CommandRecord,
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransmissionPhase {
    Journaled,
    Written,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransmissionRecord {
    pub id: u64,
    pub msg_seq_num: u64,
    pub kind: String,
    pub wire: Vec<u8>,
    pub phase: TransmissionPhase,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub kind: String,
    pub details: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: u64,
    pub event: AuditEvent,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventRecord {
    pub id: u64,
    pub kind: String,
    pub details: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundRecord {
    pub msg_seq_num: u64,
    pub msg_type: String,
    pub wire: Vec<u8>,
    pub event_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundCommit {
    pub request_id: String,
    pub fingerprint: String,
    pub cl_ord_id: String,
    pub msg_seq_num: u64,
    pub wire: Vec<u8>,
    pub audit: AuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkOutboundWritten {
    pub request_id: String,
    pub msg_seq_num: u64,
    pub audit: AuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransmissionCommit {
    pub msg_seq_num: u64,
    pub kind: String,
    pub wire: Vec<u8>,
    pub audit: AuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkTransmissionWritten {
    pub id: u64,
    pub audit: AuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundCommit {
    pub msg_seq_num: u64,
    pub next_in_after: u64,
    pub msg_type: String,
    pub wire: Vec<u8>,
    pub event: EventRecord,
    pub audit: AuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundRange {
    pub begin: u64,
    pub end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreOp {
    CommitOutbound(OutboundCommit),
    MarkOutboundWritten(MarkOutboundWritten),
    CommitTransmission(TransmissionCommit),
    MarkTransmissionWritten(MarkTransmissionWritten),
    CommitInbound(InboundCommit),
    LoadCommand(String),
    LoadOutboundRange(OutboundRange),
    LoadInbound(u64),
    LoadTransmission(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreReply {
    Command(CommandRecord),
    StoredCommand(Option<CommandRecord>),
    Transmission(TransmissionRecord),
    StoredTransmission(Option<TransmissionRecord>),
    Inbound(InboundRecord),
    StoredInbound(Option<InboundRecord>),
    Outbound(Vec<OutboundRecord>),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("request ID {request_id} was reused with a different fingerprint")]
    IdempotencyConflict { request_id: String },
    #[error("expected outbound sequence {expected}, got {actual}")]
    OutboundSequenceMismatch { expected: u64, actual: u64 },
    #[error("expected inbound sequence {expected}, got {actual}")]
    InboundSequenceMismatch { expected: u64, actual: u64 },
    #[error("expected event ID {expected}, got {actual}")]
    EventSequenceMismatch { expected: u64, actual: u64 },
    #[error("next inbound sequence {next_in_after} must be greater than current {current}")]
    InvalidNextInbound { current: u64, next_in_after: u64 },
    #[error("could not serialize audit event: {0}")]
    AuditSerialization(String),
    #[error("could not initialize audit HMAC")]
    InvalidAuditKey,
    #[error("audit chain verification failed at record {id}")]
    AuditChainInvalid { id: u64 },
    #[error("request ID {0} is not present in the journal")]
    UnknownCommand(String),
    #[error("transmission ID {0} is not present in the journal")]
    UnknownTransmission(u64),
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("stored record could not be decoded: {0}")]
    Decode(String),
    #[error("store worker stopped")]
    WorkerStopped,
}

pub trait StorePort: Send + 'static {
    fn recover(&mut self) -> Result<RecoveryState, StoreError>;
    fn apply(&mut self, operation: StoreOp) -> Result<StoreReply, StoreError>;
}

enum WorkerRequest {
    Recover(oneshot::Sender<Result<RecoveryState, StoreError>>),
    Apply(StoreOp, oneshot::Sender<Result<StoreReply, StoreError>>),
}

#[derive(Clone)]
pub struct StoreHandle {
    requests: mpsc::Sender<WorkerRequest>,
}

impl StoreHandle {
    pub async fn recover(&self) -> Result<RecoveryState, StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(WorkerRequest::Recover(reply_tx))
            .map_err(|_| StoreError::WorkerStopped)?;
        reply_rx.await.map_err(|_| StoreError::WorkerStopped)?
    }

    pub async fn apply(&self, operation: StoreOp) -> Result<StoreReply, StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(WorkerRequest::Apply(operation, reply_tx))
            .map_err(|_| StoreError::WorkerStopped)?;
        reply_rx.await.map_err(|_| StoreError::WorkerStopped)?
    }
}

pub struct StoreWorker;

impl StoreWorker {
    #[must_use]
    pub fn spawn<S>(mut store: S) -> StoreHandle
    where
        S: StorePort,
    {
        let (request_tx, request_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("fix-store".to_owned())
            .spawn(move || {
                while let Ok(request) = request_rx.recv() {
                    match request {
                        WorkerRequest::Recover(reply) => {
                            let _ = reply.send(store.recover());
                        }
                        WorkerRequest::Apply(operation, reply) => {
                            let _ = reply.send(store.apply(operation));
                        }
                    }
                }
            })
            .expect("store worker thread must start");

        StoreHandle {
            requests: request_tx,
        }
    }
}

pub struct MemoryStore {
    audit_key: Vec<u8>,
    recovery: RecoveryState,
    commands: BTreeMap<String, CommandRecord>,
    outbound: BTreeMap<u64, OutboundRecord>,
    next_transmission: u64,
    transmissions: BTreeMap<u64, TransmissionRecord>,
    inbound: BTreeMap<u64, InboundRecord>,
    events: BTreeMap<u64, EventRecord>,
    audit: Vec<AuditRecord>,
}

impl MemoryStore {
    #[must_use]
    pub fn new(audit_key: &[u8]) -> Self {
        Self {
            audit_key: audit_key.to_vec(),
            recovery: RecoveryState::default(),
            commands: BTreeMap::new(),
            outbound: BTreeMap::new(),
            next_transmission: 1,
            transmissions: BTreeMap::new(),
            inbound: BTreeMap::new(),
            events: BTreeMap::new(),
            audit: Vec::new(),
        }
    }

    #[must_use]
    pub fn audit_records(&self) -> &[AuditRecord] {
        &self.audit
    }

    #[must_use]
    pub fn events(&self) -> Vec<&EventRecord> {
        self.events.values().collect()
    }

    fn commit_outbound(&mut self, commit: OutboundCommit) -> Result<StoreReply, StoreError> {
        if let Some(existing) = self.commands.get(&commit.request_id) {
            if existing.fingerprint != commit.fingerprint {
                return Err(StoreError::IdempotencyConflict {
                    request_id: commit.request_id,
                });
            }
            return Ok(StoreReply::Command(existing.clone()));
        }
        if commit.msg_seq_num != self.recovery.next_out {
            return Err(StoreError::OutboundSequenceMismatch {
                expected: self.recovery.next_out,
                actual: commit.msg_seq_num,
            });
        }

        let command = CommandRecord {
            request_id: commit.request_id,
            fingerprint: commit.fingerprint,
            cl_ord_id: commit.cl_ord_id,
            msg_seq_num: commit.msg_seq_num,
            phase: CommandPhase::Journaled,
        };
        let audit = make_audit_record(&self.audit_key, self.audit.last(), commit.audit)?;

        self.outbound.insert(
            commit.msg_seq_num,
            OutboundRecord {
                command: command.clone(),
                wire: commit.wire,
            },
        );
        self.commands
            .insert(command.request_id.clone(), command.clone());
        self.recovery.next_out += 1;
        self.audit.push(audit);

        Ok(StoreReply::Command(command))
    }

    fn mark_outbound_written(
        &mut self,
        mark: MarkOutboundWritten,
    ) -> Result<StoreReply, StoreError> {
        let existing = self
            .commands
            .get(&mark.request_id)
            .cloned()
            .ok_or_else(|| StoreError::UnknownCommand(mark.request_id.clone()))?;
        if existing.msg_seq_num != mark.msg_seq_num {
            return Err(StoreError::OutboundSequenceMismatch {
                expected: existing.msg_seq_num,
                actual: mark.msg_seq_num,
            });
        }
        let audit = make_audit_record(&self.audit_key, self.audit.last(), mark.audit)?;
        let mut command = existing;
        command.phase = CommandPhase::Written;

        self.commands
            .insert(command.request_id.clone(), command.clone());
        let outbound = self
            .outbound
            .get_mut(&mark.msg_seq_num)
            .ok_or_else(|| StoreError::UnknownCommand(mark.request_id.clone()))?;
        outbound.command = command.clone();
        self.audit.push(audit);

        Ok(StoreReply::Command(command))
    }

    fn commit_transmission(
        &mut self,
        commit: TransmissionCommit,
    ) -> Result<StoreReply, StoreError> {
        let record = TransmissionRecord {
            id: self.next_transmission,
            msg_seq_num: commit.msg_seq_num,
            kind: commit.kind,
            wire: commit.wire,
            phase: TransmissionPhase::Journaled,
        };
        let audit = make_audit_record(&self.audit_key, self.audit.last(), commit.audit)?;
        self.transmissions.insert(record.id, record.clone());
        self.next_transmission += 1;
        self.audit.push(audit);
        Ok(StoreReply::Transmission(record))
    }

    fn mark_transmission_written(
        &mut self,
        mark: MarkTransmissionWritten,
    ) -> Result<StoreReply, StoreError> {
        let mut record = self
            .transmissions
            .get(&mark.id)
            .cloned()
            .ok_or(StoreError::UnknownTransmission(mark.id))?;
        let audit = make_audit_record(&self.audit_key, self.audit.last(), mark.audit)?;
        record.phase = TransmissionPhase::Written;
        self.transmissions.insert(record.id, record.clone());
        self.audit.push(audit);
        Ok(StoreReply::Transmission(record))
    }

    fn commit_inbound(&mut self, commit: InboundCommit) -> Result<StoreReply, StoreError> {
        if commit.msg_seq_num != self.recovery.next_in {
            return Err(StoreError::InboundSequenceMismatch {
                expected: self.recovery.next_in,
                actual: commit.msg_seq_num,
            });
        }
        if commit.event.id != self.recovery.next_event {
            return Err(StoreError::EventSequenceMismatch {
                expected: self.recovery.next_event,
                actual: commit.event.id,
            });
        }
        if commit.next_in_after <= self.recovery.next_in {
            return Err(StoreError::InvalidNextInbound {
                current: self.recovery.next_in,
                next_in_after: commit.next_in_after,
            });
        }

        let record = InboundRecord {
            msg_seq_num: commit.msg_seq_num,
            msg_type: commit.msg_type,
            wire: commit.wire,
            event_id: commit.event.id,
        };
        let audit = make_audit_record(&self.audit_key, self.audit.last(), commit.audit)?;

        self.inbound.insert(record.msg_seq_num, record.clone());
        self.events.insert(commit.event.id, commit.event);
        self.recovery.next_in = commit.next_in_after;
        self.recovery.next_event += 1;
        self.audit.push(audit);

        Ok(StoreReply::Inbound(record))
    }

    fn load_outbound_range(&self, range: OutboundRange) -> StoreReply {
        StoreReply::Outbound(
            self.outbound
                .range(range.begin..=range.end)
                .map(|(_, record)| record.clone())
                .collect(),
        )
    }

    fn load_inbound(&self, sequence: u64) -> StoreReply {
        StoreReply::StoredInbound(self.inbound.get(&sequence).cloned())
    }

    fn load_command(&self, request_id: &str) -> StoreReply {
        StoreReply::StoredCommand(self.commands.get(request_id).cloned())
    }

    fn load_transmission(&self, id: u64) -> StoreReply {
        StoreReply::StoredTransmission(self.transmissions.get(&id).cloned())
    }
}

impl StorePort for MemoryStore {
    fn recover(&mut self) -> Result<RecoveryState, StoreError> {
        Ok(self.recovery.clone())
    }

    fn apply(&mut self, operation: StoreOp) -> Result<StoreReply, StoreError> {
        match operation {
            StoreOp::CommitOutbound(commit) => self.commit_outbound(commit),
            StoreOp::MarkOutboundWritten(mark) => self.mark_outbound_written(mark),
            StoreOp::CommitTransmission(commit) => self.commit_transmission(commit),
            StoreOp::MarkTransmissionWritten(mark) => self.mark_transmission_written(mark),
            StoreOp::CommitInbound(commit) => self.commit_inbound(commit),
            StoreOp::LoadCommand(request_id) => Ok(self.load_command(&request_id)),
            StoreOp::LoadOutboundRange(range) => Ok(self.load_outbound_range(range)),
            StoreOp::LoadInbound(sequence) => Ok(self.load_inbound(sequence)),
            StoreOp::LoadTransmission(id) => Ok(self.load_transmission(id)),
        }
    }
}

pub struct RedbStore {
    database: Database,
    audit_key: Vec<u8>,
}

impl RedbStore {
    pub fn open(path: impl AsRef<Path>, audit_key: &[u8]) -> Result<Self, StoreError> {
        let database =
            Database::create(path).map_err(|error| StoreError::Backend(error.to_string()))?;
        let store = Self {
            database,
            audit_key: audit_key.to_vec(),
        };
        store.initialize()?;
        store.verify_audit_chain()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            if meta
                .get("next_out")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .is_none()
            {
                meta.insert("next_out", 1)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
            }
            if meta
                .get("next_in")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .is_none()
            {
                meta.insert("next_in", 1)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
            }
            if meta
                .get("next_audit")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .is_none()
            {
                meta.insert("next_audit", 1)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
            }
            if meta
                .get("next_event")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .is_none()
            {
                meta.insert("next_event", 1)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
            }
            if meta
                .get("next_transmission")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .is_none()
            {
                meta.insert("next_transmission", 1)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
            }
        }
        transaction
            .open_table(COMMAND_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .open_table(OUTBOUND_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .open_table(TRANSMISSION_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .open_table(INBOUND_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .open_table(EVENT_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .open_table(AUDIT_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    fn verify_audit_chain(&self) -> Result<(), StoreError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let meta = transaction
            .open_table(META_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let next_audit = meta
            .get("next_audit")
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .ok_or_else(|| StoreError::Decode("next_audit is missing".to_owned()))?
            .value();
        let audit = transaction
            .open_table(AUDIT_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let mut previous = None::<AuditRecord>;

        for id in 1..next_audit {
            let record = audit
                .get(id)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or(StoreError::AuditChainInvalid { id })?;
            let record: AuditRecord = serde_json::from_slice(record.value())
                .map_err(|_| StoreError::AuditChainInvalid { id })?;
            let expected =
                make_audit_record(&self.audit_key, previous.as_ref(), record.event.clone())?;
            if record != expected {
                return Err(StoreError::AuditChainInvalid { id });
            }
            previous = Some(record);
        }
        Ok(())
    }

    fn commit_outbound(&mut self, commit: OutboundCommit) -> Result<StoreReply, StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        let existing = {
            let commands = transaction
                .open_table(COMMAND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            commands
                .get(commit.request_id.as_str())
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| record.value().to_vec())
        };
        if let Some(existing) = existing {
            let existing: CommandRecord = serde_json::from_slice(&existing)
                .map_err(|error| StoreError::Decode(error.to_string()))?;
            if existing.fingerprint != commit.fingerprint {
                return Err(StoreError::IdempotencyConflict {
                    request_id: commit.request_id,
                });
            }
            return Ok(StoreReply::Command(existing));
        }

        let (next_out, next_audit) = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let next_out = meta
                .get("next_out")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_out is missing".to_owned()))?
                .value();
            let next_audit = meta
                .get("next_audit")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_audit is missing".to_owned()))?
                .value();
            (next_out, next_audit)
        };
        if commit.msg_seq_num != next_out {
            return Err(StoreError::OutboundSequenceMismatch {
                expected: next_out,
                actual: commit.msg_seq_num,
            });
        }

        let previous_audit = if next_audit == 1 {
            None
        } else {
            let audit = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit
                .get(next_audit - 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| {
                    serde_json::from_slice::<AuditRecord>(record.value())
                        .map_err(|error| StoreError::Decode(error.to_string()))
                })
                .transpose()?
        };

        let command = CommandRecord {
            request_id: commit.request_id,
            fingerprint: commit.fingerprint,
            cl_ord_id: commit.cl_ord_id,
            msg_seq_num: commit.msg_seq_num,
            phase: CommandPhase::Journaled,
        };
        let outbound = OutboundRecord {
            command: command.clone(),
            wire: commit.wire,
        };
        let audit = make_audit_record(&self.audit_key, previous_audit.as_ref(), commit.audit)?;
        let command_bytes =
            serde_json::to_vec(&command).map_err(|error| StoreError::Decode(error.to_string()))?;
        let outbound_bytes =
            serde_json::to_vec(&outbound).map_err(|error| StoreError::Decode(error.to_string()))?;
        let audit_bytes =
            serde_json::to_vec(&audit).map_err(|error| StoreError::Decode(error.to_string()))?;

        {
            let mut commands = transaction
                .open_table(COMMAND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            commands
                .insert(command.request_id.as_str(), command_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut outbound_table = transaction
                .open_table(OUTBOUND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            outbound_table
                .insert(command.msg_seq_num, outbound_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut audit_table = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit_table
                .insert(audit.id, audit_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_out", next_out + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_audit", next_audit + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::Command(command))
    }

    fn mark_outbound_written(
        &mut self,
        mark: MarkOutboundWritten,
    ) -> Result<StoreReply, StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        let command_bytes = {
            let commands = transaction
                .open_table(COMMAND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            commands
                .get(mark.request_id.as_str())
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| record.value().to_vec())
                .ok_or_else(|| StoreError::UnknownCommand(mark.request_id.clone()))?
        };
        let mut command: CommandRecord = serde_json::from_slice(&command_bytes)
            .map_err(|error| StoreError::Decode(error.to_string()))?;
        if command.msg_seq_num != mark.msg_seq_num {
            return Err(StoreError::OutboundSequenceMismatch {
                expected: command.msg_seq_num,
                actual: mark.msg_seq_num,
            });
        }

        let outbound_bytes = {
            let outbound = transaction
                .open_table(OUTBOUND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            outbound
                .get(mark.msg_seq_num)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| record.value().to_vec())
                .ok_or_else(|| StoreError::UnknownCommand(mark.request_id.clone()))?
        };
        let mut outbound: OutboundRecord = serde_json::from_slice(&outbound_bytes)
            .map_err(|error| StoreError::Decode(error.to_string()))?;

        let next_audit = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.get("next_audit")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_audit is missing".to_owned()))?
                .value()
        };
        let previous = {
            let audit = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit
                .get(next_audit - 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| {
                    serde_json::from_slice::<AuditRecord>(record.value())
                        .map_err(|error| StoreError::Decode(error.to_string()))
                })
                .transpose()?
        };

        command.phase = CommandPhase::Written;
        outbound.command = command.clone();
        let audit = make_audit_record(&self.audit_key, previous.as_ref(), mark.audit)?;
        let command_bytes =
            serde_json::to_vec(&command).map_err(|error| StoreError::Decode(error.to_string()))?;
        let outbound_bytes =
            serde_json::to_vec(&outbound).map_err(|error| StoreError::Decode(error.to_string()))?;
        let audit_bytes =
            serde_json::to_vec(&audit).map_err(|error| StoreError::Decode(error.to_string()))?;

        {
            let mut commands = transaction
                .open_table(COMMAND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            commands
                .insert(command.request_id.as_str(), command_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut outbound_table = transaction
                .open_table(OUTBOUND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            outbound_table
                .insert(mark.msg_seq_num, outbound_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut audit_table = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit_table
                .insert(audit.id, audit_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_audit", next_audit + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::Command(command))
    }

    fn commit_transmission(
        &mut self,
        commit: TransmissionCommit,
    ) -> Result<StoreReply, StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        let (next_transmission, next_audit) = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let next_transmission = meta
                .get("next_transmission")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_transmission is missing".to_owned()))?
                .value();
            let next_audit = meta
                .get("next_audit")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_audit is missing".to_owned()))?
                .value();
            (next_transmission, next_audit)
        };
        let previous = if next_audit == 1 {
            None
        } else {
            let audit = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit
                .get(next_audit - 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| {
                    serde_json::from_slice::<AuditRecord>(record.value())
                        .map_err(|error| StoreError::Decode(error.to_string()))
                })
                .transpose()?
        };
        let record = TransmissionRecord {
            id: next_transmission,
            msg_seq_num: commit.msg_seq_num,
            kind: commit.kind,
            wire: commit.wire,
            phase: TransmissionPhase::Journaled,
        };
        let audit = make_audit_record(&self.audit_key, previous.as_ref(), commit.audit)?;
        let record_bytes =
            serde_json::to_vec(&record).map_err(|error| StoreError::Decode(error.to_string()))?;
        let audit_bytes =
            serde_json::to_vec(&audit).map_err(|error| StoreError::Decode(error.to_string()))?;

        {
            let mut transmissions = transaction
                .open_table(TRANSMISSION_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            transmissions
                .insert(record.id, record_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut audit_table = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit_table
                .insert(audit.id, audit_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_transmission", next_transmission + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_audit", next_audit + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::Transmission(record))
    }

    fn mark_transmission_written(
        &mut self,
        mark: MarkTransmissionWritten,
    ) -> Result<StoreReply, StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        let record_bytes = {
            let transmissions = transaction
                .open_table(TRANSMISSION_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            transmissions
                .get(mark.id)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| record.value().to_vec())
                .ok_or(StoreError::UnknownTransmission(mark.id))?
        };
        let mut record: TransmissionRecord = serde_json::from_slice(&record_bytes)
            .map_err(|error| StoreError::Decode(error.to_string()))?;
        let next_audit = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.get("next_audit")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_audit is missing".to_owned()))?
                .value()
        };
        let previous = if next_audit == 1 {
            None
        } else {
            let audit = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit
                .get(next_audit - 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| {
                    serde_json::from_slice::<AuditRecord>(record.value())
                        .map_err(|error| StoreError::Decode(error.to_string()))
                })
                .transpose()?
        };

        record.phase = TransmissionPhase::Written;
        let audit = make_audit_record(&self.audit_key, previous.as_ref(), mark.audit)?;
        let record_bytes =
            serde_json::to_vec(&record).map_err(|error| StoreError::Decode(error.to_string()))?;
        let audit_bytes =
            serde_json::to_vec(&audit).map_err(|error| StoreError::Decode(error.to_string()))?;

        {
            let mut transmissions = transaction
                .open_table(TRANSMISSION_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            transmissions
                .insert(record.id, record_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut audit_table = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit_table
                .insert(audit.id, audit_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_audit", next_audit + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::Transmission(record))
    }

    fn commit_inbound(&mut self, commit: InboundCommit) -> Result<StoreReply, StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        let (next_in, next_event, next_audit) = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let next_in = meta
                .get("next_in")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_in is missing".to_owned()))?
                .value();
            let next_event = meta
                .get("next_event")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_event is missing".to_owned()))?
                .value();
            let next_audit = meta
                .get("next_audit")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_audit is missing".to_owned()))?
                .value();
            (next_in, next_event, next_audit)
        };
        if commit.msg_seq_num != next_in {
            return Err(StoreError::InboundSequenceMismatch {
                expected: next_in,
                actual: commit.msg_seq_num,
            });
        }
        if commit.event.id != next_event {
            return Err(StoreError::EventSequenceMismatch {
                expected: next_event,
                actual: commit.event.id,
            });
        }
        if commit.next_in_after <= next_in {
            return Err(StoreError::InvalidNextInbound {
                current: next_in,
                next_in_after: commit.next_in_after,
            });
        }

        let previous = if next_audit == 1 {
            None
        } else {
            let audit = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit
                .get(next_audit - 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| {
                    serde_json::from_slice::<AuditRecord>(record.value())
                        .map_err(|error| StoreError::Decode(error.to_string()))
                })
                .transpose()?
        };
        let record = InboundRecord {
            msg_seq_num: commit.msg_seq_num,
            msg_type: commit.msg_type,
            wire: commit.wire,
            event_id: commit.event.id,
        };
        let audit = make_audit_record(&self.audit_key, previous.as_ref(), commit.audit)?;
        let record_bytes =
            serde_json::to_vec(&record).map_err(|error| StoreError::Decode(error.to_string()))?;
        let event_bytes = serde_json::to_vec(&commit.event)
            .map_err(|error| StoreError::Decode(error.to_string()))?;
        let audit_bytes =
            serde_json::to_vec(&audit).map_err(|error| StoreError::Decode(error.to_string()))?;

        {
            let mut inbound = transaction
                .open_table(INBOUND_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            inbound
                .insert(record.msg_seq_num, record_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut events = transaction
                .open_table(EVENT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            events
                .insert(commit.event.id, event_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut audit_table = transaction
                .open_table(AUDIT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            audit_table
                .insert(audit.id, audit_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_in", commit.next_in_after)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_event", next_event + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_audit", next_audit + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::Inbound(record))
    }

    fn load_outbound_range(&self, range: OutboundRange) -> Result<StoreReply, StoreError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let outbound = transaction
            .open_table(OUTBOUND_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let mut records = Vec::new();

        for sequence in range.begin..=range.end {
            let record = outbound
                .get(sequence)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|record| {
                    serde_json::from_slice::<OutboundRecord>(record.value())
                        .map_err(|error| StoreError::Decode(error.to_string()))
                })
                .transpose()?;
            if let Some(record) = record {
                records.push(record);
            }
        }

        Ok(StoreReply::Outbound(records))
    }

    fn load_inbound(&self, sequence: u64) -> Result<StoreReply, StoreError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let inbound = transaction
            .open_table(INBOUND_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let record = inbound
            .get(sequence)
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .map(|record| {
                serde_json::from_slice::<InboundRecord>(record.value())
                    .map_err(|error| StoreError::Decode(error.to_string()))
            })
            .transpose()?;
        Ok(StoreReply::StoredInbound(record))
    }

    fn load_command(&self, request_id: &str) -> Result<StoreReply, StoreError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let commands = transaction
            .open_table(COMMAND_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let record = commands
            .get(request_id)
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .map(|record| {
                serde_json::from_slice::<CommandRecord>(record.value())
                    .map_err(|error| StoreError::Decode(error.to_string()))
            })
            .transpose()?;
        Ok(StoreReply::StoredCommand(record))
    }

    fn load_transmission(&self, id: u64) -> Result<StoreReply, StoreError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let transmissions = transaction
            .open_table(TRANSMISSION_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let record = transmissions
            .get(id)
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .map(|record| {
                serde_json::from_slice::<TransmissionRecord>(record.value())
                    .map_err(|error| StoreError::Decode(error.to_string()))
            })
            .transpose()?;
        Ok(StoreReply::StoredTransmission(record))
    }
}

impl StorePort for RedbStore {
    fn recover(&mut self) -> Result<RecoveryState, StoreError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let meta = transaction
            .open_table(META_TABLE)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let next_out = meta
            .get("next_out")
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .ok_or_else(|| StoreError::Decode("next_out is missing".to_owned()))?
            .value();
        let next_in = meta
            .get("next_in")
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .ok_or_else(|| StoreError::Decode("next_in is missing".to_owned()))?
            .value();
        let next_event = meta
            .get("next_event")
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .ok_or_else(|| StoreError::Decode("next_event is missing".to_owned()))?
            .value();
        Ok(RecoveryState {
            next_out,
            next_in,
            next_event,
        })
    }

    fn apply(&mut self, operation: StoreOp) -> Result<StoreReply, StoreError> {
        match operation {
            StoreOp::CommitOutbound(commit) => self.commit_outbound(commit),
            StoreOp::MarkOutboundWritten(mark) => self.mark_outbound_written(mark),
            StoreOp::CommitTransmission(commit) => self.commit_transmission(commit),
            StoreOp::MarkTransmissionWritten(mark) => self.mark_transmission_written(mark),
            StoreOp::CommitInbound(commit) => self.commit_inbound(commit),
            StoreOp::LoadCommand(request_id) => self.load_command(&request_id),
            StoreOp::LoadOutboundRange(range) => self.load_outbound_range(range),
            StoreOp::LoadInbound(sequence) => self.load_inbound(sequence),
            StoreOp::LoadTransmission(id) => self.load_transmission(id),
        }
    }
}

fn make_audit_record(
    key: &[u8],
    previous: Option<&AuditRecord>,
    event: AuditEvent,
) -> Result<AuditRecord, StoreError> {
    let previous_hash = previous.map_or_else(String::new, |record| record.hash.clone());
    let event_bytes = serde_json::to_vec(&event)
        .map_err(|error| StoreError::AuditSerialization(error.to_string()))?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| StoreError::InvalidAuditKey)?;
    mac.update(previous_hash.as_bytes());
    mac.update(&event_bytes);
    let hash = hex(&mac.finalize().into_bytes());

    Ok(AuditRecord {
        id: previous.map_or(1, |record| record.id + 1),
        event,
        previous_hash,
        hash,
    })
}

fn hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in input {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
