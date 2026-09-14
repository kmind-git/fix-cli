#![forbid(unsafe_code)]

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::mpsc;
use thiserror::Error;
use tokio::sync::oneshot;

const META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("meta");
const COMMAND_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("commands");
const OUTBOUND_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("outbound");
const TRANSMISSION_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("transmissions");
const INBOUND_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("inbound");
const EVENT_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events");

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
pub struct ResyncInboundCommit {
    pub next_in_after: u64,
    pub event: EventRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundCommit {
    pub request_id: String,
    pub fingerprint: String,
    pub cl_ord_id: String,
    pub msg_seq_num: u64,
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkOutboundWritten {
    pub request_id: String,
    pub msg_seq_num: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransmissionCommit {
    pub msg_seq_num: u64,
    pub kind: String,
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkTransmissionWritten {
    pub id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundCommit {
    pub msg_seq_num: u64,
    pub next_in_after: u64,
    pub msg_type: String,
    pub wire: Vec<u8>,
    pub event: EventRecord,
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
    ResyncInbound(ResyncInboundCommit),
    ResetSequences,
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
    ResyncedInbound(u64),
    /// Carries the post-reset `next_event`; every reset consumes one event
    /// slot so admin idempotency keys stay unique across sequence epochs.
    SequencesReset(u64),
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

pub struct RedbStore {
    database: Database,
}

impl RedbStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let database =
            Database::create(path).map_err(|error| StoreError::Backend(error.to_string()))?;
        let store = Self { database };
        store.initialize()?;
        Ok(store)
    }

    /// In-memory journal with the same semantics as [`RedbStore::open`];
    /// nothing touches the disk. Intended for tests.
    #[must_use]
    pub fn open_in_memory() -> Self {
        let database = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .expect("in-memory redb database must initialize");
        let store = Self { database };
        store.initialize().expect("in-memory store must initialize");
        store
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
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))
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

        let next_out = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.get("next_out")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_out is missing".to_owned()))?
                .value()
        };
        if commit.msg_seq_num != next_out {
            return Err(StoreError::OutboundSequenceMismatch {
                expected: next_out,
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
        let outbound = OutboundRecord {
            command: command.clone(),
            wire: commit.wire,
        };
        let command_bytes =
            serde_json::to_vec(&command).map_err(|error| StoreError::Decode(error.to_string()))?;
        let outbound_bytes =
            serde_json::to_vec(&outbound).map_err(|error| StoreError::Decode(error.to_string()))?;

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
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_out", next_out + 1)
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

        command.phase = CommandPhase::Written;
        outbound.command = command.clone();
        let command_bytes =
            serde_json::to_vec(&command).map_err(|error| StoreError::Decode(error.to_string()))?;
        let outbound_bytes =
            serde_json::to_vec(&outbound).map_err(|error| StoreError::Decode(error.to_string()))?;

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

        let next_transmission = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.get("next_transmission")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_transmission is missing".to_owned()))?
                .value()
        };
        let record = TransmissionRecord {
            id: next_transmission,
            msg_seq_num: commit.msg_seq_num,
            kind: commit.kind,
            wire: commit.wire,
            phase: TransmissionPhase::Journaled,
        };
        let record_bytes =
            serde_json::to_vec(&record).map_err(|error| StoreError::Decode(error.to_string()))?;

        {
            let mut transmissions = transaction
                .open_table(TRANSMISSION_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            transmissions
                .insert(record.id, record_bytes.as_slice())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_transmission", next_transmission + 1)
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

        record.phase = TransmissionPhase::Written;
        let record_bytes =
            serde_json::to_vec(&record).map_err(|error| StoreError::Decode(error.to_string()))?;

        {
            let mut transmissions = transaction
                .open_table(TRANSMISSION_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            transmissions
                .insert(record.id, record_bytes.as_slice())
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

        let (next_in, next_event) = {
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
            (next_in, next_event)
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

        let record = InboundRecord {
            msg_seq_num: commit.msg_seq_num,
            msg_type: commit.msg_type,
            wire: commit.wire,
            event_id: commit.event.id,
        };
        let record_bytes =
            serde_json::to_vec(&record).map_err(|error| StoreError::Decode(error.to_string()))?;
        let event_bytes = serde_json::to_vec(&commit.event)
            .map_err(|error| StoreError::Decode(error.to_string()))?;

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
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_in", commit.next_in_after)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_event", next_event + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::Inbound(record))
    }

    fn resync_inbound(&mut self, commit: ResyncInboundCommit) -> Result<StoreReply, StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        let next_event = {
            let meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.get("next_event")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_event is missing".to_owned()))?
                .value()
        };
        if commit.next_in_after == 0 {
            return Err(StoreError::InvalidNextInbound {
                current: 0,
                next_in_after: 0,
            });
        }
        if commit.event.id != next_event {
            return Err(StoreError::EventSequenceMismatch {
                expected: next_event,
                actual: commit.event.id,
            });
        }

        let event_bytes = serde_json::to_vec(&commit.event)
            .map_err(|error| StoreError::Decode(error.to_string()))?;
        {
            let mut events = transaction
                .open_table(EVENT_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            events
                .insert(commit.event.id, event_bytes.as_slice())
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
        }

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::ResyncedInbound(commit.next_in_after))
    }

    fn reset_sequences(&mut self) -> Result<StoreReply, StoreError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        for definition in [OUTBOUND_TABLE, TRANSMISSION_TABLE, INBOUND_TABLE] {
            let mut table = transaction
                .open_table(definition)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let keys: Vec<u64> = table
                .iter()
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .map(|entry| entry.map(|(key, _)| key.value()))
                .collect::<Result<_, _>>()
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            for key in keys {
                table
                    .remove(key)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
            }
        }
        let new_next_event = {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let next_event = meta
                .get("next_event")
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .ok_or_else(|| StoreError::Decode("next_event is missing".to_owned()))?
                .value();
            meta.insert("next_out", 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_in", 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_transmission", 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            meta.insert("next_event", next_event + 1)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            next_event + 1
        };

        transaction
            .commit()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(StoreReply::SequencesReset(new_next_event))
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
            StoreOp::ResyncInbound(commit) => self.resync_inbound(commit),
            StoreOp::ResetSequences => self.reset_sequences(),
            StoreOp::LoadCommand(request_id) => self.load_command(&request_id),
            StoreOp::LoadOutboundRange(range) => self.load_outbound_range(range),
            StoreOp::LoadInbound(sequence) => self.load_inbound(sequence),
            StoreOp::LoadTransmission(id) => self.load_transmission(id),
        }
    }
}
