#![forbid(unsafe_code)]

use bytes::Bytes;
use fix_protocol::Field;
use fix_session::{ApplicationRequest, SessionError, SessionHandle, SessionPhase, SessionStatus};
use fix_store::{CommandRecord, StoreHandle, StoreOp, StoreReply};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Inspect,
    DryRun,
    Certification,
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeMode {
    Certification,
    Live,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveAuth {
    pub key_id: String,
    pub unix_ms: u64,
    pub nonce: String,
    pub mac_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub version: u32,
    pub request_id: String,
    pub profile: String,
    pub execution_mode: ExecutionMode,
    pub command: Command,
    pub auth: Option<LiveAuth>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    SessionStatus,
    SessionLogout,
    NewOrderSingle(NewOrderSingle),
    CancelOrder(CancelOrder),
    ReplaceOrder(ReplaceOrder),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NewOrderSingle {
    pub symbol: String,
    pub account: String,
    pub security_exchange: String,
    pub security_group: String,
    pub side: Side,
    pub quantity: String,
    #[serde(rename = "ord_type")]
    pub order_type: OrderType,
    pub price: Option<String>,
    pub time_in_force: TimeInForce,
    /// 200 MaturityMonthYear for futures contracts, e.g. "202609".
    #[serde(default)]
    pub maturity_month_year: Option<String>,
    /// Extra (tag, value) pairs appended verbatim, e.g. venue-specific
    /// tags like [[16013, "SGHB"], [16095, "0"]].
    #[serde(default)]
    pub extra_tags: Vec<(u32, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CancelOrder {
    /// request_id of the original order; planner derives its ClOrdID.
    #[serde(default)]
    pub original_request_id: Option<String>,
    /// The target order's ClOrdID (tag 11) as seen on the wire, used
    /// directly as OrigClOrdID(41). Exactly one of the two id fields.
    #[serde(default)]
    pub cl_ord_id: Option<String>,
    pub account: String,
    pub security_group: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplaceOrder {
    pub original_request_id: String,
    pub symbol: String,
    pub account: Option<String>,
    pub security_exchange: Option<String>,
    pub security_group: Option<String>,
    pub side: Side,
    pub quantity: String,
    #[serde(rename = "ord_type")]
    pub order_type: OrderType,
    pub price: Option<String>,
    pub time_in_force: TimeInForce,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Buy,
    Sell,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrderType {
    Market,
    Limit,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeInForce {
    Day,
    Gtc,
    Ioc,
    Fok,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub max_quantity: Decimal,
    pub max_notional: Decimal,
    pub allow_market_orders: bool,
    pub max_messages_per_second: u32,
}

impl Policy {
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            max_quantity: Decimal::ZERO,
            max_notional: Decimal::ZERO,
            allow_market_orders: false,
            max_messages_per_second: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedCommand {
    SessionStatus,
    SessionLogout,
    Application(ApplicationRequest),
}

pub struct CommandPlanner {
    profile: String,
    runtime_mode: RuntimeMode,
    policy: Policy,
}

impl CommandPlanner {
    #[must_use]
    pub fn new(profile: impl Into<String>, runtime_mode: RuntimeMode, policy: Policy) -> Self {
        Self {
            profile: profile.into(),
            runtime_mode,
            policy,
        }
    }

    fn max_messages_per_second(&self) -> u32 {
        self.policy.max_messages_per_second
    }

    pub fn plan(&self, request: &ControlRequest) -> Result<PlannedCommand, ControlError> {
        self.validate_envelope(request)?;

        match &request.command {
            Command::SessionStatus => Ok(PlannedCommand::SessionStatus),
            Command::SessionLogout => {
                if request.execution_mode != ExecutionMode::Certification {
                    return Err(ControlError::invalid(
                        "session logout requires certification execution_mode",
                    ));
                }
                Ok(PlannedCommand::SessionLogout)
            }
            Command::NewOrderSingle(order) => {
                let normalized = self.validate_order(
                    order.quantity.as_str(),
                    order.order_type,
                    order.price.as_deref(),
                )?;
                let mut fields = vec![
                    Field::new(1, Bytes::copy_from_slice(order.account.as_bytes())),
                    Field::new(21, Bytes::from_static(b"1")),
                    Field::new(
                        207,
                        Bytes::copy_from_slice(order.security_exchange.as_bytes()),
                    ),
                    Field::new(
                        1151,
                        Bytes::copy_from_slice(order.security_group.as_bytes()),
                    ),
                    Field::new(55, Bytes::copy_from_slice(order.symbol.as_bytes())),
                    Field::new(54, Bytes::from_static(side_code(order.side))),
                    Field::new(38, Bytes::from(normalized.quantity)),
                    Field::new(40, Bytes::from_static(order_type_code(order.order_type))),
                ];
                if let Some(maturity) = &order.maturity_month_year {
                    validate_tag_value(200, maturity)?;
                    fields.push(Field::new(200, Bytes::copy_from_slice(maturity.as_bytes())));
                }
                let fields = append_tif_then_price(fields, normalized.price, order.time_in_force);
                let mut fields = fields;
                for (tag, value) in &order.extra_tags {
                    validate_extra_tag(*tag, value)?;
                    fields.push(Field::new(*tag, Bytes::copy_from_slice(value.as_bytes())));
                }
                Ok(PlannedCommand::Application(ApplicationRequest {
                    request_id: request.request_id.clone(),
                    fingerprint: fingerprint(request, "D", &fields),
                    cl_ord_id: cl_ord_id(&self.profile, &request.request_id),
                    msg_type: "D".to_owned(),
                    fields,
                }))
            }
            Command::CancelOrder(cancel) => {
                let orig_cl_ord_id = match (&cancel.original_request_id, &cancel.cl_ord_id) {
                    (Some(request_id), None) => cl_ord_id(&self.profile, request_id),
                    (None, Some(cl_ord_id)) => {
                        if cl_ord_id.is_empty() || cl_ord_id.len() > 64 {
                            return Err(ControlError::invalid("cl_ord_id is empty or too long"));
                        }
                        cl_ord_id.clone()
                    }
                    (Some(_), Some(_)) => {
                        return Err(ControlError::invalid(
                            "provide either original_request_id or cl_ord_id, not both",
                        ));
                    }
                    (None, None) => {
                        return Err(ControlError::invalid(
                            "cancel requires original_request_id or cl_ord_id",
                        ));
                    }
                };
                let fields = vec![
                    Field::new(41, Bytes::from(orig_cl_ord_id)),
                    Field::new(1, Bytes::copy_from_slice(cancel.account.as_bytes())),
                    Field::new(
                        1151,
                        Bytes::copy_from_slice(cancel.security_group.as_bytes()),
                    ),
                ];
                Ok(PlannedCommand::Application(ApplicationRequest {
                    request_id: request.request_id.clone(),
                    fingerprint: fingerprint(request, "F", &fields),
                    cl_ord_id: cl_ord_id(&self.profile, &request.request_id),
                    msg_type: "F".to_owned(),
                    fields,
                }))
            }
            Command::ReplaceOrder(replace) => {
                let normalized = self.validate_order(
                    replace.quantity.as_str(),
                    replace.order_type,
                    replace.price.as_deref(),
                )?;
                let mut fields = vec![Field::new(
                    41,
                    Bytes::from(cl_ord_id(&self.profile, &replace.original_request_id)),
                )];
                if let Some(account) = &replace.account {
                    fields.push(Field::new(1, Bytes::copy_from_slice(account.as_bytes())));
                }
                if let Some(exchange) = &replace.security_exchange {
                    fields.push(Field::new(207, Bytes::copy_from_slice(exchange.as_bytes())));
                }
                if let Some(group) = &replace.security_group {
                    fields.push(Field::new(1151, Bytes::copy_from_slice(group.as_bytes())));
                }
                fields.push(Field::new(
                    55,
                    Bytes::copy_from_slice(replace.symbol.as_bytes()),
                ));
                fields.push(Field::new(54, Bytes::from_static(side_code(replace.side))));
                fields.push(Field::new(38, Bytes::from(normalized.quantity)));
                fields.push(Field::new(
                    40,
                    Bytes::from_static(order_type_code(replace.order_type)),
                ));
                let fields = append_tif_then_price(fields, normalized.price, replace.time_in_force);
                Ok(PlannedCommand::Application(ApplicationRequest {
                    request_id: request.request_id.clone(),
                    fingerprint: fingerprint(request, "G", &fields),
                    cl_ord_id: cl_ord_id(&self.profile, &request.request_id),
                    msg_type: "G".to_owned(),
                    fields,
                }))
            }
        }
    }

    fn validate_envelope(&self, request: &ControlRequest) -> Result<(), ControlError> {
        if request.version != 1 {
            return Err(ControlError::new(
                "SCHEMA_VERSION_UNSUPPORTED",
                false,
                "only control protocol version 1 is supported",
            ));
        }
        if request.profile != self.profile {
            return Err(ControlError::new(
                "PROFILE_NOT_FOUND",
                false,
                "request profile does not match this daemon",
            ));
        }
        if request.request_id.is_empty()
            || request.request_id.len() > 128
            || !request
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(ControlError::new(
                "INVALID_REQUEST",
                false,
                "request_id contains unsupported characters",
            ));
        }
        if request.execution_mode == ExecutionMode::Live {
            return Err(ControlError::new(
                "LIVE_GUARD_NOT_ARMED",
                false,
                "live execution is disabled until capability proofs and pure-Rust TLS are approved",
            ));
        }
        if request.execution_mode == ExecutionMode::Certification
            && self.runtime_mode != RuntimeMode::Certification
        {
            return Err(ControlError::new(
                "POLICY_DENIED",
                false,
                "certification execution is disabled in a live daemon",
            ));
        }
        Ok(())
    }

    fn validate_order(
        &self,
        quantity: &str,
        order_type: OrderType,
        price: Option<&str>,
    ) -> Result<NormalizedOrder, ControlError> {
        let quantity = positive_decimal(quantity, "quantity")?;
        if quantity > self.policy.max_quantity {
            return Err(ControlError::policy(
                "quantity exceeds the configured maximum",
            ));
        }

        let price = price
            .map(|price| positive_decimal(price, "price"))
            .transpose()?;
        if matches!(order_type, OrderType::Limit) && price.is_none() {
            return Err(ControlError::invalid("limit order requires price"));
        }

        if let Some(price) = price {
            let notional = quantity
                .checked_mul(price)
                .ok_or_else(|| ControlError::invalid("notional overflow"))?;
            if notional > self.policy.max_notional {
                return Err(ControlError::policy(
                    "order notional exceeds the configured maximum",
                ));
            }
        }

        Ok(NormalizedOrder {
            quantity: quantity.normalize().to_string(),
            price: price.map(|price| price.normalize().to_string()),
        })
    }
}

struct NormalizedOrder {
    quantity: String,
    price: Option<String>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct ControlError {
    code: &'static str,
    retryable: bool,
    message: String,
}

impl ControlError {
    fn new(code: &'static str, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            code,
            retryable,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new("INVALID_REQUEST", false, message)
    }

    fn policy(message: impl Into<String>) -> Self {
        Self::new("POLICY_DENIED", false, message)
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

fn positive_decimal(value: &str, field: &str) -> Result<Decimal, ControlError> {
    let decimal = Decimal::from_str(value)
        .map_err(|_| ControlError::invalid(format!("{field} is not a decimal string")))?;
    if decimal <= Decimal::ZERO {
        return Err(ControlError::invalid(format!("{field} must be positive")));
    }
    Ok(decimal)
}

fn side_code(side: Side) -> &'static [u8] {
    match side {
        Side::Buy => b"1",
        Side::Sell => b"2",
    }
}

fn order_type_code(order_type: OrderType) -> &'static [u8] {
    match order_type {
        OrderType::Market => b"1",
        OrderType::Limit => b"2",
    }
}

fn time_in_force_code(time_in_force: TimeInForce) -> &'static [u8] {
    match time_in_force {
        // ponytail: Hundsun's dictionary wants literal "DAY" (standard FIX is
        // "0" and the venue Rejects 59=0 as out-of-range). Other venues =>
        // dictionary-aware mapping.
        TimeInForce::Day => b"DAY",
        TimeInForce::Gtc => b"1",
        TimeInForce::Ioc => b"3",
        TimeInForce::Fok => b"4",
    }
}

fn validate_extra_tag(tag: u32, value: &str) -> Result<(), ControlError> {
    const MANAGED: [u32; 22] = [
        1, 8, 9, 10, 11, 21, 34, 35, 38, 40, 41, 44, 49, 52, 54, 55, 56, 58, 59, 60, 1151, 200,
    ];
    if MANAGED.contains(&tag) {
        return Err(ControlError::invalid(format!(
            "extra tag {tag} is managed by the order schema"
        )));
    }
    validate_tag_value(tag, value)
}

fn validate_tag_value(tag: u32, value: &str) -> Result<(), ControlError> {
    if tag == 0
        || value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'=')
    {
        return Err(ControlError::invalid(format!(
            "tag {tag} value is empty, too long, or not safe ASCII"
        )));
    }
    Ok(())
}

fn append_tif_then_price(
    mut fields: Vec<Field>,
    price: Option<String>,
    time_in_force: TimeInForce,
) -> Vec<Field> {
    fields.push(Field::new(
        59,
        Bytes::from_static(time_in_force_code(time_in_force)),
    ));
    if let Some(price) = price {
        fields.push(Field::new(44, Bytes::from(price)));
    }
    fields
}

fn cl_ord_id(profile: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"fix-cli-clordid-v1\0");
    digest.update(profile.as_bytes());
    digest.update(b"\0");
    digest.update(request_id.as_bytes());
    let hash = digest.finalize();
    format!("FC-{}", hex(&hash[..12]))
}

fn fingerprint(request: &ControlRequest, msg_type: &str, fields: &[Field]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"fix-cli-command-v1\0");
    digest.update(request.profile.as_bytes());
    digest.update(b"\0");
    digest.update(match request.execution_mode {
        ExecutionMode::Inspect => b"inspect".as_slice(),
        ExecutionMode::DryRun => b"dry_run".as_slice(),
        ExecutionMode::Certification => b"certification".as_slice(),
        ExecutionMode::Live => b"live".as_slice(),
    });
    digest.update(b"\0");
    digest.update(msg_type.as_bytes());
    for field in fields {
        digest.update(field.tag.to_be_bytes());
        digest.update((field.value.len() as u64).to_be_bytes());
        digest.update(&field.value);
    }
    hex(&digest.finalize())
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

#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ControlResponse {
    pub version: u32,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ControlErrorBody>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlErrorBody {
    pub code: String,
    pub retryable: bool,
    pub message: String,
}

impl ControlResponse {
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        let Some(error) = &self.error else {
            return 0;
        };
        match error.code.as_str() {
            "INVALID_REQUEST" | "SCHEMA_VERSION_UNSUPPORTED" | "PROFILE_NOT_FOUND" => 2,
            "AUTH_FAILED" | "POLICY_DENIED" | "LIVE_GUARD_NOT_ARMED" => 3,
            "SESSION_NOT_ESTABLISHED" | "SESSION_RECOVERING" => 4,
            "IDEMPOTENCY_CONFLICT" => 5,
            "PROTOCOL_ERROR" | "TRANSPORT_ERROR" => 6,
            "STORE_UNAVAILABLE" => 7,
            "TIMEOUT" | "RATE_LIMITED" => 8,
            _ => 70,
        }
    }
}

pub struct ControlService {
    planner: CommandPlanner,
    sessions: SessionSlot,
    store: Option<StoreHandle>,
    application_gate: tokio::sync::Mutex<()>,
    rate_limiter: SlidingWindowRateLimiter,
}

#[derive(Clone, Default)]
pub struct SessionSlot {
    inner: Arc<RwLock<Option<SessionHandle>>>,
}

impl SessionSlot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_session(session: SessionHandle) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Some(session))),
        }
    }

    pub fn replace(&self, session: SessionHandle) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(session);
    }

    pub fn clear(&self) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn current(&self) -> Option<SessionHandle> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl ControlService {
    #[must_use]
    pub fn new_dynamic(planner: CommandPlanner, sessions: SessionSlot) -> Self {
        Self::build(planner, sessions, None)
    }

    #[must_use]
    pub fn new_dynamic_with_store(
        planner: CommandPlanner,
        sessions: SessionSlot,
        store: StoreHandle,
    ) -> Self {
        Self::build(planner, sessions, Some(store))
    }

    fn build(planner: CommandPlanner, sessions: SessionSlot, store: Option<StoreHandle>) -> Self {
        let max_messages_per_second = planner.max_messages_per_second();
        Self {
            planner,
            sessions,
            store,
            application_gate: tokio::sync::Mutex::new(()),
            rate_limiter: SlidingWindowRateLimiter::new(max_messages_per_second),
        }
    }

    pub async fn execute(&self, request: ControlRequest) -> ControlResponse {
        let request_id = request.request_id.clone();
        let planned = match self.planner.plan(&request) {
            Ok(planned) => planned,
            Err(error) => return error_response(request_id, &error),
        };

        let result = match planned {
            PlannedCommand::SessionStatus => match self.sessions.current() {
                Some(session) => session
                    .status()
                    .await
                    .map(|status| serde_json::to_value(status).expect("SessionStatus serializes")),
                None => Ok(serde_json::to_value(SessionStatus {
                    phase: SessionPhase::Disconnected,
                    next_out: 0,
                    next_in: 0,
                    test_request_outstanding: None,
                })
                .expect("SessionStatus serializes")),
            },
            PlannedCommand::SessionLogout => match self.sessions.current() {
                Some(session) => session
                    .logout(Some(format!("control request {}", request.request_id)))
                    .await
                    .map(|()| serde_json::json!({ "phase": "logout_sent" })),
                None => Err(SessionError::ActorStopped),
            },
            PlannedCommand::Application(application) => match request.execution_mode {
                ExecutionMode::DryRun => Ok(serde_json::json!({
                    "phase": "validated",
                    "would_send": false,
                    "msg_type": application.msg_type,
                    "cl_ord_id": application.cl_ord_id,
                    "fields": application.fields.iter().map(|field| {
                        serde_json::json!({
                            "tag": field.tag,
                            "value": String::from_utf8_lossy(&field.value),
                        })
                    }).collect::<Vec<_>>(),
                })),
                ExecutionMode::Certification | ExecutionMode::Live => {
                    // SessionActor is a single writer. Keep idempotency lookup, rate admission,
                    // and submit in the same control-plane single-flight section so a failed
                    // duplicate can never release another caller's successful reservation.
                    let _application_admission = self.application_gate.lock().await;
                    let session = self.sessions.current();
                    let existing = match self
                        .lookup_persisted_command(session.as_ref(), application.request_id.clone())
                        .await
                    {
                        Ok(existing) => existing,
                        Err(error) => return session_error_response(request_id, &error),
                    };
                    if let Some(existing) = existing {
                        if existing.fingerprint != application.fingerprint {
                            Err(SessionError::Store(format!(
                                "request ID {} was reused with a different fingerprint",
                                application.request_id
                            )))
                        } else {
                            Ok(command_result(existing))
                        }
                    } else {
                        match session {
                            Some(session) => {
                                if !self.rate_limiter.try_acquire(&request.request_id) {
                                    return ControlResponse {
                                        version: 1,
                                        request_id,
                                        ok: false,
                                        result: None,
                                        error: Some(ControlErrorBody {
                                            code: "RATE_LIMITED".to_owned(),
                                            retryable: true,
                                            message: "outbound message rate limit exceeded"
                                                .to_owned(),
                                        }),
                                    };
                                }
                                let submission = session.submit(application).await;
                                if matches!(
                                    submission,
                                    Err(SessionError::ActorStopped | SessionError::NotEstablished)
                                ) {
                                    self.rate_limiter.release(&request.request_id);
                                }
                                submission.map(command_result)
                            }
                            None => Err(SessionError::ActorStopped),
                        }
                    }
                }
                ExecutionMode::Inspect => Err(SessionError::InvalidApplication(
                    "application command cannot use inspect mode".to_owned(),
                )),
            },
        };

        match result {
            Ok(result) => ControlResponse {
                version: 1,
                request_id,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => session_error_response(request_id, &error),
        }
    }

    async fn lookup_persisted_command(
        &self,
        session: Option<&SessionHandle>,
        request_id: String,
    ) -> Result<Option<CommandRecord>, SessionError> {
        if let Some(store) = &self.store {
            let reply = store
                .apply(StoreOp::LoadCommand(request_id))
                .await
                .map_err(|error| SessionError::Store(error.to_string()))?;
            let StoreReply::StoredCommand(command) = reply else {
                return Err(SessionError::Store(
                    "command lookup returned the wrong record type".to_owned(),
                ));
            };
            return Ok(command);
        }
        match session {
            Some(session) => session.lookup_command(request_id).await,
            None => Ok(None),
        }
    }
}

fn command_result(command: CommandRecord) -> serde_json::Value {
    serde_json::json!({
        "phase": match command.phase {
            fix_store::CommandPhase::Journaled => "journaled",
            fix_store::CommandPhase::Written => "written_to_socket",
        },
        "cl_ord_id": command.cl_ord_id,
        "msg_seq_num": command.msg_seq_num,
        "venue_status": "pending",
    })
}

struct SlidingWindowRateLimiter {
    maximum: usize,
    state: Mutex<RateLimitState>,
}

#[derive(Default)]
struct RateLimitState {
    accepted: VecDeque<(Instant, String)>,
    request_ids: BTreeSet<String>,
}

impl SlidingWindowRateLimiter {
    fn new(maximum: u32) -> Self {
        Self {
            maximum: maximum as usize,
            state: Mutex::new(RateLimitState::default()),
        }
    }

    fn try_acquire(&self, request_id: &str) -> bool {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while state.accepted.front().is_some_and(|(accepted_at, _)| {
            now.duration_since(*accepted_at) >= Duration::from_secs(1)
        }) {
            if let Some((_, expired_request_id)) = state.accepted.pop_front() {
                state.request_ids.remove(&expired_request_id);
            }
        }
        if state.request_ids.contains(request_id) {
            return true;
        }
        if state.accepted.len() >= self.maximum {
            return false;
        }
        state.accepted.push_back((now, request_id.to_owned()));
        state.request_ids.insert(request_id.to_owned());
        true
    }

    fn release(&self, request_id: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .accepted
            .retain(|(_, accepted_request_id)| accepted_request_id != request_id);
        state.request_ids.remove(request_id);
    }
}

fn error_response(request_id: String, error: &ControlError) -> ControlResponse {
    ControlResponse {
        version: 1,
        request_id,
        ok: false,
        result: None,
        error: Some(ControlErrorBody {
            code: error.code().to_owned(),
            retryable: error.retryable(),
            message: error.message().to_owned(),
        }),
    }
}

fn session_error_response(request_id: String, error: &SessionError) -> ControlResponse {
    let (code, retryable) = match error {
        SessionError::NotEstablished => ("SESSION_NOT_ESTABLISHED", true),
        SessionError::Store(message) if message.contains("different fingerprint") => {
            ("IDEMPOTENCY_CONFLICT", false)
        }
        SessionError::Store(_) => ("STORE_UNAVAILABLE", true),
        SessionError::Transport(_) => ("TRANSPORT_ERROR", true),
        SessionError::Codec(_) | SessionError::Protocol(_) => ("PROTOCOL_ERROR", false),
        SessionError::ActorStopped => ("SESSION_NOT_ESTABLISHED", true),
        SessionError::InvalidApplication(_) => ("INVALID_REQUEST", false),
    };
    ControlResponse {
        version: 1,
        request_id,
        ok: false,
        result: None,
        error: Some(ControlErrorBody {
            code: code.to_owned(),
            retryable,
            message: error.to_string(),
        }),
    }
}
