#![forbid(unsafe_code)]

use bytes::Bytes;
use fix_protocol::{
    Field, FrameDecoder, ParseDictionary, ParsedMessage, encode_message, parse_frame,
};
use fix_session::TimeSource;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockConfig {
    pub begin_string: String,
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Error)]
pub enum MockError {
    #[error("FIX framing failed: {0}")]
    Frame(String),
    #[error("FIX parsing failed: {0}")]
    Parse(String),
    #[error("FIX encoding failed: {0}")]
    Encode(String),
    #[error("FIX protocol violation: {0}")]
    Protocol(String),
    #[error("transport failed: {0}")]
    Transport(String),
}

pub async fn run_mock_session<T>(
    mut io: T,
    config: MockConfig,
    time_source: Arc<dyn TimeSource>,
) -> Result<(), MockError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut decoder = FrameDecoder::new(1024 * 1024);
    let mut input = vec![0_u8; 8192];
    let mut next_in = 1_u64;
    let mut next_out = 1_u64;
    let mut next_execution_id = 1_u64;

    loop {
        let count = io
            .read(&mut input)
            .await
            .map_err(|error| MockError::Transport(error.to_string()))?;
        if count == 0 {
            return Ok(());
        }

        let frames = decoder
            .ingest(&input[..count])
            .map_err(|error| MockError::Frame(error.to_string()))?;
        for frame in frames {
            let message = parse_frame(&frame, &ParseDictionary::new())
                .map_err(|error| MockError::Parse(error.to_string()))?;
            validate_envelope(&message, &config, next_in)?;
            next_in = next_in
                .checked_add(1)
                .ok_or_else(|| MockError::Protocol("inbound sequence overflow".to_owned()))?;

            let msg_type = required(&message, 35)?;
            let response = match msg_type {
                b"A" => Some(logon_fields(&config, &*time_source, next_out)),
                b"0" => None,
                b"1" => Some(heartbeat_fields(
                    &config,
                    &*time_source,
                    next_out,
                    message.values(112).next(),
                )),
                b"D" | b"F" | b"G" => {
                    let fields = execution_report_fields(
                        &config,
                        &*time_source,
                        next_out,
                        next_execution_id,
                        &message,
                    )?;
                    next_execution_id = next_execution_id.checked_add(1).ok_or_else(|| {
                        MockError::Protocol("execution identifier overflow".to_owned())
                    })?;
                    Some(fields)
                }
                b"5" => {
                    let fields = logout_fields(&config, &*time_source, next_out);
                    write_message(&mut io, &config.begin_string, &fields).await?;
                    return Ok(());
                }
                value => {
                    return Err(MockError::Protocol(format!(
                        "unsupported MsgType {}",
                        String::from_utf8_lossy(value)
                    )));
                }
            };

            if let Some(fields) = response {
                write_message(&mut io, &config.begin_string, &fields).await?;
                next_out = next_out
                    .checked_add(1)
                    .ok_or_else(|| MockError::Protocol("outbound sequence overflow".to_owned()))?;
            }
        }
    }
}

fn validate_envelope(
    message: &ParsedMessage,
    config: &MockConfig,
    expected_sequence: u64,
) -> Result<(), MockError> {
    if message.begin_string.as_ref() != config.begin_string.as_bytes() {
        return Err(MockError::Protocol("BeginString mismatch".to_owned()));
    }
    if required(message, 49)? != config.target_comp_id.as_bytes() {
        return Err(MockError::Protocol("SenderCompID mismatch".to_owned()));
    }
    if required(message, 56)? != config.sender_comp_id.as_bytes() {
        return Err(MockError::Protocol("TargetCompID mismatch".to_owned()));
    }
    let sequence = parse_u64(required(message, 34)?, 34)?;
    if sequence != expected_sequence {
        return Err(MockError::Protocol(format!(
            "expected MsgSeqNum {expected_sequence}, got {sequence}"
        )));
    }
    Ok(())
}

fn logon_fields(config: &MockConfig, time_source: &dyn TimeSource, sequence: u64) -> Vec<Field> {
    let mut fields = standard_header(config, time_source, sequence, "A");
    fields.push(Field::new(98, Bytes::from_static(b"0")));
    fields.push(Field::new(
        108,
        Bytes::from(config.heartbeat_interval_secs.to_string()),
    ));
    fields
}

fn heartbeat_fields(
    config: &MockConfig,
    time_source: &dyn TimeSource,
    sequence: u64,
    test_request_id: Option<&[u8]>,
) -> Vec<Field> {
    let mut fields = standard_header(config, time_source, sequence, "0");
    if let Some(test_request_id) = test_request_id {
        fields.push(Field::new(112, Bytes::copy_from_slice(test_request_id)));
    }
    fields
}

fn logout_fields(config: &MockConfig, time_source: &dyn TimeSource, sequence: u64) -> Vec<Field> {
    standard_header(config, time_source, sequence, "5")
}

fn execution_report_fields(
    config: &MockConfig,
    time_source: &dyn TimeSource,
    sequence: u64,
    execution_id: u64,
    request: &ParsedMessage,
) -> Result<Vec<Field>, MockError> {
    let request_type = required(request, 35)?;
    let cl_ord_id = required(request, 11)?;
    let symbol = required(request, 55)?;
    let side = required(request, 54)?;
    let order_qty = request.values(38).next().unwrap_or(b"0");
    let (exec_type, order_status, leaves_qty) = match request_type {
        b"D" => (b"0".as_slice(), b"0".as_slice(), order_qty),
        b"F" => (b"4".as_slice(), b"4".as_slice(), b"0".as_slice()),
        b"G" => (b"5".as_slice(), b"0".as_slice(), order_qty),
        _ => {
            return Err(MockError::Protocol(
                "execution report requested for non-order message".to_owned(),
            ));
        }
    };
    let mut fields = standard_header(config, time_source, sequence, "8");
    fields.extend([
        Field::new(37, Bytes::from(format!("MOCK-ORDER-{execution_id}"))),
        Field::new(17, Bytes::from(format!("MOCK-EXEC-{execution_id}"))),
        Field::new(150, Bytes::copy_from_slice(exec_type)),
        Field::new(39, Bytes::copy_from_slice(order_status)),
        Field::new(11, Bytes::copy_from_slice(cl_ord_id)),
    ]);
    if let Some(orig_cl_ord_id) = request.values(41).next() {
        fields.push(Field::new(41, Bytes::copy_from_slice(orig_cl_ord_id)));
    }
    fields.extend([
        Field::new(55, Bytes::copy_from_slice(symbol)),
        Field::new(54, Bytes::copy_from_slice(side)),
        Field::new(151, Bytes::copy_from_slice(leaves_qty)),
        Field::new(14, Bytes::from_static(b"0")),
        Field::new(6, Bytes::from_static(b"0")),
    ]);
    Ok(fields)
}

fn standard_header(
    config: &MockConfig,
    time_source: &dyn TimeSource,
    sequence: u64,
    msg_type: &str,
) -> Vec<Field> {
    vec![
        Field::new(35, Bytes::copy_from_slice(msg_type.as_bytes())),
        Field::new(49, Bytes::copy_from_slice(config.sender_comp_id.as_bytes())),
        Field::new(56, Bytes::copy_from_slice(config.target_comp_id.as_bytes())),
        Field::new(34, Bytes::from(sequence.to_string())),
        Field::new(52, Bytes::from(time_source.sending_time())),
    ]
}

async fn write_message<T>(io: &mut T, begin_string: &str, fields: &[Field]) -> Result<(), MockError>
where
    T: AsyncWrite + Unpin,
{
    let wire = encode_message(begin_string.as_bytes(), fields)
        .map_err(|error| MockError::Encode(error.to_string()))?;
    io.write_all(&wire)
        .await
        .map_err(|error| MockError::Transport(error.to_string()))?;
    io.flush()
        .await
        .map_err(|error| MockError::Transport(error.to_string()))
}

fn required(message: &ParsedMessage, tag: u32) -> Result<&[u8], MockError> {
    message
        .values(tag)
        .next()
        .ok_or_else(|| MockError::Protocol(format!("required tag {tag} is missing")))
}

fn parse_u64(value: &[u8], tag: u32) -> Result<u64, MockError> {
    let value = std::str::from_utf8(value)
        .map_err(|_| MockError::Protocol(format!("tag {tag} is not ASCII")))?;
    value
        .parse()
        .map_err(|_| MockError::Protocol(format!("tag {tag} is not an unsigned integer")))
}
