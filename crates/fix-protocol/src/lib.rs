#![forbid(unsafe_code)]

use bytes::{Bytes, BytesMut};
use thiserror::Error;

const SOH: u8 = 0x01;
const CHECKSUM_FIELD_LEN: usize = 7;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("malformed FIX frame: {0}")]
    Malformed(&'static str),
    #[error("FIX BodyLength exceeds the configured maximum")]
    BodyTooLarge,
    #[error("buffered FIX data exceeds the configured maximum")]
    BufferedDataTooLarge,
    #[error("FIX frame length overflow")]
    LengthOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub tag: u32,
    pub value: Bytes,
}

impl Field {
    #[must_use]
    pub const fn new(tag: u32, value: Bytes) -> Self {
        Self { tag, value }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("MsgType(35) must be the first body field")]
    MsgTypeMustBeFirst,
    #[error("field {0} is managed by the FIX encoder")]
    ManagedField(u32),
    #[error("field tag must be non-zero")]
    InvalidTag,
    #[error("BeginString contains a delimiter")]
    InvalidBeginString,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMessage {
    pub begin_string: Bytes,
    pub fields: Vec<Field>,
    pub checksum: u8,
}

impl ParsedMessage {
    #[must_use]
    pub fn msg_type(&self) -> Option<&[u8]> {
        self.fields
            .first()
            .filter(|field| field.tag == 35)
            .map(|field| field.value.as_ref())
    }

    pub fn values(&self, tag: u32) -> impl Iterator<Item = &[u8]> {
        self.fields
            .iter()
            .filter(move |field| field.tag == tag)
            .map(|field| field.value.as_ref())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("malformed FIX message: {0}")]
    Malformed(&'static str),
}

pub fn encode_message(begin_string: &[u8], fields: &[Field]) -> Result<Bytes, CodecError> {
    if begin_string.is_empty() || begin_string.iter().any(|byte| matches!(*byte, SOH | b'=')) {
        return Err(CodecError::InvalidBeginString);
    }
    if fields.first().map(|field| field.tag) != Some(35) {
        return Err(CodecError::MsgTypeMustBeFirst);
    }

    let mut body = BytesMut::new();
    for field in fields {
        if field.tag == 0 {
            return Err(CodecError::InvalidTag);
        }
        if matches!(field.tag, 8..=10) {
            return Err(CodecError::ManagedField(field.tag));
        }

        body.extend_from_slice(field.tag.to_string().as_bytes());
        body.extend_from_slice(b"=");
        body.extend_from_slice(&field.value);
        body.extend_from_slice(&[SOH]);
    }

    let mut wire = BytesMut::new();
    wire.extend_from_slice(b"8=");
    wire.extend_from_slice(begin_string);
    wire.extend_from_slice(&[SOH]);
    wire.extend_from_slice(b"9=");
    wire.extend_from_slice(body.len().to_string().as_bytes());
    wire.extend_from_slice(&[SOH]);
    wire.extend_from_slice(&body);

    let checksum = wire.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    wire.extend_from_slice(format!("10={checksum:03}").as_bytes());
    wire.extend_from_slice(&[SOH]);

    Ok(wire.freeze())
}

pub fn parse_frame(frame: &[u8]) -> Result<ParsedMessage, ParseError> {
    let mut checked = BytesMut::from(frame);
    let extracted = try_take_frame(&mut checked, frame.len())?
        .ok_or(ParseError::Malformed("incomplete frame"))?;
    if !checked.is_empty() || extracted.len() != frame.len() {
        return Err(ParseError::Malformed("input contains more than one frame"));
    }

    let end_begin_string =
        find_soh(frame, 0).ok_or(ParseError::Malformed("missing BeginString delimiter"))?;
    let body_length_start = end_begin_string + 1;
    let end_body_length = find_soh(frame, body_length_start)
        .ok_or(ParseError::Malformed("missing BodyLength delimiter"))?;
    let body_length = parse_decimal(&frame[body_length_start + 2..end_body_length])?;
    let body_start = end_body_length + 1;
    let checksum_start = body_start
        .checked_add(body_length)
        .ok_or(FrameError::LengthOverflow)?;

    let mut fields = Vec::new();
    let mut cursor = body_start;

    while cursor < checksum_start {
        let equals_offset = frame[cursor..checksum_start]
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(ParseError::Malformed("field is missing '='"))?;
        let equals = cursor + equals_offset;
        let tag_value = parse_decimal(&frame[cursor..equals])?;
        let tag =
            u32::try_from(tag_value).map_err(|_| ParseError::Malformed("field tag exceeds u32"))?;
        let value_start = equals + 1;
        let value_end = find_soh(frame, value_start)
            .filter(|end| *end < checksum_start)
            .ok_or(ParseError::Malformed("field is missing SOH delimiter"))?;
        cursor = value_end + 1;
        fields.push(Field {
            tag,
            value: Bytes::copy_from_slice(&frame[value_start..value_end]),
        });
    }
    if fields.first().map(|field| field.tag) != Some(35) {
        return Err(ParseError::Malformed("MsgType(35) must be third"));
    }

    let checksum = parse_decimal(&frame[checksum_start + 3..checksum_start + 6])? as u8;

    Ok(ParsedMessage {
        begin_string: Bytes::copy_from_slice(&frame[2..end_begin_string]),
        fields,
        checksum,
    })
}

pub struct FrameDecoder {
    buffer: BytesMut,
    max_body_length: usize,
}

impl FrameDecoder {
    #[must_use]
    pub fn new(max_body_length: usize) -> Self {
        Self {
            buffer: BytesMut::new(),
            max_body_length,
        }
    }

    pub fn ingest(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, FrameError> {
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();

        while let Some(frame) = try_take_frame(&mut self.buffer, self.max_body_length)? {
            frames.push(frame);
        }

        let max_buffer_length = self
            .max_body_length
            .checked_add(1024)
            .ok_or(FrameError::LengthOverflow)?;
        if self.buffer.len() > max_buffer_length {
            return Err(FrameError::BufferedDataTooLarge);
        }

        Ok(frames)
    }
}

fn try_take_frame(
    buffer: &mut BytesMut,
    max_body_length: usize,
) -> Result<Option<Bytes>, FrameError> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    if !buffer.starts_with(b"8=") {
        return Err(FrameError::Malformed("BeginString(8) must be first"));
    }

    let Some(end_begin_string) = find_soh(buffer, 0) else {
        return Ok(None);
    };
    let body_length_start = end_begin_string + 1;

    if buffer.len() < body_length_start + 2 {
        return Ok(None);
    }
    if !buffer[body_length_start..].starts_with(b"9=") {
        return Err(FrameError::Malformed("BodyLength(9) must be second"));
    }

    let Some(end_body_length) = find_soh(buffer, body_length_start) else {
        return Ok(None);
    };
    let body_length = parse_decimal(&buffer[body_length_start + 2..end_body_length])?;

    if body_length > max_body_length {
        return Err(FrameError::BodyTooLarge);
    }

    let body_start = end_body_length
        .checked_add(1)
        .ok_or(FrameError::LengthOverflow)?;
    let checksum_start = body_start
        .checked_add(body_length)
        .ok_or(FrameError::LengthOverflow)?;
    let frame_end = checksum_start
        .checked_add(CHECKSUM_FIELD_LEN)
        .ok_or(FrameError::LengthOverflow)?;

    if buffer.len() < frame_end {
        return Ok(None);
    }

    let checksum_field = &buffer[checksum_start..frame_end];
    if !checksum_field.starts_with(b"10=") || checksum_field[6] != SOH {
        return Err(FrameError::Malformed(
            "CheckSum(10) is not at the BodyLength boundary",
        ));
    }

    let claimed = parse_decimal(&checksum_field[3..6])?;
    if claimed > u8::MAX as usize {
        return Err(FrameError::Malformed("CheckSum(10) must fit in one byte"));
    }

    let actual = buffer[..checksum_start]
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));

    if actual != claimed as u8 {
        return Err(FrameError::Malformed("CheckSum(10) mismatch"));
    }

    Ok(Some(buffer.split_to(frame_end).freeze()))
}

fn find_soh(input: &[u8], from: usize) -> Option<usize> {
    input
        .get(from..)?
        .iter()
        .position(|byte| *byte == SOH)
        .map(|offset| from + offset)
}

fn parse_decimal(input: &[u8]) -> Result<usize, FrameError> {
    if input.is_empty() || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(FrameError::Malformed("expected an unsigned decimal value"));
    }

    input.iter().try_fold(0_usize, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add((byte - b'0') as usize))
            .ok_or(FrameError::LengthOverflow)
    })
}
