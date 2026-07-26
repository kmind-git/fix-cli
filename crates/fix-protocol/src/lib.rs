#![forbid(unsafe_code)]

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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

#[derive(Clone, Debug, Default)]
pub struct ParseDictionary {
    data_pairs: BTreeMap<u32, u32>,
}

impl ParseDictionary {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_data_pair(mut self, length_tag: u32, data_tag: u32) -> Self {
        self.data_pairs.insert(length_tag, data_tag);
        self
    }

    fn data_tag_for_length(&self, length_tag: u32) -> Option<u32> {
        self.data_pairs.get(&length_tag).copied()
    }

    fn is_data_tag(&self, tag: u32) -> bool {
        self.data_pairs.values().any(|data_tag| *data_tag == tag)
    }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompiledDictionary {
    pub artifact_version: u32,
    pub begin_strings: Vec<String>,
    pub messages: BTreeMap<String, MessageDefinition>,
    #[serde(default)]
    pub data_pairs: BTreeMap<u32, u32>,
    #[serde(default)]
    pub sensitive_tags: BTreeSet<u32>,
    #[serde(default)]
    pub source_sha256: Option<String>,
}

impl CompiledDictionary {
    #[must_use]
    pub fn new(begin_string: impl Into<String>) -> Self {
        Self {
            artifact_version: 1,
            begin_strings: vec![begin_string.into()],
            messages: BTreeMap::new(),
            data_pairs: BTreeMap::new(),
            sensitive_tags: BTreeSet::new(),
            source_sha256: None,
        }
    }

    #[must_use]
    pub fn with_message(mut self, message: MessageDefinition) -> Self {
        self.messages.insert(message.msg_type.clone(), message);
        self
    }

    #[must_use]
    pub fn with_data_pair(mut self, length_tag: u32, data_tag: u32) -> Self {
        self.data_pairs.insert(length_tag, data_tag);
        self
    }

    #[must_use]
    pub fn parse_dictionary(&self) -> ParseDictionary {
        ParseDictionary {
            data_pairs: self.data_pairs.clone(),
        }
    }

    pub fn validate(&self, message: ParsedMessage) -> Result<StructuredMessage, ValidationError> {
        let begin_string = std::str::from_utf8(&message.begin_string)
            .map_err(|_| ValidationError::NonAsciiBeginString)?;
        if !self
            .begin_strings
            .iter()
            .any(|allowed| allowed == begin_string)
        {
            return Err(ValidationError::UnsupportedBeginString(
                begin_string.to_owned(),
            ));
        }

        let msg_type = message.msg_type().ok_or(ValidationError::MissingMsgType)?;
        let msg_type = std::str::from_utf8(msg_type)
            .map_err(|_| ValidationError::NonAsciiMsgType)?
            .to_owned();
        let definition = self
            .messages
            .get(&msg_type)
            .ok_or_else(|| ValidationError::UnknownMsgType(msg_type.clone()))?;

        let mut cursor = 1;
        let items = parse_layout(&definition.members, &message.fields, &mut cursor)?;
        if cursor != message.fields.len() {
            return Err(ValidationError::UnexpectedTag {
                tag: message.fields[cursor].tag,
                position: cursor,
            });
        }

        Ok(StructuredMessage {
            message_name: definition.name.clone(),
            raw: message,
            items,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageDefinition {
    pub name: String,
    pub msg_type: String,
    pub members: Vec<MemberDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemberDefinition {
    Field {
        tag: u32,
        required: bool,
    },
    Group {
        count_tag: u32,
        delimiter_tag: u32,
        required: bool,
        members: Vec<MemberDefinition>,
    },
}

impl MemberDefinition {
    #[must_use]
    pub const fn field(tag: u32, required: bool) -> Self {
        Self::Field { tag, required }
    }

    #[must_use]
    pub fn group(
        count_tag: u32,
        delimiter_tag: u32,
        required: bool,
        members: Vec<MemberDefinition>,
    ) -> Self {
        Self::Group {
            count_tag,
            delimiter_tag,
            required,
            members,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredMessage {
    pub message_name: String,
    pub raw: ParsedMessage,
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Field(Field),
    Group(RepeatingGroup),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepeatingGroup {
    pub count_tag: u32,
    pub delimiter_tag: u32,
    pub entries: Vec<GroupEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    pub items: Vec<Item>,
}

impl GroupEntry {
    #[must_use]
    pub fn fields(&self) -> Vec<&Field> {
        self.items
            .iter()
            .filter_map(|item| match item {
                Item::Field(field) => Some(field),
                Item::Group(_) => None,
            })
            .collect()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("BeginString is not ASCII")]
    NonAsciiBeginString,
    #[error("unsupported BeginString {0}")]
    UnsupportedBeginString(String),
    #[error("MsgType(35) is missing")]
    MissingMsgType,
    #[error("MsgType(35) is not ASCII")]
    NonAsciiMsgType,
    #[error("unknown MsgType {0}")]
    UnknownMsgType(String),
    #[error("required tag {tag} is missing at field position {position}")]
    MissingRequiredTag { tag: u32, position: usize },
    #[error("unexpected tag {tag} at field position {position}")]
    UnexpectedTag { tag: u32, position: usize },
    #[error("NumInGroup tag {tag} is not an unsigned decimal")]
    InvalidGroupCount { tag: u32 },
    #[error(
        "group {count_tag} entry {entry} must start with delimiter {delimiter_tag}, got {actual:?}"
    )]
    MissingGroupDelimiter {
        count_tag: u32,
        delimiter_tag: u32,
        entry: usize,
        actual: Option<u32>,
    },
}

fn parse_layout(
    definitions: &[MemberDefinition],
    fields: &[Field],
    cursor: &mut usize,
) -> Result<Vec<Item>, ValidationError> {
    let mut items = Vec::new();

    for definition in definitions {
        match definition {
            MemberDefinition::Field { tag, required } => {
                if fields.get(*cursor).map(|field| field.tag) == Some(*tag) {
                    items.push(Item::Field(fields[*cursor].clone()));
                    *cursor += 1;
                } else if *required {
                    return Err(ValidationError::MissingRequiredTag {
                        tag: *tag,
                        position: *cursor,
                    });
                }
            }
            MemberDefinition::Group {
                count_tag,
                delimiter_tag,
                required,
                members,
            } => {
                if fields.get(*cursor).map(|field| field.tag) != Some(*count_tag) {
                    if *required {
                        return Err(ValidationError::MissingRequiredTag {
                            tag: *count_tag,
                            position: *cursor,
                        });
                    }
                    continue;
                }

                let count_field = &fields[*cursor];
                let count = parse_decimal(&count_field.value)
                    .map_err(|_| ValidationError::InvalidGroupCount { tag: *count_tag })?;
                *cursor += 1;

                let mut entries = Vec::with_capacity(count);
                for entry_index in 0..count {
                    let actual = fields.get(*cursor).map(|field| field.tag);
                    if actual != Some(*delimiter_tag) {
                        return Err(ValidationError::MissingGroupDelimiter {
                            count_tag: *count_tag,
                            delimiter_tag: *delimiter_tag,
                            entry: entry_index,
                            actual,
                        });
                    }

                    let entry_items = parse_layout(members, fields, cursor)?;
                    entries.push(GroupEntry { items: entry_items });
                }

                items.push(Item::Group(RepeatingGroup {
                    count_tag: *count_tag,
                    delimiter_tag: *delimiter_tag,
                    entries,
                }));
            }
        }
    }

    Ok(items)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("malformed FIX message: {0}")]
    Malformed(&'static str),
    #[error("DATA tag {actual} appeared without its Length tag; expected {expected}")]
    UnexpectedDataTag { expected: u32, actual: u32 },
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

pub fn parse_frame(
    frame: &[u8],
    dictionary: &ParseDictionary,
) -> Result<ParsedMessage, ParseError> {
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
    let mut pending_data: Option<(u32, usize)> = None;

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

        let value = if let Some((expected_tag, data_length)) = pending_data.take() {
            if tag != expected_tag {
                return Err(ParseError::UnexpectedDataTag {
                    expected: expected_tag,
                    actual: tag,
                });
            }
            let value_end = value_start
                .checked_add(data_length)
                .ok_or(FrameError::LengthOverflow)?;
            if value_end >= checksum_start || frame[value_end] != SOH {
                return Err(ParseError::Malformed(
                    "DATA length exceeds its field boundary",
                ));
            }
            cursor = value_end + 1;
            Bytes::copy_from_slice(&frame[value_start..value_end])
        } else {
            if dictionary.is_data_tag(tag) {
                return Err(ParseError::UnexpectedDataTag {
                    expected: tag,
                    actual: tag,
                });
            }
            let value_end = find_soh(frame, value_start)
                .filter(|end| *end < checksum_start)
                .ok_or(ParseError::Malformed("field is missing SOH delimiter"))?;
            cursor = value_end + 1;
            Bytes::copy_from_slice(&frame[value_start..value_end])
        };

        if let Some(data_tag) = dictionary.data_tag_for_length(tag) {
            let data_length = parse_decimal(&value)?;
            pending_data = Some((data_tag, data_length));
        }
        fields.push(Field { tag, value });
    }

    if pending_data.is_some() {
        return Err(ParseError::Malformed(
            "Length field has no following DATA field",
        ));
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
