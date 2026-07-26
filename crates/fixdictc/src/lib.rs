#![forbid(unsafe_code)]

use fix_protocol::{CompiledDictionary, MemberDefinition, MessageDefinition};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("XML error: {0}")]
    Xml(String),
    #[error("DOCTYPE and entity references are forbidden")]
    ForbiddenXmlConstruct,
    #[error("missing attribute {attribute} on {element}")]
    MissingAttribute {
        element: &'static str,
        attribute: &'static str,
    },
    #[error("attribute {attribute} on {element} must be an unsigned integer")]
    InvalidInteger {
        element: &'static str,
        attribute: &'static str,
    },
    #[error("nested Orchestra definitions are not supported")]
    NestedDefinition,
    #[error("unknown field reference {0}")]
    UnknownField(u32),
    #[error("unknown group reference {0}")]
    UnknownGroup(u32),
    #[error("unknown component reference {0}")]
    UnknownComponent(u32),
    #[error("reference cycle includes {0}")]
    ReferenceCycle(String),
    #[error("group {0} has no field delimiter")]
    MissingGroupDelimiter(u32),
    #[error("unsupported Orchestra presence value {0}")]
    UnsupportedPresence(String),
    #[error("duplicate Orchestra definition {0}")]
    DuplicateDefinition(String),
}

#[derive(Clone, Debug)]
enum Reference {
    Field { id: u32, required: bool },
    Group { id: u32, required: bool },
    Component { id: u32, required: bool },
}

#[derive(Clone, Debug)]
struct Aggregate {
    id: u32,
    members: Vec<Reference>,
}

#[derive(Clone, Debug)]
struct Message {
    name: String,
    msg_type: String,
    members: Vec<Reference>,
}

#[derive(Clone, Debug)]
enum ActiveDefinition {
    Group(Aggregate),
    Component(Aggregate),
    Message(Message),
}

impl ActiveDefinition {
    fn members_mut(&mut self) -> &mut Vec<Reference> {
        match self {
            Self::Group(aggregate) | Self::Component(aggregate) => &mut aggregate.members,
            Self::Message(message) => &mut message.members,
        }
    }
}

pub fn compile_orchestra(
    xml: &[u8],
    begin_string: &str,
) -> Result<CompiledDictionary, CompileError> {
    let mut reader = Reader::from_reader(Cursor::new(xml));
    reader.config_mut().trim_text(true);

    let mut event_buffer = Vec::new();
    let mut path = Vec::<String>::new();
    let mut known_fields = BTreeSet::new();
    let mut data_pairs = BTreeMap::<u32, u32>::new();
    let mut groups = BTreeMap::<u32, Aggregate>::new();
    let mut components = BTreeMap::<u32, Aggregate>::new();
    let mut messages = Vec::<Message>::new();
    let mut active = None::<ActiveDefinition>;

    loop {
        match reader.read_event_into(&mut event_buffer) {
            Ok(Event::Start(start)) => {
                let name = local_name(start.name().as_ref());
                process_start(
                    &reader,
                    &start,
                    &name,
                    path.last().map(String::as_str),
                    &mut known_fields,
                    &mut data_pairs,
                    &mut active,
                )?;
                path.push(name);
            }
            Ok(Event::Empty(start)) => {
                let name = local_name(start.name().as_ref());
                process_start(
                    &reader,
                    &start,
                    &name,
                    path.last().map(String::as_str),
                    &mut known_fields,
                    &mut data_pairs,
                    &mut active,
                )?;
            }
            Ok(Event::End(end)) => {
                let name = local_name(end.name().as_ref());
                if matches!(name.as_str(), "group" | "component" | "message") {
                    finish_definition(
                        &name,
                        &mut active,
                        &mut groups,
                        &mut components,
                        &mut messages,
                    )?;
                }
                path.pop();
            }
            Ok(Event::DocType(_) | Event::GeneralRef(_)) => {
                return Err(CompileError::ForbiddenXmlConstruct);
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(CompileError::Xml(error.to_string())),
        }
        event_buffer.clear();
    }

    let mut dictionary = CompiledDictionary::new(begin_string);
    dictionary.source_sha256 = Some(hex_sha256(xml));
    dictionary.sensitive_tags.extend(
        [553_u32, 554, 925]
            .into_iter()
            .filter(|tag| known_fields.contains(tag)),
    );
    for (length_tag, data_tag) in data_pairs {
        if !known_fields.contains(&length_tag) {
            return Err(CompileError::UnknownField(length_tag));
        }
        dictionary = dictionary.with_data_pair(length_tag, data_tag);
    }

    for message in messages {
        let members = resolve_references(
            &message.members,
            &known_fields,
            &groups,
            &components,
            &mut Vec::new(),
            false,
        )?;
        dictionary = dictionary.with_message(MessageDefinition {
            name: message.name,
            msg_type: message.msg_type,
            members,
        });
    }

    Ok(dictionary)
}

fn process_start(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    name: &str,
    parent: Option<&str>,
    known_fields: &mut BTreeSet<u32>,
    data_pairs: &mut BTreeMap<u32, u32>,
    active: &mut Option<ActiveDefinition>,
) -> Result<(), CompileError> {
    match (parent, name) {
        (Some("fields"), "field") => {
            let id = required_u32(reader, start, "field", "id")?;
            if !known_fields.insert(id) {
                return Err(CompileError::DuplicateDefinition(format!("field {id}")));
            }
            if attribute(reader, start, "type")?
                .is_some_and(|value| value.eq_ignore_ascii_case("data"))
            {
                let length_id = required_u32(reader, start, "field", "lengthId")?;
                if data_pairs.insert(length_id, id).is_some() {
                    return Err(CompileError::DuplicateDefinition(format!(
                        "DATA length mapping {length_id}"
                    )));
                }
            }
        }
        (Some("groups"), "group") => {
            ensure_no_active(active)?;
            let _name = required_string(reader, start, "group", "name")?;
            *active = Some(ActiveDefinition::Group(Aggregate {
                id: required_u32(reader, start, "group", "id")?,
                members: Vec::new(),
            }));
        }
        (Some("components"), "component") => {
            ensure_no_active(active)?;
            let _name = required_string(reader, start, "component", "name")?;
            *active = Some(ActiveDefinition::Component(Aggregate {
                id: required_u32(reader, start, "component", "id")?,
                members: Vec::new(),
            }));
        }
        (Some("messages"), "message") => {
            ensure_no_active(active)?;
            *active = Some(ActiveDefinition::Message(Message {
                name: required_string(reader, start, "message", "name")?,
                msg_type: required_string(reader, start, "message", "msgType")?,
                members: Vec::new(),
            }));
        }
        (_, "fieldRef") => {
            if let Some(active) = active {
                active.members_mut().push(Reference::Field {
                    id: required_u32(reader, start, "fieldRef", "id")?,
                    required: required_presence(reader, start)?,
                });
            }
        }
        (_, "groupRef") => {
            if let Some(active) = active {
                active.members_mut().push(Reference::Group {
                    id: required_u32(reader, start, "groupRef", "id")?,
                    required: required_presence(reader, start)?,
                });
            }
        }
        (_, "componentRef") => {
            if let Some(active) = active {
                active.members_mut().push(Reference::Component {
                    id: required_u32(reader, start, "componentRef", "id")?,
                    required: required_presence(reader, start)?,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

fn finish_definition(
    ending: &str,
    active: &mut Option<ActiveDefinition>,
    groups: &mut BTreeMap<u32, Aggregate>,
    components: &mut BTreeMap<u32, Aggregate>,
    messages: &mut Vec<Message>,
) -> Result<(), CompileError> {
    let matches = matches!(
        (ending, active.as_ref()),
        ("group", Some(ActiveDefinition::Group(_)))
            | ("component", Some(ActiveDefinition::Component(_)))
            | ("message", Some(ActiveDefinition::Message(_)))
    );
    if !matches {
        return Ok(());
    }

    match active.take().expect("active definition checked above") {
        ActiveDefinition::Group(group) => {
            let id = group.id;
            if groups.insert(id, group).is_some() {
                return Err(CompileError::DuplicateDefinition(format!("group {id}")));
            }
        }
        ActiveDefinition::Component(component) => {
            let id = component.id;
            if components.insert(id, component).is_some() {
                return Err(CompileError::DuplicateDefinition(format!("component {id}")));
            }
        }
        ActiveDefinition::Message(message) => messages.push(message),
    }
    Ok(())
}

fn resolve_references(
    references: &[Reference],
    known_fields: &BTreeSet<u32>,
    groups: &BTreeMap<u32, Aggregate>,
    components: &BTreeMap<u32, Aggregate>,
    stack: &mut Vec<String>,
    force_optional: bool,
) -> Result<Vec<MemberDefinition>, CompileError> {
    let mut definitions = Vec::new();

    for reference in references {
        match reference {
            Reference::Field { id, required } => {
                if !known_fields.contains(id) {
                    return Err(CompileError::UnknownField(*id));
                }
                definitions.push(MemberDefinition::field(*id, *required && !force_optional));
            }
            Reference::Group { id, required } => {
                let group = groups.get(id).ok_or(CompileError::UnknownGroup(*id))?;
                let marker = format!("group:{id}");
                enter_reference(stack, &marker)?;
                let members = resolve_references(
                    &group.members,
                    known_fields,
                    groups,
                    components,
                    stack,
                    false,
                )?;
                stack.pop();
                let delimiter_tag =
                    first_field_tag(&members).ok_or(CompileError::MissingGroupDelimiter(*id))?;
                definitions.push(MemberDefinition::group(
                    *id,
                    delimiter_tag,
                    *required && !force_optional,
                    members,
                ));
            }
            Reference::Component { id, required } => {
                let component = components
                    .get(id)
                    .ok_or(CompileError::UnknownComponent(*id))?;
                let marker = format!("component:{id}");
                enter_reference(stack, &marker)?;
                definitions.extend(resolve_references(
                    &component.members,
                    known_fields,
                    groups,
                    components,
                    stack,
                    force_optional || !*required,
                )?);
                stack.pop();
            }
        }
    }

    Ok(definitions)
}

fn first_field_tag(definitions: &[MemberDefinition]) -> Option<u32> {
    definitions.first().map(|definition| match definition {
        MemberDefinition::Field { tag, .. } => *tag,
        MemberDefinition::Group { delimiter_tag, .. } => *delimiter_tag,
    })
}

fn enter_reference(stack: &mut Vec<String>, marker: &str) -> Result<(), CompileError> {
    if stack.iter().any(|current| current == marker) {
        return Err(CompileError::ReferenceCycle(marker.to_owned()));
    }
    stack.push(marker.to_owned());
    Ok(())
}

fn ensure_no_active(active: &Option<ActiveDefinition>) -> Result<(), CompileError> {
    if active.is_some() {
        Err(CompileError::NestedDefinition)
    } else {
        Ok(())
    }
}

fn required_presence(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
) -> Result<bool, CompileError> {
    match attribute(reader, start, "presence")?.as_deref() {
        None | Some("optional") => Ok(false),
        Some("required") | Some("constant") => Ok(true),
        Some(other) => Err(CompileError::UnsupportedPresence(other.to_owned())),
    }
}

fn required_u32(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    element: &'static str,
    attribute_name: &'static str,
) -> Result<u32, CompileError> {
    required_string(reader, start, element, attribute_name)?
        .parse()
        .map_err(|_| CompileError::InvalidInteger {
            element,
            attribute: attribute_name,
        })
}

fn required_string(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    element: &'static str,
    attribute_name: &'static str,
) -> Result<String, CompileError> {
    attribute(reader, start, attribute_name)?.ok_or(CompileError::MissingAttribute {
        element,
        attribute: attribute_name,
    })
}

fn attribute(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    sought: &str,
) -> Result<Option<String>, CompileError> {
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| CompileError::Xml(error.to_string()))?;
        if local_name(attribute.key.as_ref()) == sought {
            return attribute
                .decode_and_unescape_value(reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| CompileError::Xml(error.to_string()));
        }
    }
    Ok(None)
}

fn local_name(name: &[u8]) -> String {
    let local = name
        .iter()
        .rposition(|byte| *byte == b':')
        .map_or(name, |position| &name[position + 1..]);
    String::from_utf8_lossy(local).into_owned()
}

fn hex_sha256(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut output = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
