use bytes::Bytes;
use fix_protocol::{
    CompiledDictionary, Field, Item, MemberDefinition, MessageDefinition, ParseDictionary,
    ValidationError, encode_message, parse_frame,
};

#[test]
fn encoder_calculates_body_length_and_checksum() {
    let fields = vec![Field::new(35, Bytes::from_static(b"0"))];

    let encoded = encode_message(b"FIX.4.2", &fields).expect("encodable message");

    assert_eq!(
        encoded,
        Bytes::from_static(b"8=FIX.4.2\x019=5\x0135=0\x0110=161\x01")
    );
}

#[test]
fn parser_uses_the_length_field_for_data_containing_soh() {
    const RAW_DATA_MESSAGE: &[u8] = b"8=FIX.4.4\x019=17\x0135=A\x0195=3\x0196=A\x01B\x0110=247\x01";
    let dictionary = ParseDictionary::new().with_data_pair(95, 96);

    let message = parse_frame(RAW_DATA_MESSAGE, &dictionary).expect("valid DATA field");

    assert_eq!(message.msg_type(), Some(b"A".as_slice()));
    assert_eq!(
        message.values(96).collect::<Vec<_>>(),
        vec![b"A\x01B".as_slice()]
    );
}

#[test]
fn dictionary_materializes_repeating_group_entries_without_losing_duplicate_tags() {
    let dictionary = CompiledDictionary::new("FIX.4.4").with_message(MessageDefinition {
        name: "PartyList".to_owned(),
        msg_type: "Z".to_owned(),
        members: vec![MemberDefinition::group(
            453,
            448,
            true,
            vec![
                MemberDefinition::field(448, true),
                MemberDefinition::field(447, true),
                MemberDefinition::field(452, true),
            ],
        )],
    });
    let fields = vec![
        Field::new(35, Bytes::from_static(b"Z")),
        Field::new(453, Bytes::from_static(b"2")),
        Field::new(448, Bytes::from_static(b"PARTY-1")),
        Field::new(447, Bytes::from_static(b"D")),
        Field::new(452, Bytes::from_static(b"1")),
        Field::new(448, Bytes::from_static(b"PARTY-2")),
        Field::new(447, Bytes::from_static(b"D")),
        Field::new(452, Bytes::from_static(b"3")),
    ];
    let frame = encode_message(b"FIX.4.4", &fields).expect("encodable group");
    let parsed = parse_frame(&frame, &dictionary.parse_dictionary()).expect("valid FIX frame");

    let structured = dictionary
        .validate(parsed)
        .expect("group matches dictionary");

    let Item::Group(group) = &structured.items[0] else {
        panic!("first body item must be a repeating group");
    };
    assert_eq!(group.count_tag, 453);
    assert_eq!(group.entries.len(), 2);
    assert_eq!(group.entries[0].fields()[0].value, b"PARTY-1"[..]);
    assert_eq!(group.entries[1].fields()[0].value, b"PARTY-2"[..]);
}

#[test]
fn dictionary_rejects_a_group_count_larger_than_the_remaining_message() {
    let dictionary = CompiledDictionary::new("FIX.4.4").with_message(MessageDefinition {
        name: "PartyList".to_owned(),
        msg_type: "Z".to_owned(),
        members: vec![MemberDefinition::group(
            453,
            448,
            true,
            vec![MemberDefinition::field(448, true)],
        )],
    });
    let fields = vec![
        Field::new(35, Bytes::from_static(b"Z")),
        Field::new(453, Bytes::from_static(b"18446744073709551615")),
    ];
    let frame = encode_message(b"FIX.4.4", &fields).expect("encodable malicious count");
    let parsed = parse_frame(&frame, &dictionary.parse_dictionary()).expect("valid FIX frame");

    let error = dictionary
        .validate(parsed)
        .expect_err("untrusted count must not allocate");

    assert!(matches!(
        error,
        ValidationError::GroupCountLimitExceeded { tag: 453, .. }
            | ValidationError::InvalidGroupCount { tag: 453 }
    ));
}
