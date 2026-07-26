use fix_protocol::{Item, ParseDictionary, encode_message, parse_frame};
use fixdictc::{CompileError, compile_orchestra};

const ORCHESTRA: &str = r#"
<fixr:repository xmlns:fixr="http://fixprotocol.io/2020/orchestra/repository">
  <fixr:fields>
    <fixr:field id="35" name="MsgType" type="String"/>
    <fixr:field id="453" name="NoPartyIDs" type="NumInGroup"/>
    <fixr:field id="448" name="PartyID" type="String"/>
    <fixr:field id="447" name="PartyIDSource" type="char"/>
    <fixr:field id="452" name="PartyRole" type="int"/>
  </fixr:fields>
  <fixr:groups>
    <fixr:group id="453" name="NoPartyIDs">
      <fixr:structure>
        <fixr:fieldRef id="448" presence="required"/>
        <fixr:fieldRef id="447" presence="required"/>
        <fixr:fieldRef id="452" presence="required"/>
      </fixr:structure>
    </fixr:group>
  </fixr:groups>
  <fixr:messages>
    <fixr:message name="PartyList" msgType="Z">
      <fixr:structure>
        <fixr:groupRef id="453" presence="required"/>
      </fixr:structure>
    </fixr:message>
  </fixr:messages>
</fixr:repository>
"#;

#[test]
fn compiler_resolves_an_orchestra_repeating_group() {
    let dictionary =
        compile_orchestra(ORCHESTRA.as_bytes(), "FIX.4.4").expect("valid Orchestra repository");
    let fields = vec![
        fix_protocol::Field::new(35, "Z".into()),
        fix_protocol::Field::new(453, "1".into()),
        fix_protocol::Field::new(448, "PARTY-1".into()),
        fix_protocol::Field::new(447, "D".into()),
        fix_protocol::Field::new(452, "1".into()),
    ];
    let wire = encode_message(b"FIX.4.4", &fields).expect("encodable fixture");
    let parsed = parse_frame(&wire, &ParseDictionary::new()).expect("parseable fixture");

    let message = dictionary.validate(parsed).expect("dictionary validation");

    assert_eq!(message.message_name, "PartyList");
    let Item::Group(group) = &message.items[0] else {
        panic!("expected resolved repeating group");
    };
    assert_eq!(group.delimiter_tag, 448);
    assert_eq!(group.entries.len(), 1);
}

#[test]
fn compiler_derives_the_data_length_pair_from_orchestra_length_id() {
    const DATA_ORCHESTRA: &str = r#"
<fixr:repository xmlns:fixr="http://fixprotocol.io/2023/orchestra/repository">
  <fixr:fields>
    <fixr:field id="35" name="MsgType" type="String"/>
    <fixr:field id="95" name="RawDataLength" type="Length"/>
    <fixr:field id="96" name="RawData" type="data" lengthId="95"/>
  </fixr:fields>
  <fixr:messages>
    <fixr:message name="DataMessage" msgType="U1">
      <fixr:structure>
        <fixr:fieldRef id="95" presence="required"/>
        <fixr:fieldRef id="96" presence="required"/>
      </fixr:structure>
    </fixr:message>
  </fixr:messages>
</fixr:repository>
"#;
    let dictionary =
        compile_orchestra(DATA_ORCHESTRA.as_bytes(), "FIX.4.4").expect("valid data dictionary");
    assert_eq!(dictionary.data_pairs.get(&95), Some(&96));

    let raw = encode_message(
        b"FIX.4.4",
        &[
            fix_protocol::Field::new(35, "U1".into()),
            fix_protocol::Field::new(95, "3".into()),
            fix_protocol::Field::new(96, b"A\x01B".as_slice().into()),
        ],
    )
    .expect("encodable DATA fixture");
    let parsed = parse_frame(&raw, &dictionary.parse_dictionary()).expect("length-aware parse");
    let message = dictionary.validate(parsed).expect("dictionary validation");

    assert_eq!(message.raw.values(96).next(), Some(b"A\x01B".as_slice()));
}

#[test]
fn compiler_rejects_duplicate_message_types() {
    const DUPLICATE_MESSAGE_TYPE: &str = r#"
<fixr:repository xmlns:fixr="http://fixprotocol.io/2023/orchestra/repository">
  <fixr:fields>
    <fixr:field id="35" name="MsgType" type="String"/>
  </fixr:fields>
  <fixr:messages>
    <fixr:message name="First" msgType="U1"><fixr:structure/></fixr:message>
    <fixr:message name="Second" msgType="U1"><fixr:structure/></fixr:message>
  </fixr:messages>
</fixr:repository>
"#;

    let error = compile_orchestra(DUPLICATE_MESSAGE_TYPE.as_bytes(), "FIX.4.4")
        .expect_err("duplicate MsgType must fail closed");

    assert!(matches!(
        error,
        CompileError::DuplicateDefinition(ref value)
            if value == "message MsgType U1"
    ));
}
