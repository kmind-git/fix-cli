use bytes::Bytes;
use fix_protocol::{Field, encode_message};

#[test]
fn encoder_calculates_body_length_and_checksum() {
    let fields = vec![Field::new(35, Bytes::from_static(b"0"))];

    let encoded = encode_message(b"FIX.4.2", &fields).expect("encodable message");

    assert_eq!(
        encoded,
        Bytes::from_static(b"8=FIX.4.2\x019=5\x0135=0\x0110=161\x01")
    );
}
