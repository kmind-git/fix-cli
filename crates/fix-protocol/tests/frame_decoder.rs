use bytes::Bytes;
use fix_protocol::FrameDecoder;

const HEARTBEAT: &[u8] = b"8=FIX.4.2\x019=5\x0135=0\x0110=161\x01";

#[test]
fn decoder_returns_a_complete_fix_frame() {
    let mut decoder = FrameDecoder::new(1024);

    let frames = decoder.ingest(HEARTBEAT).expect("valid FIX frame");

    assert_eq!(frames, vec![Bytes::from_static(HEARTBEAT)]);
}

#[test]
fn decoder_returns_every_frame_from_a_sticky_packet() {
    let mut decoder = FrameDecoder::new(1024);
    let mut packet = Vec::from(HEARTBEAT);
    packet.extend_from_slice(HEARTBEAT);

    let frames = decoder.ingest(&packet).expect("two valid FIX frames");

    assert_eq!(
        frames,
        vec![Bytes::from_static(HEARTBEAT), Bytes::from_static(HEARTBEAT)]
    );
}

#[test]
fn decoder_rejects_an_unbounded_unterminated_header() {
    let mut decoder = FrameDecoder::new(32);
    let mut attack = Vec::from(&b"8="[0..]);
    attack.resize(2048, b'X');

    let error = decoder
        .ingest(&attack)
        .expect_err("unterminated header must be bounded");

    assert_eq!(
        error.to_string(),
        "buffered FIX data exceeds the configured maximum"
    );
}
