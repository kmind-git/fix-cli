use bytes::Bytes;
use fix_protocol::{Field, FrameDecoder, encode_message, parse_frame};

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn range(&mut self, upper: usize) -> usize {
        (self.next() as usize) % upper
    }

    fn fix_value(&mut self, maximum: usize) -> Bytes {
        let length = 1 + self.range(maximum);
        let value = (0..length)
            .map(|_| b'!' + self.range(94) as u8)
            .filter(|byte| *byte != b'=')
            .collect::<Vec<_>>();
        Bytes::from(value)
    }
}

#[test]
fn property_encoded_messages_round_trip_under_arbitrary_fragmentation() {
    let mut random = XorShift64(0x6a09_e667_f3bc_c909);

    for case in 0..2_000 {
        let msg_type = ["D", "8", "U1"][random.range(3)];
        let mut expected = vec![Field::new(35, Bytes::copy_from_slice(msg_type.as_bytes()))];
        let field_count = random.range(16);
        for _ in 0..field_count {
            let tag = 1_000 + random.range(200) as u32;
            expected.push(Field::new(tag, random.fix_value(48)));
        }
        let wire = encode_message(b"FIX.4.4", &expected).expect("generated message encodes");
        let mut decoder = FrameDecoder::new(64 * 1024);
        let mut frames = Vec::new();
        let mut cursor = 0;
        while cursor < wire.len() {
            let chunk = 1 + random.range(23);
            let end = (cursor + chunk).min(wire.len());
            frames.extend(
                decoder
                    .ingest(&wire[cursor..end])
                    .unwrap_or_else(|error| panic!("case {case} framing failed: {error}")),
            );
            cursor = end;
        }

        assert_eq!(frames.len(), 1, "case {case}");
        let parsed = parse_frame(&frames[0])
            .unwrap_or_else(|error| panic!("case {case} parse failed: {error}"));
        assert_eq!(parsed.begin_string.as_ref(), b"FIX.4.4", "case {case}");
        assert_eq!(parsed.fields, expected, "case {case}");
    }
}

#[test]
fn property_decoder_never_panics_on_arbitrary_bounded_input() {
    let mut random = XorShift64(0xbb67_ae85_84ca_a73b);

    for _ in 0..10_000 {
        let length = random.range(1_024);
        let input = (0..length).map(|_| random.next() as u8).collect::<Vec<_>>();
        let mut decoder = FrameDecoder::new(4_096);
        let _result = decoder.ingest(&input);
    }
}
