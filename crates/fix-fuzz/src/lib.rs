#![forbid(unsafe_code)]

use fix_protocol::{FrameDecoder, ParseDictionary, parse_frame};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuzzConfig {
    pub seed: u64,
    pub cases: usize,
    pub max_input_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FuzzStats {
    pub cases: usize,
    pub framed_messages: usize,
    pub parsed_messages: usize,
    pub rejected_inputs: usize,
}

pub fn run_campaign(config: FuzzConfig) -> FuzzStats {
    let mut random = XorShift64(config.seed.max(1));
    let corpus = [
        b"8=FIX.4.2\x019=5\x0135=0\x0110=161\x01".as_slice(),
        b"8=FIX.4.4\x019=17\x0135=A\x0195=3\x0196=A\x01B\x0110=247\x01".as_slice(),
    ];
    let mut stats = FuzzStats::default();

    for case_index in 0..config.cases {
        let mut input = if case_index % 3 == 0 {
            corpus[random.range(corpus.len())].to_vec()
        } else {
            let maximum = config.max_input_bytes.max(1);
            let length = random.range(maximum);
            (0..length).map(|_| random.next() as u8).collect()
        };
        if !input.is_empty() && case_index % 7 != 0 {
            let mutations = 1 + random.range(8);
            for _ in 0..mutations {
                let index = random.range(input.len());
                input[index] ^= 1_u8 << random.range(8);
            }
        }

        let mut decoder = FrameDecoder::new(config.max_input_bytes.max(64));
        let mut cursor = 0;
        let mut rejected = false;
        while cursor < input.len() {
            let end = (cursor + 1 + random.range(31)).min(input.len());
            match decoder.ingest(&input[cursor..end]) {
                Ok(frames) => {
                    stats.framed_messages += frames.len();
                    for frame in frames {
                        if parse_frame(&frame, &ParseDictionary::new()).is_ok() {
                            stats.parsed_messages += 1;
                        } else {
                            rejected = true;
                        }
                    }
                }
                Err(_) => {
                    rejected = true;
                    break;
                }
            }
            cursor = end;
        }
        if rejected {
            stats.rejected_inputs += 1;
        }
        stats.cases += 1;
    }

    stats
}

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
}

#[cfg(test)]
mod tests {
    use super::{FuzzConfig, run_campaign};

    #[test]
    fn deterministic_campaign_completes_without_a_panic() {
        let stats = run_campaign(FuzzConfig {
            seed: 0x3c6e_f372_fe94_f82b,
            cases: 1_000,
            max_input_bytes: 4_096,
        });

        assert_eq!(stats.cases, 1_000);
        assert!(stats.rejected_inputs > 0);
        assert!(stats.parsed_messages > 0);
    }
}
