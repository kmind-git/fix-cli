#![forbid(unsafe_code)]

use fix_fuzz::{FuzzConfig, run_campaign};

fn main() -> Result<(), String> {
    let mut config = FuzzConfig {
        seed: 0x3c6e_f372_fe94_f82b,
        cases: 100_000,
        max_input_bytes: 64 * 1024,
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--seed" => {
                config.seed = value
                    .parse()
                    .map_err(|_| "--seed must be a u64".to_owned())?;
            }
            "--cases" => {
                config.cases = value
                    .parse()
                    .map_err(|_| "--cases must be an integer".to_owned())?;
            }
            "--max-input-bytes" => {
                config.max_input_bytes = value
                    .parse()
                    .map_err(|_| "--max-input-bytes must be an integer".to_owned())?;
            }
            _ => return Err(format!("unknown argument {argument}")),
        }
    }
    let stats = run_campaign(config);
    println!(
        "{{\"seed\":{},\"cases\":{},\"framed_messages\":{},\"parsed_messages\":{},\"rejected_inputs\":{}}}",
        config.seed,
        stats.cases,
        stats.framed_messages,
        stats.parsed_messages,
        stats.rejected_inputs
    );
    Ok(())
}
