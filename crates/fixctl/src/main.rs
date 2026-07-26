use clap::{Parser, Subcommand, ValueEnum};
use fix_control::{
    CancelOrder, Command as ControlCommand, ControlRequest, ControlResponse, ExecutionMode,
    NewOrderSingle, ReplaceOrder,
};
use fix_ipc::{connect_local, endpoint_for_profile, read_json_frame, write_json_frame};
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(name = "fixctl", about = "Agent-friendly control client for fixd")]
struct Arguments {
    #[arg(long, global = true)]
    profile: Option<String>,
    #[arg(long, global = true)]
    endpoint: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Invoke {
        #[arg(long, default_value_t = false)]
        stdin: bool,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Order {
        #[command(subcommand)]
        command: OrderCommand,
    },
    Schema,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    Status,
    Logout {
        #[arg(long)]
        request_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum OrderCommand {
    New {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Mode::DryRun)]
        mode: Mode,
        #[arg(long)]
        request_id: Option<String>,
    },
    Cancel {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Mode::DryRun)]
        mode: Mode,
        #[arg(long)]
        request_id: Option<String>,
    },
    Replace {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = Mode::DryRun)]
        mode: Mode,
        #[arg(long)]
        request_id: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    DryRun,
    Certification,
    Live,
}

impl From<Mode> for ExecutionMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::DryRun => Self::DryRun,
            Mode::Certification => Self::Certification,
            Mode::Live => Self::Live,
        }
    }
}

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    if matches!(arguments.command, Command::Schema) {
        match serde_json::to_string_pretty(&fix_control::control_request_schema()) {
            Ok(schema) => {
                println!("{schema}");
                return;
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(70);
            }
        }
    }

    let profile = match arguments.profile {
        Some(profile) => profile,
        None => {
            eprintln!("--profile is required");
            std::process::exit(2);
        }
    };
    let request = match build_request(&profile, arguments.command) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let endpoint = arguments
        .endpoint
        .unwrap_or_else(|| endpoint_for_profile(&profile));
    let response = match invoke(&endpoint, &request).await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(70);
        }
    };
    println!(
        "{}",
        serde_json::to_string(&response).expect("ControlResponse serializes")
    );
    std::process::exit(response.exit_code());
}

fn build_request(profile: &str, command: Command) -> Result<ControlRequest, String> {
    match command {
        Command::Invoke { stdin } => {
            if !stdin {
                return Err("invoke requires --stdin".to_owned());
            }
            let mut input = String::new();
            std::io::stdin()
                .read_to_string(&mut input)
                .map_err(|error| error.to_string())?;
            serde_json::from_str(&input).map_err(|error| error.to_string())
        }
        Command::Session {
            command: SessionCommand::Status,
        } => Ok(ControlRequest {
            version: 1,
            request_id: generated_request_id("status"),
            profile: profile.to_owned(),
            execution_mode: ExecutionMode::Inspect,
            command: ControlCommand::SessionStatus,
            auth: None,
        }),
        Command::Session {
            command: SessionCommand::Logout { request_id },
        } => Ok(ControlRequest {
            version: 1,
            request_id: request_id.unwrap_or_else(|| generated_request_id("logout")),
            profile: profile.to_owned(),
            execution_mode: ExecutionMode::Certification,
            command: ControlCommand::SessionLogout,
            auth: None,
        }),
        Command::Order {
            command:
                OrderCommand::New {
                    input,
                    mode,
                    request_id,
                },
        } => {
            let order: NewOrderSingle =
                serde_json::from_slice(&std::fs::read(input).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            Ok(ControlRequest {
                version: 1,
                request_id: request_id.unwrap_or_else(|| generated_request_id("order")),
                profile: profile.to_owned(),
                execution_mode: mode.into(),
                command: ControlCommand::NewOrderSingle(order),
                auth: None,
            })
        }
        Command::Order {
            command:
                OrderCommand::Cancel {
                    input,
                    mode,
                    request_id,
                },
        } => {
            let order: CancelOrder =
                serde_json::from_slice(&std::fs::read(input).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            Ok(ControlRequest {
                version: 1,
                request_id: request_id.unwrap_or_else(|| generated_request_id("cancel")),
                profile: profile.to_owned(),
                execution_mode: mode.into(),
                command: ControlCommand::CancelOrder(order),
                auth: None,
            })
        }
        Command::Order {
            command:
                OrderCommand::Replace {
                    input,
                    mode,
                    request_id,
                },
        } => {
            let order: ReplaceOrder =
                serde_json::from_slice(&std::fs::read(input).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            Ok(ControlRequest {
                version: 1,
                request_id: request_id.unwrap_or_else(|| generated_request_id("replace")),
                profile: profile.to_owned(),
                execution_mode: mode.into(),
                command: ControlCommand::ReplaceOrder(order),
                auth: None,
            })
        }
        Command::Schema => Err("schema does not create a request".to_owned()),
    }
}

async fn invoke(endpoint: &str, request: &ControlRequest) -> Result<ControlResponse, String> {
    let mut stream = connect_local(endpoint)
        .await
        .map_err(|error| error.to_string())?;
    write_json_frame(&mut stream, request, 256 * 1024)
        .await
        .map_err(|error| error.to_string())?;
    read_json_frame(&mut stream, 256 * 1024)
        .await
        .map_err(|error| error.to_string())
}

fn generated_request_id(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{prefix}-{millis}-{}", std::process::id())
}
