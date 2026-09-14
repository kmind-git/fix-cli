//! QuickFIX-style file logging: per-day `Messages` (wire) and `Event` log files.
//!
//! Line formats mirror QuickFIX acceptor logs:
//! - messages: `{ts}: incoming {wire}` / `{ts}: outgoing {wire}` (SOH bytes preserved)
//! - events:   `{ts}: INFO {text}` / `{ts}: ERROR {text}`
//! - files:    `{prefix}_Messages_{Day}-{seq}.log` and `{prefix}_Event_{Day}-{seq}.log`
//!
//! `SessionLogger` is cheap to clone; clones share the same underlying files.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use time::macros::format_description;
use time::{Date, OffsetDateTime};

const TIMESTAMP_FORMAT: &[time::format_description::BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");

struct OpenLogs {
    day: Date,
    messages: BufWriter<File>,
    events: BufWriter<File>,
}

/// File logger shared across sessions. Files are created lazily on the first
/// write and rotate when the local date changes.
#[derive(Clone)]
pub struct SessionLogger {
    inner: Option<Arc<LoggerCore>>,
}

impl SessionLogger {
    pub fn new(log_dir: impl AsRef<Path>, prefix: impl Into<String>) -> Self {
        Self {
            inner: Some(Arc::new(LoggerCore {
                log_dir: log_dir.as_ref().to_path_buf(),
                prefix: prefix.into(),
                open: Mutex::new(None),
            })),
        }
    }

    /// No-op logger used by tests and callers that do not want files.
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn incoming(&self, wire: &[u8]) {
        if let Some(core) = &self.inner {
            core.write_message("incoming", wire);
        }
    }

    pub fn outgoing(&self, wire: &[u8]) {
        if let Some(core) = &self.inner {
            core.write_message("outgoing", wire);
        }
    }

    pub fn info(&self, message: impl AsRef<str>) {
        if let Some(core) = &self.inner {
            core.write_event("INFO", message.as_ref());
        }
    }

    pub fn error(&self, message: impl AsRef<str>) {
        if let Some(core) = &self.inner {
            core.write_event("ERROR", message.as_ref());
        }
    }
}

struct LoggerCore {
    log_dir: PathBuf,
    prefix: String,
    open: Mutex<Option<OpenLogs>>,
}

impl LoggerCore {
    fn write_message(&self, direction: &str, wire: &[u8]) {
        Self::ensure_current(&self.open, &self.log_dir, &self.prefix);
        let mut open = Self::lock(&self.open);
        let Some(logs) = open.as_mut() else {
            return;
        };
        let line = format!("{}: {direction} ", timestamp());
        let _ = logs.messages.write_all(line.as_bytes());
        let _ = logs.messages.write_all(wire);
        let _ = logs.messages.write_all(b"\n");
        let _ = logs.messages.flush();
    }

    fn write_event(&self, level: &str, message: &str) {
        Self::ensure_current(&self.open, &self.log_dir, &self.prefix);
        let mut open = Self::lock(&self.open);
        let Some(logs) = open.as_mut() else {
            return;
        };
        let line = format!("{}: {level} {message}\n", timestamp());
        let _ = logs.events.write_all(line.as_bytes());
        let _ = logs.events.flush();
    }

    /// Rotate on date change; first use opens today's files.
    fn ensure_current(state: &Mutex<Option<OpenLogs>>, log_dir: &Path, prefix: &str) {
        let mut open = Self::lock(state);
        if !matches!(&*open, Some(logs) if logs.day == today()) {
            *open = Some(Self::open(log_dir, prefix));
        }
    }

    fn lock(state: &Mutex<Option<OpenLogs>>) -> MutexGuard<'_, Option<OpenLogs>> {
        match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn open(log_dir: &Path, prefix: &str) -> OpenLogs {
        let day = today();
        let _ = fs::create_dir_all(log_dir);
        let day_token = weekday_token(day);
        let open_file = |kind: &str| {
            let path = log_dir.join(format!("{prefix}_{kind}_{day_token}-0.log"));
            BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .expect("open FIX log file"),
            )
        };
        OpenLogs {
            day,
            messages: open_file("Messages"),
            events: open_file("Event"),
        }
    }
}

fn timestamp() -> String {
    now().format(&TIMESTAMP_FORMAT).expect("format timestamp")
}

fn today() -> Date {
    now().date()
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

fn weekday_token(day: Date) -> &'static str {
    match day.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    }
}
