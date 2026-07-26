#![forbid(unsafe_code)]

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("IPC frame length {actual} exceeds maximum {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("IPC I/O error: {0}")]
    Io(String),
    #[error("IPC JSON error: {0}")]
    Json(String),
}

pub async fn write_json_frame<W, T>(
    writer: &mut W,
    value: &T,
    maximum: usize,
) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value).map_err(|error| IpcError::Json(error.to_string()))?;
    if payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(IpcError::FrameTooLarge {
            actual: payload.len(),
            maximum,
        });
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|error| IpcError::Io(error.to_string()))?;
    writer
        .write_all(&payload)
        .await
        .map_err(|error| IpcError::Io(error.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|error| IpcError::Io(error.to_string()))
}

pub async fn read_json_frame<R, T>(reader: &mut R, maximum: usize) -> Result<T, IpcError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .await
        .map_err(|error| IpcError::Io(error.to_string()))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > maximum {
        return Err(IpcError::FrameTooLarge {
            actual: length,
            maximum,
        });
    }

    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| IpcError::Io(error.to_string()))?;
    serde_json::from_slice(&payload).map_err(|error| IpcError::Json(error.to_string()))
}

#[cfg(windows)]
pub type LocalClientStream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(windows)]
pub type LocalServerStream = tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(unix)]
pub type LocalClientStream = tokio::net::UnixStream;
#[cfg(unix)]
pub type LocalServerStream = tokio::net::UnixStream;

#[cfg(windows)]
#[must_use]
pub fn endpoint_for_profile(profile: &str) -> String {
    format!(r"\\.\pipe\fixd.{profile}")
}

#[cfg(unix)]
#[must_use]
pub fn endpoint_for_profile(profile: &str) -> String {
    format!("/tmp/fixd.{profile}.sock")
}

#[cfg(windows)]
pub struct LocalListener {
    pipe_name: String,
    first_instance: bool,
}

#[cfg(windows)]
impl LocalListener {
    pub fn bind(pipe_name: impl Into<String>) -> Result<Self, IpcError> {
        Ok(Self {
            pipe_name: pipe_name.into(),
            first_instance: true,
        })
    }

    pub async fn accept(&mut self) -> Result<LocalServerStream, IpcError> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let mut options = ServerOptions::new();
        options.first_pipe_instance(self.first_instance);
        options.reject_remote_clients(true);
        let server = options
            .create(&self.pipe_name)
            .map_err(|error| IpcError::Io(error.to_string()))?;
        self.first_instance = false;
        server
            .connect()
            .await
            .map_err(|error| IpcError::Io(error.to_string()))?;
        Ok(server)
    }
}

#[cfg(unix)]
pub struct LocalListener {
    listener: tokio::net::UnixListener,
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl LocalListener {
    pub fn bind(path: impl AsRef<std::path::Path>) -> Result<Self, IpcError> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        let path = path.as_ref().to_path_buf();
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket() {
                return Err(IpcError::Io(format!(
                    "refusing to replace non-socket IPC path {}",
                    path.display()
                )));
            }
            std::fs::remove_file(&path).map_err(|error| IpcError::Io(error.to_string()))?;
        }
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|error| IpcError::Io(error.to_string()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| IpcError::Io(error.to_string()))?;
        Ok(Self { listener, path })
    }

    pub async fn accept(&mut self) -> Result<LocalServerStream, IpcError> {
        self.listener
            .accept()
            .await
            .map(|(stream, _)| stream)
            .map_err(|error| IpcError::Io(error.to_string()))
    }
}

#[cfg(unix)]
impl Drop for LocalListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
pub async fn connect_local(pipe_name: &str) -> Result<LocalClientStream, IpcError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio::time::{Duration, sleep};

    const ERROR_PIPE_BUSY: i32 = 231;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    for _ in 0..100 {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(ERROR_PIPE_BUSY) | Some(ERROR_FILE_NOT_FOUND)
                ) =>
            {
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(IpcError::Io(error.to_string())),
        }
    }
    Err(IpcError::Io("named pipe remained busy".to_owned()))
}

#[cfg(unix)]
pub async fn connect_local(path: &str) -> Result<LocalClientStream, IpcError> {
    tokio::net::UnixStream::connect(path)
        .await
        .map_err(|error| IpcError::Io(error.to_string()))
}
