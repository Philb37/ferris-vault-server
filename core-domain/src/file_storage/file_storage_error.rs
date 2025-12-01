#[derive(Debug)]
pub enum FileStorageError {
    FileNotFound(String),
    PermissionDenied(String),
    ReadingFile(String),
    WritingToFile(String),
    Internal(String)
}

impl std::fmt::Display for FileStorageError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            FileStorageError::FileNotFound(path) => write!(formatter, "Vault {} not found", path),
            FileStorageError::PermissionDenied(path) => write!(formatter, "You don't have access to this path: {}", path),
            FileStorageError::ReadingFile(message) => write!(formatter, "Error during file reading: {}", message),
            FileStorageError::WritingToFile(message) => write!(formatter, "Error writing to the file: {}", message),
            FileStorageError::Internal(message) => write!(formatter, "Internal error: {}", message)
        }
    }
}

impl std::error::Error for FileStorageError {}

pub type Result<T> = std::result::Result<T, FileStorageError>;