#[derive(Debug)]
pub enum VaultStoreError {
    VaultNotFound(String),
    PermissionDenied(String),
    ReadingFile(String),
    WritingToFile(String),
    Internal(String)
}

impl std::fmt::Display for VaultStoreError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            VaultStoreError::VaultNotFound(path) => write!(formatter, "Vault {} not found", path),
            VaultStoreError::PermissionDenied(path) => write!(formatter, "You don't have access to this path: {}", path),
            VaultStoreError::ReadingFile(message) => write!(formatter, "Error during file reading: {}", message),
            VaultStoreError::WritingToFile(message) => write!(formatter, "Error writing to the file: {}", message),
            VaultStoreError::Internal(message) => write!(formatter, "Internal error: {}", message)
        }
    }
}

impl std::error::Error for VaultStoreError {}

pub type Result<T> = std::result::Result<T, VaultStoreError>;