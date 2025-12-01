use crate::{
    file_storage::file_storage_error::FileStorageError,
    vault_store::vault_store_error::VaultStoreError,
};

pub fn file_storage_error_to_vault_store_error(
    file_storage_error: FileStorageError,
) -> VaultStoreError {
    match file_storage_error {
        FileStorageError::FileNotFound(error) => VaultStoreError::VaultNotFound(error),
        FileStorageError::PermissionDenied(error) => VaultStoreError::PermissionDenied(error),
        FileStorageError::ReadingFile(error) => VaultStoreError::ReadingFile(error),
        FileStorageError::WritingToFile(error) => VaultStoreError::WritingToFile(error),
        FileStorageError::Internal(error) => VaultStoreError::Internal(error),
    }
}
