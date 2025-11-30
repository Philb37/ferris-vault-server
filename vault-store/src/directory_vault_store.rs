use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use core_domain::{
    ports::vault_store::VaultStore,
    vault_store::vault_store_error::{Result, VaultStoreError},
};

const INVALID_UTF8_PATH: &'static str = "Invalid UTF-8 file path.";

pub struct DirectoryVaultStore {
    path: String,
}

impl DirectoryVaultStore {
    pub fn new(path: String) -> Self {
        Self {
            path
        }
    }
}

impl VaultStore for DirectoryVaultStore {
    fn retrieve(&self, username: &str) -> Result<Vec<u8>> {
        let vault_path = Path::new(&self.path).join(username);

        let file = File::open(&vault_path)
            .map_err(|error| file_error_to_vault_store_error(vault_path, error))?;
        
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader
            .read_to_end(&mut buffer)
            .map_err(|error| VaultStoreError::ReadingFile(error.to_string()))?;

        Ok(buffer)
    }

    fn save(&self, username: &str, vault: Vec<u8>) -> Result<()> {
        let vault_path = Path::new(&self.path).join(username);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&vault_path)
            .map_err(|error| file_error_to_vault_store_error(vault_path, error))?;

        file.write_all(&vault)
            .map_err(|error| VaultStoreError::WritingToFile(error.to_string()))?;

        Ok(())
    }
}

fn file_error_to_vault_store_error(vault_path: PathBuf, error: Error) -> VaultStoreError {
    let Some(vault_path) = vault_path.to_str() else {
        return VaultStoreError::Internal(INVALID_UTF8_PATH.to_string());
    };

    return match error.kind() {
        ErrorKind::NotFound => VaultStoreError::VaultNotFound(vault_path.to_string()),
        ErrorKind::PermissionDenied => VaultStoreError::PermissionDenied(vault_path.to_string()),
        _ => VaultStoreError::Internal(error.to_string()),
    };
}
