use core_domain::{
    ports::{file_storage::FileStorage, vault_store::VaultStore},
    utils::file_storage_error_to_vault_store_error,
    vault_store::vault_store_error::Result,
};

pub struct DirectoryVaultStore<FS: FileStorage> {
    file_storage: FS,
}

impl<FS: FileStorage> DirectoryVaultStore<FS> {
    pub fn new(file_storage: FS) -> Self {
        Self { file_storage }
    }
}

impl<FS: FileStorage> VaultStore for DirectoryVaultStore<FS> {
    fn retrieve(&self, username: &str) -> Result<Vec<u8>> {
        self.file_storage
            .retrieve(username)
            .map_err(file_storage_error_to_vault_store_error)
    }

    fn save(&self, username: &str, vault: Vec<u8>) -> Result<()> {
        self.file_storage
            .save(username, vault)
            .map_err(file_storage_error_to_vault_store_error)
    }
}
