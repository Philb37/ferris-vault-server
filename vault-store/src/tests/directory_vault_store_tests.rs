use core_domain::ports::{file_storage::FileStorage, vault_store::VaultStore};

use crate::directory_vault_store::DirectoryVaultStore;

#[test]
fn should_retrieve_file() {
    // A-rrange

    let username = "username";

    let directory_vault_store = DirectoryVaultStore::new(MockFileStorage::new(String::new()));

    // A-ct

    let result = directory_vault_store.retrieve(username);

    // A-ssert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![42]);
}

#[test]
fn should_save_file() {
    // A-rrange

    let directory_vault_store = DirectoryVaultStore::new(MockFileStorage::new(String::new()));

    // A-ct

    let result = directory_vault_store.save("test", vec![42]);

    // A-ssert
    assert!(result.is_ok());
}

struct MockFileStorage;

impl FileStorage for MockFileStorage {
    fn new(_: String) -> Self {
        Self
    }

    fn retrieve(&self, _: &str) -> core_domain::file_storage::file_storage_error::Result<Vec<u8>> {
        Ok(vec![42])
    }

    fn save(
        &self,
        _: &str,
        _: Vec<u8>,
    ) -> core_domain::file_storage::file_storage_error::Result<()> {
        Ok(())
    }
}
