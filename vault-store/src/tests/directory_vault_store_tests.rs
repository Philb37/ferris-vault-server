use core_domain::{
    ports::vault_store::VaultStore, vault_store::vault_store_error::VaultStoreError,
};
use tempfile::NamedTempFile;

use crate::directory_vault_store::DirectoryVaultStore;

#[test]
fn should_retrieve_file() {
    // A-rrange

    let file = NamedTempFile::new().unwrap();
    let username = file.path().file_name().unwrap().to_str().unwrap();
    let path = file.path().parent().unwrap().to_str().unwrap().to_string();

    let directory_vault_store = DirectoryVaultStore::new(path);

    // A-ct

    let result = directory_vault_store.retrieve(username);

    // A-ssert
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn should_not_retrieve_file_not_found() {
    // A-rrange

    let directory_vault_store = DirectoryVaultStore::new("/wrong_path/".to_string());

    // A-ct

    let result = directory_vault_store.retrieve("doest_not_exist");

    // A-ssert
    assert!(result.is_err());

    match result {
        Err(VaultStoreError::VaultNotFound(_)) => assert!(true),
        _ => panic!("Test result should be VaultNotFound."),
    }
}

#[test]
fn should_save_file() {

    // A-rrange

    let file = NamedTempFile::new().unwrap();
    let path = file.path().parent().unwrap().to_str().unwrap().to_string();

    let directory_vault_store = DirectoryVaultStore::new(path);

    // A-ct

    let result = directory_vault_store.save("test", vec![42]);

    // A-ssert
    assert!(result.is_ok());
}
