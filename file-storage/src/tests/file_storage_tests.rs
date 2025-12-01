use tempfile::NamedTempFile;

use crate::file_storage::StandardFileStorage;

use core_domain::{
    file_storage::file_storage_error::FileStorageError,
    ports::file_storage::FileStorage,
};

#[test]
fn should_retrieve_file() {
    // A-rrange

    let file = NamedTempFile::new().unwrap();
    let file_name = file.path().file_name().unwrap().to_str().unwrap();
    let path = file.path().parent().unwrap().to_str().unwrap().to_string();

    let standard_file_storage = StandardFileStorage::new(path);

    // A-ct

    let result = standard_file_storage.retrieve(file_name);

    // A-ssert
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn should_not_retrieve_file_not_found() {
    // A-rrange

    let standard_file_storage = StandardFileStorage::new("/wrong_path/".to_string());

    // A-ct

    let result = standard_file_storage.retrieve("doest_not_exist");

    // A-ssert
    assert!(result.is_err());

    match result {
        Err(FileStorageError::FileNotFound(_)) => assert!(true),
        _ => panic!("Test result should be FileNotFound."),
    }
}

#[test]
fn should_save_file() {

    // A-rrange

    let file = NamedTempFile::new().unwrap();
    let path = file.path().parent().unwrap().to_str().unwrap().to_string();

    let standard_file_storage = StandardFileStorage::new(path);

    // A-ct

    let result = standard_file_storage.save("test", vec![42]);

    // A-ssert
    assert!(result.is_ok());
}
