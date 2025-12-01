use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use core_domain::{
    file_storage::file_storage_error::{FileStorageError, Result},
    ports::file_storage::FileStorage,
};

const INVALID_UTF8_PATH: &'static str = "Invalid UTF-8 file path.";

pub struct StandardFileStorage {
    path: String,
}

impl FileStorage for StandardFileStorage {
    fn new(path: String) -> Self {
        Self { path }
    }

    fn retrieve(&self, file_name: &str) -> Result<Vec<u8>> {
        let file_path = Path::new(&self.path).join(file_name);

        let file = File::open(&file_path)
            .map_err(|error| file_error_to_file_storage_error(file_path, error))?;

        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader
            .read_to_end(&mut buffer)
            .map_err(|error| FileStorageError::ReadingFile(error.to_string()))?;

        Ok(buffer)
    }

    fn save(&self, file_name: &str, vault: Vec<u8>) -> Result<()> {
        let file_path = Path::new(&self.path).join(file_name);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&file_path)
            .map_err(|error| file_error_to_file_storage_error(file_path, error))?;

        file.write_all(&vault)
            .map_err(|error| FileStorageError::WritingToFile(error.to_string()))?;

        Ok(())
    }
}

fn file_error_to_file_storage_error(file_path: PathBuf, error: Error) -> FileStorageError {
    let Some(file_path) = file_path.to_str() else {
        return FileStorageError::Internal(INVALID_UTF8_PATH.to_string());
    };

    return match error.kind() {
        ErrorKind::NotFound => FileStorageError::FileNotFound(file_path.to_string()),
        ErrorKind::PermissionDenied => FileStorageError::PermissionDenied(file_path.to_string()),
        _ => FileStorageError::Internal(error.to_string()),
    };
}
