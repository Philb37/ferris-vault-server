use crate::file_storage::file_storage_error::Result;

pub trait FileStorage {
    fn new(path: String) -> Self; 
    fn retrieve(&self, file_name: &str) -> Result<Vec<u8>>;
    fn save(&self, file_name: &str, content: Vec<u8>) -> Result<()>;
}