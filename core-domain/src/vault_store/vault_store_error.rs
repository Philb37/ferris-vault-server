#[derive(Debug)]
pub enum VaultStoreError {
}

impl std::fmt::Display for VaultStoreError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "todo")
    }
}

impl std::error::Error for VaultStoreError {}

pub type Result<T> = std::result::Result<T, VaultStoreError>;