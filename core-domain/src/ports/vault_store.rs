use crate::vault_store::vault_store_error::Result;

pub trait VaultStore {
    fn retrieve(&self, username: &str) -> Result<Vec<u8>>;
    fn save(&self, username: &str, vault: Vec<u8>) -> Result<()>;
}