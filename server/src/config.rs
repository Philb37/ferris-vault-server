use config::{Config, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct AppConfig {
    pub server: ServerInfo,
    pub vault_store: VaultStoreInfo,
    pub password_file: PasswordFileInfo
}

#[derive(Debug, Deserialize, Default)]
pub struct ServerInfo {
    pub request_max_ttl: u64
}

#[derive(Debug, Deserialize, Default)]
pub struct VaultStoreInfo {
    pub path: String
}

#[derive(Debug, Deserialize, Default)]
pub struct PasswordFileInfo {
    pub path: String
}

impl AppConfig {
    pub fn build(args: Vec<String>) -> Result<Self, String> {
        if args.len() < 2 {
            return Err("First argument should be the config path.".to_string());
        }

        let config = Config::builder()
            .add_source(File::with_name(&args[1]))
            .build()
            .map_err(|error| error.to_string())?;

        let app_config = config
            .try_deserialize()
            .map_err(|error| error.to_string())?;

        Ok(app_config)
    }
}
