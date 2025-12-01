use crate::{
    authentication::authentication_error::AuthenticationError,
    domain::server_domain_errors::{Result, ServerDomainError},
    ports::{authentication::Authentication, vault_store::VaultStore},
    vault_store::vault_store_error::VaultStoreError,
};

const INVALID_BEARER_TOKEN: &'static str = "Invalid bearer token.";
const INVALID_SIGNATURE: &'static str = "Invalid request signature.";
const INVALID_REQUEST: &'static str = "Invalid request, it outlived its duration.";

pub trait Domain<VS: VaultStore, A: Authentication> {
    fn start_server_registration(&self, username: &str, client_message: Vec<u8>)
    -> Result<Vec<u8>>;
    fn finish_server_registration(&self, username: &str, client_message: Vec<u8>) -> Result<()>;
    fn start_server_login(&mut self, username: &str, client_message: Vec<u8>) -> Result<Vec<u8>>;
    fn finish_server_login(&mut self, username: &str, client_message: Vec<u8>) -> Result<()>;
    fn get_vault(
        &self,
        bearer_token: &str,
        verb: &str,
        uri: &str,
        timestamp: &str,
        signature: &str,
    ) -> Result<Vec<u8>>;
    fn save_vault(
        &self,
        bearer_token: &str,
        verb: &str,
        uri: &str,
        timestamp: &str,
        signature: &str,
        vault: Vec<u8>,
    ) -> Result<()>;
}

pub struct ServerDomain<VS: VaultStore, A: Authentication> {
    vault_store: VS,
    authentication: A,
}

impl<VS: VaultStore, A: Authentication> ServerDomain<VS, A> {
    pub fn new(vault_store: VS, authentication: A) -> Self {
        Self {
            vault_store,
            authentication,
        }
    }

    fn verify_request_and_get_username(
        &self,
        bearer_token: &str,
        verb: &str,
        uri: &str,
        timestamp: &str,
        signature: &str,
    ) -> Result<String> {
        if !self.authentication.verify_bearer_token(bearer_token) {
            return Err(ServerDomainError::Forbidden(
                INVALID_BEARER_TOKEN.to_string(),
            ));
        }

        match self
            .authentication
            .verify_signature(bearer_token, verb, uri, timestamp, signature)
        {
            Ok(value) if !value => {
                return Err(ServerDomainError::Forbidden(INVALID_SIGNATURE.to_string()));
            }
            Err(error) => return Err(ServerDomainError::Internal(error.to_string())),
            _ => {}
        }

        match self.authentication.verify_request_timestamp(timestamp) {
            Ok(value) if !value => {
                return Err(ServerDomainError::Forbidden(INVALID_REQUEST.to_string()));
            }
            Err(error) => return Err(ServerDomainError::Internal(error.to_string())),
            _ => {}
        }

        self.authentication
            .get_username_from_session(bearer_token)
            .map_err(authentication_error_to_server_domain_error)
    }
}

impl<VS: VaultStore, A: Authentication> Domain<VS, A> for ServerDomain<VS, A> {
    fn start_server_registration(
        &self,
        username: &str,
        client_message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.authentication
            .start_server_registration(username, client_message)
            .map_err(authentication_error_to_server_domain_error)
    }

    fn finish_server_registration(&self, username: &str, client_message: Vec<u8>) -> Result<()> {
        self.authentication
            .finish_server_registration(username, client_message)
            .map_err(authentication_error_to_server_domain_error)?;

        self.vault_store.save(username, vec![])
            .map_err(vault_store_error_to_server_domain_error)?;

        Ok(())
    }

    fn start_server_login(&mut self, username: &str, client_message: Vec<u8>) -> Result<Vec<u8>> {
        self.authentication
            .start_server_login(username, client_message)
            .map_err(authentication_error_to_server_domain_error)
    }

    fn finish_server_login(&mut self, username: &str, client_message: Vec<u8>) -> Result<()> {
        self.authentication
            .finish_server_login(username, client_message)
            .map_err(authentication_error_to_server_domain_error)
    }

    fn get_vault(
        &self,
        bearer_token: &str,
        verb: &str,
        uri: &str,
        timestamp: &str,
        signature: &str,
    ) -> Result<Vec<u8>> {
        let username =
            self.verify_request_and_get_username(bearer_token, verb, uri, timestamp, signature)?;

        self.vault_store
            .retrieve(&username)
            .map_err(vault_store_error_to_server_domain_error)
    }

    fn save_vault(
        &self,
        bearer_token: &str,
        verb: &str,
        uri: &str,
        timestamp: &str,
        signature: &str,
        vault: Vec<u8>,
    ) -> Result<()> {
        let username =
            self.verify_request_and_get_username(bearer_token, verb, uri, timestamp, signature)?;

        self.vault_store
            .save(&username, vault)
            .map_err(vault_store_error_to_server_domain_error)
    }
}

fn authentication_error_to_server_domain_error(
    authentication_error: AuthenticationError,
) -> ServerDomainError {
    match authentication_error {
        AuthenticationError::Login(error) => ServerDomainError::Internal(error),
        AuthenticationError::Registration(error) => ServerDomainError::Internal(error),
        AuthenticationError::CreatingSession(error) => ServerDomainError::Internal(error),
        AuthenticationError::Deserialization(error) => ServerDomainError::Internal(error),
        AuthenticationError::PasswordFileRetrieve(error) => ServerDomainError::Forbidden(error),
        AuthenticationError::Internal(error) => ServerDomainError::Internal(error),
        AuthenticationError::PasswordFileSave(error) => ServerDomainError::Internal(error),
    }
}

fn vault_store_error_to_server_domain_error(
    vault_store_error: VaultStoreError,
) -> ServerDomainError {
    ServerDomainError::Internal(vault_store_error.to_string())
}
