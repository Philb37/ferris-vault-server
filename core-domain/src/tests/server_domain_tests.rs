use crate::{
    domain::server_domain::{Domain, ServerDomain},
    ports::{authentication::Authentication, vault_store::VaultStore},
};

#[test]
fn should_start_server_registration() {
    // A-rrange

    let username = "username";
    let client_message = vec![42];

    let mock_vault_store = MockVaultStore;
    let mock_authentication = MockAuthentication;

    let server_domain = ServerDomain::new(mock_vault_store, mock_authentication);

    // A-ct

    let result = server_domain.start_server_registration(username, client_message);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![42]);
}

#[test]
fn should_finish_server_registration() {

    // A-rrange

    let username = "username";
    let client_message = vec![42];

    let mock_vault_store = MockVaultStore;
    let mock_authentication = MockAuthentication;

    let server_domain = ServerDomain::new(mock_vault_store, mock_authentication);

    // A-ct

    let result = server_domain.finish_server_registration(username, client_message);

    // A-ssert

    assert!(result.is_ok());
}

#[test]
fn should_start_server_login() {

    // A-rrange

    let username = "username";
    let client_message = vec![42];

    let mock_vault_store = MockVaultStore;
    let mock_authentication = MockAuthentication;

    let mut server_domain = ServerDomain::new(mock_vault_store, mock_authentication);

    // A-ct

    let result = server_domain.start_server_login(username, client_message);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![42]);
}

#[test]
fn should_finish_server_login() {

    // A-rrange

    let username = "username";
    let client_message = vec![42];

    let mock_vault_store = MockVaultStore;
    let mock_authentication = MockAuthentication;

    let mut server_domain = ServerDomain::new(mock_vault_store, mock_authentication);

    // A-ct

    let result = server_domain.finish_server_login(username, client_message);

    // A-ssert

    assert!(result.is_ok());
}

#[test]
fn should_get_vault() {

    // A-rrange

    let bearer_token = "bearer ...";
    let verb = "GET";
    let uri = "http://localhost";
    let timestamp = "42";
    let signature = "signature";

    let mock_vault_store = MockVaultStore;
    let mock_authentication = MockAuthentication;

    let server_domain = ServerDomain::new(mock_vault_store, mock_authentication);

    // A-ct

    let result = server_domain.get_vault(bearer_token, verb, uri, timestamp, signature);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![42]);
}

#[test]
fn should_save_vault() {

    // A-rrange

    let bearer_token = "bearer ...";
    let verb = "GET";
    let uri = "http://localhost";
    let timestamp = "42";
    let signature = "signature";
    let vault = vec![42];

    let mock_vault_store = MockVaultStore;
    let mock_authentication = MockAuthentication;

    let server_domain = ServerDomain::new(mock_vault_store, mock_authentication);

    // A-ct

    let result = server_domain.save_vault(bearer_token, verb, uri, timestamp, signature, vault);

    // A-ssert

    assert!(result.is_ok());
}

struct MockVaultStore;

impl VaultStore for MockVaultStore {
    fn retrieve(&self, _: &str) -> crate::vault_store::vault_store_error::Result<Vec<u8>> {
        Ok(vec![42])
    }

    fn save(
        &self,
        _: &str,
        _: Vec<u8>,
    ) -> crate::vault_store::vault_store_error::Result<()> {
        Ok(())
    }
}

struct MockAuthentication;

impl Authentication for MockAuthentication {
    fn start_server_registration(
        &self,
        _: &str,
        _: Vec<u8>,
    ) -> crate::authentication::authentication_error::Result<Vec<u8>> {
        Ok(vec![42])
    }

    fn finish_server_registration(
        &self,
        _: &str,
        _: Vec<u8>,
    ) -> crate::authentication::authentication_error::Result<()> {
        Ok(())
    }

    fn start_server_login(
        &mut self,
        _: &str,
        _: Vec<u8>,
    ) -> crate::authentication::authentication_error::Result<Vec<u8>> {
        Ok(vec![42])
    }

    fn finish_server_login(
        &mut self,
        _: &str,
        _: Vec<u8>,
    ) -> crate::authentication::authentication_error::Result<()> {
        Ok(())
    }

    fn verify_bearer_token(&self, _: &str) -> bool {
        true
    }

    fn verify_signature(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> crate::authentication::authentication_error::Result<bool> {
        Ok(true)
    }

    fn verify_request_timestamp(
        &self,
        _: &str,
    ) -> crate::authentication::authentication_error::Result<bool> {
        Ok(true)
    }

    fn get_username_from_session(
        &self,
        _: &str,
    ) -> crate::authentication::authentication_error::Result<String> {
        Ok(String::from("username"))
    }
}
