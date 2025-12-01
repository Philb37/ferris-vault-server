use crate::authentication::authentication_error::Result;

pub trait Authentication {

    fn start_server_registration(&self, username: &str, client_registration_message: Vec<u8>) -> Result<Vec<u8>>;
    fn finish_server_registration(&self, username: &str, client_registration_message: Vec<u8>) -> Result<()>;
    fn start_server_login(&mut self, username: &str, client_login_message: Vec<u8>) -> Result<Vec<u8>>;
    fn finish_server_login(&mut self, username: &str, client_login_message: Vec<u8>) -> Result<()>;
    fn verify_bearer_token(&self, bearer_token: &str) -> bool;
    fn verify_signature(&self, bearer_token: &str, verb: &str, uri: &str, timestamp: &str, signature: &str) -> Result<bool>;
    fn verify_request_timestamp(&self, request_creation_timestamp: &str) -> Result<bool>;
}