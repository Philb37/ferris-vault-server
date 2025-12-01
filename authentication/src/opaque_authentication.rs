use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use core_domain::{
    authentication::authentication_error::{AuthenticationError, Result},
    ports::{authentication::Authentication, file_storage::FileStorage},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerLoginStartResult,
    ServerRegistration, ServerSetup, argon2::Argon2, rand::rngs::OsRng,
};
use sha2::Sha512;

use crate::session::Session;

const USERNAME_DID_NOT_START_LOGIN_PHASE: &'static str = "Username did not start login phase.";
const SESSION_SHOULD_BE_PRESENT: &'static str = "Session should be present, checks should have been performed before.";

pub type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Default)]
pub struct StandardCipherSuite;

impl CipherSuite for StandardCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub struct OpaqueAuthentication<FS: FileStorage> {
    file_storage: FS,
    server_setup: ServerSetup<StandardCipherSuite>,
    current_login_sessions: HashMap<String, ServerLoginStartResult<StandardCipherSuite>>,
    logged_sessions: HashMap<String, Session>,
    request_max_ttl: u64,
}

impl<FS: FileStorage> OpaqueAuthentication<FS> {
    fn create_session(&mut self, session_key: &[u8], username: &str) -> Result<()> {
        let hkdf = Hkdf::<Sha512>::from_prk(session_key)
            .map_err(|error| AuthenticationError::CreatingSession(error.to_string()))?;

        let mut token = vec![0u8; 64];

        hkdf.expand(b"opaque-session-token", &mut token)
            .map_err(|error| AuthenticationError::CreatingSession(error.to_string()))?;

        let session_token = hex::encode(token);

        self.logged_sessions.insert(
            session_token.clone(),
            Session::new(session_key.to_vec(), session_token, username.to_string()),
        );

        Ok(())
    }
}

impl<FS: FileStorage> OpaqueAuthentication<FS> {
    pub fn new(file_storage: FS, request_max_ttl: u64) -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<StandardCipherSuite>::new(&mut rng);

        Self {
            file_storage,
            server_setup,
            current_login_sessions: HashMap::new(),
            logged_sessions: HashMap::new(),
            request_max_ttl,
        }
    }
}

impl<FS: FileStorage> Authentication for OpaqueAuthentication<FS> {
    fn start_server_registration(
        &self,
        username: &str,
        client_registration_message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let client_registration_start_result =
            RegistrationRequest::deserialize(&client_registration_message)
                .map_err(|error| AuthenticationError::Deserialization(error.to_string()))?;

        let server_registration_start_result = ServerRegistration::<StandardCipherSuite>::start(
            &self.server_setup,
            client_registration_start_result,
            username.as_bytes(),
        )
        .map_err(|error| AuthenticationError::Registration(error.to_string()))?;

        Ok(server_registration_start_result
            .message
            .serialize()
            .to_vec())
    }

    fn finish_server_registration(
        &self,
        username: &str,
        client_registration_message: Vec<u8>,
    ) -> Result<()> {
        let client_registration_finish_result =
            RegistrationUpload::<StandardCipherSuite>::deserialize(&client_registration_message)
                .map_err(|error| AuthenticationError::Deserialization(error.to_string()))?;

        let password_file = ServerRegistration::finish(client_registration_finish_result);

        self.file_storage
            .save(username, password_file.serialize().to_vec())
            .map_err(|error| AuthenticationError::PasswordFileSave(error.to_string()))
    }

    fn start_server_login(
        &mut self,
        username: &str,
        client_login_message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let password_file = self
            .file_storage
            .retrieve(username)
            .map_err(|error| AuthenticationError::PasswordFileRetrieve(error.to_string()))?;

        let password_file = ServerRegistration::<StandardCipherSuite>::deserialize(&password_file)
            .map_err(|error| AuthenticationError::Deserialization(error.to_string()))?;

        let mut server_rng = OsRng;

        let client_login_start_result = CredentialRequest::deserialize(&client_login_message)
            .map_err(|error| AuthenticationError::Deserialization(error.to_string()))?;

        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &self.server_setup,
            Some(password_file),
            client_login_start_result,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|error| AuthenticationError::Login(error.to_string()))?;

        self.current_login_sessions
            .insert(username.to_string(), server_login_start_result.clone());

        Ok(server_login_start_result.message.serialize().to_vec())
    }

    fn finish_server_login(&mut self, username: &str, client_login_message: Vec<u8>) -> Result<()> {
        let Some(server_login_start_result) = self.current_login_sessions.remove(username) else {
            return Err(AuthenticationError::Login(
                USERNAME_DID_NOT_START_LOGIN_PHASE.to_string(),
            ));
        };

        let client_login_start_finish = CredentialFinalization::deserialize(&client_login_message)
            .map_err(|error| AuthenticationError::Login(error.to_string()))?;

        let server_login_finish_result = server_login_start_result
            .state
            .finish(client_login_start_finish, ServerLoginParameters::default())
            .map_err(|error| AuthenticationError::Login(error.to_string()))?;

        self.create_session(&server_login_finish_result.session_key, username)?;

        Ok(())
    }

    fn verify_bearer_token(&self, bearer_token: &str) -> bool {
        let Some(_) = self.logged_sessions.get(bearer_token) else {
            return false;
        };

        return true;
    }

    fn verify_signature(
        &self,
        bearer_token: &str,
        verb: &str,
        uri: &str,
        timestamp: &str,
        signature: &str,
    ) -> Result<bool> {
        let raw_expected_signature = format!("{}|{}|{}", verb, uri, timestamp);

        let Some(session) = self.logged_sessions.get(bearer_token) else {
            return Ok(false);
        };

        let mut mac = HmacSha512::new_from_slice(&session.session_key)
            .map_err(|error| AuthenticationError::Internal(error.to_string()))?;

        mac.update(raw_expected_signature.as_bytes());

        let expected_signature = &hex::encode(mac.finalize().into_bytes().to_vec());

        return Ok(signature == expected_signature);
    }

    fn verify_request_timestamp(&self, request_creation_timestamp: &str) -> Result<bool> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| AuthenticationError::Internal(error.to_string()))?
            .as_secs();

        let request_creation_timestamp: u64 =
            request_creation_timestamp
                .parse()
                .map_err(|error: std::num::ParseIntError| {
                    AuthenticationError::Internal(error.to_string())
                })?;

        return Ok(
            self.request_max_ttl >= current_timestamp.saturating_sub(request_creation_timestamp)
        );
    }
    
    fn get_username_from_session(&self, bearer_token: &str) -> Result<String> {

        let Some(session) = self.logged_sessions.get(bearer_token) else {
            return Err(AuthenticationError::Internal(SESSION_SHOULD_BE_PRESENT.to_string()));
        };

        Ok(session.username.clone())
    }
}
