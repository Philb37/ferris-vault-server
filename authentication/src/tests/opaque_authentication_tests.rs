use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use core_domain::{
    file_storage::file_storage_error::Result,
    ports::{authentication::Authentication, file_storage::FileStorage},
};
use hkdf::Hkdf;
use hmac::Mac;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    ServerRegistration, ServerSetup,
    rand::{rngs::OsRng, seq::SliceRandom},
};
use sha2::Sha512;

use crate::opaque_authentication::{HmacSha512, OpaqueAuthentication, StandardCipherSuite};

const TESTS_FILE_PATH: &'static str = "tests_files/";

#[test]
fn should_start_server_registration() {
    // A-rrange

    let request_max_ttl = 5;

    let username = "username";
    let password = "password";

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let mut client_rng = OsRng;

    let client_registration_start_result =
        ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();

    let opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    // A-ct

    let result = opaque_authentication.start_server_registration(
        username,
        client_registration_start_result
            .message
            .serialize()
            .to_vec(),
    );

    // A-ssert

    assert!(result.is_ok());

    match result {
        Ok(result) => {
            let response = RegistrationResponse::<StandardCipherSuite>::deserialize(&result);
            assert!(response.is_ok());
        }
        Err(_) => panic!("Result should be OK."),
    }

    cleanup(&test_path);
}

#[test]
fn should_finish_server_registration() {
    // A-rrange

    let request_max_ttl = 5;

    let username = "username";
    let password = "password";

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let mut rng = OsRng;
    let server_setup = ServerSetup::<StandardCipherSuite>::new(&mut rng);

    let mut client_rng = OsRng;

    let client_registration_start_result =
        ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();

    let server_registration_start_result = ServerRegistration::<StandardCipherSuite>::start(
        &server_setup,
        client_registration_start_result.message,
        username.as_bytes(),
    )
    .unwrap();

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            server_registration_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    let opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    // A-ct

    let result = opaque_authentication.finish_server_registration(
        username,
        client_finish_registration_result
            .message
            .serialize()
            .to_vec(),
    );

    // A-ssert

    assert!(result.is_ok());

    cleanup(&test_path);
}

#[test]
fn should_start_server_login() {
    // A-rrange

    let request_max_ttl = 5;

    let username = "username";
    let password = "password";

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let mut client_rng = OsRng;

    let mut opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    let client_registration_start_result =
        ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();

    let server_registration_start_result = opaque_authentication
        .start_server_registration(
            username,
            client_registration_start_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&server_registration_start_result).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_registration(
            username,
            client_finish_registration_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_login_start_result =
        ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

    // A-ct

    let result = opaque_authentication.start_server_login(
        username,
        client_login_start_result.message.serialize().to_vec(),
    );

    // A-ssert

    assert!(result.is_ok());

    match result {
        Ok(result) => {
            let response = CredentialResponse::<StandardCipherSuite>::deserialize(&result);
            assert!(response.is_ok());
        }
        Err(_) => panic!("Result should be OK."),
    }

    cleanup(&test_path);
}

#[test]
fn should_finish_server_login() {
    // A-rrange

    let request_max_ttl = 5;

    let username = "username";
    let password = "password";

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let mut client_rng = OsRng;

    let mut opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    let client_registration_start_result =
        ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();

    let server_registration_start_result = opaque_authentication
        .start_server_registration(
            username,
            client_registration_start_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&server_registration_start_result).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_registration(
            username,
            client_finish_registration_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_login_start_result =
        ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

    let server_login_start_result = opaque_authentication
        .start_server_login(
            username,
            client_login_start_result.message.serialize().to_vec(),
        )
        .unwrap();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            CredentialResponse::<StandardCipherSuite>::deserialize(&server_login_start_result)
                .unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    // A-ct

    let result = opaque_authentication.finish_server_login(
        username,
        client_login_finish_result.message.serialize().to_vec(),
    );

    // A-ssert

    assert!(result.is_ok());

    cleanup(&test_path);
}

#[test]
fn should_verify_bearer_token() {
    // A-rrange

    let request_max_ttl = 5;

    let username = "username";
    let password = "password";

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let mut client_rng = OsRng;

    let mut opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    let client_registration_start_result =
        ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();

    let server_registration_start_result = opaque_authentication
        .start_server_registration(
            username,
            client_registration_start_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&server_registration_start_result).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_registration(
            username,
            client_finish_registration_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_login_start_result =
        ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

    let server_login_start_result = opaque_authentication
        .start_server_login(
            username,
            client_login_start_result.message.serialize().to_vec(),
        )
        .unwrap();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            CredentialResponse::<StandardCipherSuite>::deserialize(&server_login_start_result)
                .unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_login(
            username,
            client_login_finish_result.message.serialize().to_vec(),
        )
        .unwrap();

    let client_session_token = create_session(&client_login_finish_result.session_key);

    // A-ct

    let result = opaque_authentication.verify_bearer_token(&client_session_token);

    // A-ssert

    assert!(result);

    cleanup(&test_path);
}

#[test]
fn should_verify_signature() {
    // A-rrange

    let request_max_ttl = 5;

    let username = "username";
    let password = "password";

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let mut client_rng = OsRng;

    let mut opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    let client_registration_start_result =
        ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();

    let server_registration_start_result = opaque_authentication
        .start_server_registration(
            username,
            client_registration_start_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&server_registration_start_result).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_registration(
            username,
            client_finish_registration_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_login_start_result =
        ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

    let server_login_start_result = opaque_authentication
        .start_server_login(
            username,
            client_login_start_result.message.serialize().to_vec(),
        )
        .unwrap();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            CredentialResponse::<StandardCipherSuite>::deserialize(&server_login_start_result)
                .unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_login(
            username,
            client_login_finish_result.message.serialize().to_vec(),
        )
        .unwrap();

    let verb = "GET";
    let uri = "http://localhost";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let client_session_token = create_session(&client_login_finish_result.session_key);
    let signature = create_client_signature(
        &format!("{}|{}|{}", verb, uri, timestamp),
        &client_login_finish_result.session_key,
    );

    // A-ct

    let result = opaque_authentication.verify_signature(
        &client_session_token,
        verb,
        uri,
        &timestamp,
        &signature,
    );

    // A-ssert

    assert!(result.is_ok());
    assert!(result.unwrap());

    cleanup(&test_path);
}

#[test]
fn should_verify_request_timestamp() {
    // A-rrange

    let request_max_ttl = 5;

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    // A-ct

    let result = opaque_authentication.verify_request_timestamp(&current_timestamp);

    // A-ssert

    assert!(result.is_ok());
    assert!(result.unwrap());

    cleanup(test_path);
}

#[test]
fn should_not_verify_request_timestamp() {
    // A-rrange

    let request_max_ttl = 5;

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    let ten_seconds = Duration::new(10, 0);

    let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let wrong_timestamp = current_timestamp - ten_seconds;

    let wrong_timestamp = wrong_timestamp.as_secs().to_string();

    // A-ct

    let result = opaque_authentication.verify_request_timestamp(&wrong_timestamp);

    // A-ssert

    assert!(result.is_ok());
    assert!(!result.unwrap());

    cleanup(test_path);
}

#[test]
fn should_give_username() {
    // A-rrange

    let request_max_ttl = 5;

    let username = "username";
    let password = "password";

    let mock_file_storage = generate_mock_file_storage();

    let test_path = &mock_file_storage.path.clone();

    let mut client_rng = OsRng;

    let mut opaque_authentication = OpaqueAuthentication::new(mock_file_storage, request_max_ttl);

    let client_registration_start_result =
        ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();

    let server_registration_start_result = opaque_authentication
        .start_server_registration(
            username,
            client_registration_start_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&server_registration_start_result).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_registration(
            username,
            client_finish_registration_result
                .message
                .serialize()
                .to_vec(),
        )
        .unwrap();

    let client_login_start_result =
        ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

    let server_login_start_result = opaque_authentication
        .start_server_login(
            username,
            client_login_start_result.message.serialize().to_vec(),
        )
        .unwrap();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            CredentialResponse::<StandardCipherSuite>::deserialize(&server_login_start_result)
                .unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    opaque_authentication
        .finish_server_login(
            username,
            client_login_finish_result.message.serialize().to_vec(),
        )
        .unwrap();

    let client_session_token = create_session(&client_login_finish_result.session_key);

    // A-ct

    let result = opaque_authentication.get_username_from_session(&client_session_token);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), username);

    cleanup(&test_path);
}

pub struct MockFileStorage {
    pub path: String,
}

impl FileStorage for MockFileStorage {
    fn new(path: String) -> Self {
        Self { path }
    }

    fn retrieve(&self, file_name: &str) -> Result<Vec<u8>> {
        let file_path = Path::new(&self.path).join(file_name);

        dbg!(&file_path);

        let file = File::open(&file_path).unwrap();

        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer).unwrap();

        Ok(buffer)
    }

    fn save(&self, file_name: &str, vault: Vec<u8>) -> Result<()> {
        if !Path::new(&self.path).exists() {
            fs::create_dir_all(&self.path).unwrap();
        }

        let file_path = Path::new(&self.path).join(file_name);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&file_path)
            .unwrap();

        file.write_all(&vault).unwrap();

        Ok(())
    }
}

fn create_session(session_key: &[u8]) -> String {
    let hkdf = Hkdf::<Sha512>::from_prk(session_key).unwrap();

    let mut token = vec![0u8; 64];

    hkdf.expand(b"opaque-session-token", &mut token).unwrap();

    hex::encode(token)
}

fn create_client_signature(raw_signature: &str, session_key: &[u8]) -> String {
    let mut mac = HmacSha512::new_from_slice(&session_key).unwrap();

    mac.update(raw_signature.as_bytes());

    hex::encode(mac.finalize().into_bytes().to_vec())
}

fn cleanup(path: &str) {

    if Path::new(path).exists() {
        fs::remove_dir_all(path).unwrap();
    }

    let parent_path = Path::new(TESTS_FILE_PATH);

    if parent_path.exists() && parent_path.read_dir().unwrap().next().is_none() {
        fs::remove_dir_all(TESTS_FILE_PATH).unwrap();
    }
}

fn generate_mock_file_storage() -> MockFileStorage {

    let mut rng = OsRng;

    let range: Vec<i32> = (1..100000).collect();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();

    let id = range.choose(&mut rng).unwrap();

    MockFileStorage::new(format!("{}/{}-{}", TESTS_FILE_PATH, id, timestamp))
}