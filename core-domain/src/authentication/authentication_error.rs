#[derive(Debug)]
pub enum AuthenticationError {
    Deserialization(String),
    Registration(String),
    Login(String),
    PasswordFileSave(String),
    PasswordFileRetrieve(String),
    CreatingSession(String),
    Internal(String)
}

impl std::fmt::Display for AuthenticationError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            AuthenticationError::Deserialization(message) => write!(formatter, "Error during client message deserialization: {}", message),
            AuthenticationError::Registration(message) => write!(formatter, "Error during registration phase: {}", message),
            AuthenticationError::Login(message) => write!(formatter, "Error during login phase: {}", message),
            AuthenticationError::PasswordFileSave(message) => write!(formatter, "Error while saving password file: {}", message),
            AuthenticationError::PasswordFileRetrieve(message) => write!(formatter, "Error while retrieving password file: {}", message),
            AuthenticationError::CreatingSession(message) => write!(formatter, "Error while creating session: {}", message),
            AuthenticationError::Internal(message) => write!(formatter, "Internal error: {}", message)
        }
    }
}

impl std::error::Error for AuthenticationError {}

pub type Result<T> = std::result::Result<T, AuthenticationError>;