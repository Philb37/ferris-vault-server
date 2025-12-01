#[derive(Debug)]
pub enum ServerDomainError {
    Forbidden(String),
    Internal(String)
}

impl std::fmt::Display for ServerDomainError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            ServerDomainError::Forbidden(message) => write!(formatter, "Error during registration phase: {}", message),
            ServerDomainError::Internal(message) => write!(formatter, "Error during login phase: {}", message),
        }
    }
}

impl std::error::Error for ServerDomainError {}

pub type Result<T> = std::result::Result<T, ServerDomainError>;