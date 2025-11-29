#[derive(Debug)]
pub enum AuthenticationError {
}

impl std::fmt::Display for AuthenticationError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "todo")
    }
}

impl std::error::Error for AuthenticationError {}

pub type Result<T> = std::result::Result<T, AuthenticationError>;