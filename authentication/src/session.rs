#[derive(Debug, Default)]
pub struct Session {
    pub session_key: Vec<u8>,
    pub session_token: String,
}

impl Session {
    pub fn new(session_key: Vec<u8>, session_token: String) -> Self {
        Self {
            session_key,
            session_token,
        }
    }
}