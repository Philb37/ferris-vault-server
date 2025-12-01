#[derive(Debug, Default)]
pub struct Session {
    pub session_key: Vec<u8>,
    #[allow(dead_code)]
    pub session_token: String,
    pub username: String
}

impl Session {
    pub fn new(session_key: Vec<u8>, session_token: String, username: String) -> Self {
        Self {
            session_key,
            session_token,
            username
        }
    }
}