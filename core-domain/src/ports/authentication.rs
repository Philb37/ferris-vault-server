pub trait Authentication {

    fn start_server_registration(&self, client_registration_message: Vec<u8>) -> Vec<u8>;
    fn finish_server_registration(&self, client_registration_message: Vec<u8>) -> Vec<u8>;
    fn start_server_login(&self, client_login_message: Vec<u8>) -> Vec<u8>;
    fn finish_server_login(&self, client_login_message: Vec<u8>) -> Vec<u8>;
    fn verify_signature(&self);
}