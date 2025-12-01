use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};

const AUTHORIZATION: &'static str = "Authorization";
const X_TIMESTAMP: &'static str = "X-Timestamp";
const X_SIGNATURE: &'static str = "X-Signature";
const X_USERNAME: &'static str = "X-Username";
const BEARER: &'static str = "Bearer ";
const HOST: &'static str = "Host";

pub struct VaultRequest {
    pub bearer_token: String,
    pub host: String,
    pub timestamp: String,
    pub signature: String,
}

#[derive(Debug)]
pub enum RequestError {
    Missing,
}

pub struct OpaqueRequest {
    pub username: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for VaultRequest {
    type Error = RequestError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {

        let bearer_token = match request.headers().get_one(AUTHORIZATION) {
            Some(value) if value.starts_with(BEARER) => &value[BEARER.len()..],
            _ => return Outcome::Error((Status::BadRequest, RequestError::Missing))
        };        

        let Some(host) = request.headers().get_one(HOST) else {
            return Outcome::Error((Status::BadRequest, RequestError::Missing));
        };

        let Some(signature) = request.headers().get_one(X_SIGNATURE) else {
            return Outcome::Error((Status::BadRequest, RequestError::Missing));
        };

        let Some(timestamp) = request.headers().get_one(X_TIMESTAMP) else {
            return Outcome::Error((Status::BadRequest, RequestError::Missing));
        };

        Outcome::Success(VaultRequest {
            bearer_token: bearer_token.to_string(),
            host: host.to_string(),
            timestamp: timestamp.to_string(),
            signature: signature.to_string(),
        })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OpaqueRequest {
    type Error = RequestError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(username) = request.headers().get_one(X_USERNAME) else {
            return Outcome::Error((Status::BadRequest, RequestError::Missing));
        };

        Outcome::Success(OpaqueRequest {
            username: username.to_string(),
        })
    }
}
