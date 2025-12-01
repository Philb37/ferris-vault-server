use std::{env, process::exit, sync::Mutex};

use authentication::opaque_authentication::OpaqueAuthentication;
use core_domain::{domain::server_domain::{Domain, ServerDomain}, ports::file_storage::FileStorage};
use file_storage::file_storage::StandardFileStorage;
use rocket::{http::Status, State};
use vault_store::directory_vault_store::DirectoryVaultStore;

use crate::{config::AppConfig, requests::{OpaqueRequest, VaultRequest}};

#[macro_use]
extern crate rocket;

mod requests;
mod config;

const POST: &'static str = "POST";
const GET: &'static str = "GET";

#[post("/opaque/registration/start", format = "application/octet-stream", data = "<client_message>")]
fn opaque_registration_start(client_message: &[u8], opaque_request: OpaqueRequest, server_domain: &State<Mutex<ServerDomain<DirectoryVaultStore<StandardFileStorage>, OpaqueAuthentication<StandardFileStorage>>>>) -> (Status, Vec<u8>) {

    match server_domain.lock().unwrap().start_server_registration(&opaque_request.username, client_message.to_vec()) {
        Ok(server_registration_start_result) => (Status::Ok, server_registration_start_result),
        Err(error) => (Status::InternalServerError, error.to_string().into_bytes())
    }
}

#[post("/opaque/registration/finish", format = "application/octet-stream", data = "<client_message>")]
fn opaque_registration_finish(client_message: &[u8], opaque_request: OpaqueRequest, server_domain: &State<Mutex<ServerDomain<DirectoryVaultStore<StandardFileStorage>, OpaqueAuthentication<StandardFileStorage>>>>) -> (Status, Vec<u8>) {

    match server_domain.lock().unwrap().finish_server_registration(&opaque_request.username, client_message.to_vec()) {
        Ok(_) => (Status::Ok, vec![]),
        Err(error) => (Status::InternalServerError, error.to_string().into_bytes())
    }
}

#[post("/opaque/login/start", format = "application/octet-stream", data = "<client_message>")]
fn opaque_login_start(client_message: &[u8], opaque_request: OpaqueRequest, server_domain: &State<Mutex<ServerDomain<DirectoryVaultStore<StandardFileStorage>, OpaqueAuthentication<StandardFileStorage>>>>) -> (Status, Vec<u8>) {

    match server_domain.lock().unwrap().start_server_login(&opaque_request.username, client_message.to_vec()) {
        Ok(server_login_start_result) => (Status::Ok, server_login_start_result),
        Err(error) => (Status::InternalServerError, error.to_string().into_bytes())
    }
}

#[post("/opaque/login/finish", format = "application/octet-stream", data = "<client_message>")]
fn opaque_login_finish(client_message: &[u8], opaque_request: OpaqueRequest, server_domain: &State<Mutex<ServerDomain<DirectoryVaultStore<StandardFileStorage>, OpaqueAuthentication<StandardFileStorage>>>>) -> (Status, Vec<u8>) {

    match server_domain.lock().unwrap().finish_server_login(&opaque_request.username, client_message.to_vec()) {
        Ok(_) => (Status::Ok, vec![]),
        Err(error) => (Status::InternalServerError, error.to_string().into_bytes())
    }
}

#[post("/vault", format = "application/octet-stream", data = "<vault>")]
fn save_vault(vault: &[u8], vault_request: VaultRequest, server_domain: &State<Mutex<ServerDomain<DirectoryVaultStore<StandardFileStorage>, OpaqueAuthentication<StandardFileStorage>>>>) -> (Status, Vec<u8>) {

    let uri = format!("{}{}", &vault_request.host, "/vault");

    match server_domain.lock().unwrap().save_vault(&vault_request.bearer_token, POST, &uri, &vault_request.timestamp, &vault_request.signature, vault.to_vec()) {
        Ok(_) => (Status::Ok, vec![]),
        Err(error) => (Status::InternalServerError, error.to_string().into_bytes())
    }
}

#[get("/vault")]
fn retrieve_vault(vault_request: VaultRequest, server_domain: &State<Mutex<ServerDomain<DirectoryVaultStore<StandardFileStorage>, OpaqueAuthentication<StandardFileStorage>>>>) -> (Status, Vec<u8>) {

    let uri = format!("{}{}", &vault_request.host, "/vault");

    match server_domain.lock().unwrap().get_vault(&vault_request.bearer_token, GET, &uri, &vault_request.timestamp, &vault_request.signature) {
        Ok(vault) => (Status::Ok, vault),
        Err(error) => (Status::InternalServerError, error.to_string().into_bytes())
    }
}

#[launch]
fn rocket() -> _ {
    let args: Vec<String> = env::args().collect();

    let app_config = match AppConfig::build(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Error creating config: {error}");
            exit(1);
        }
    };

    let vault_file_storage = StandardFileStorage::new(app_config.vault_store.path);
    let authentication_file_storage = StandardFileStorage::new(app_config.password_file.path);

    let vault_store = DirectoryVaultStore::new(vault_file_storage);

    let authentication = OpaqueAuthentication::new(
        authentication_file_storage,
        app_config.server.request_max_ttl,
    );
    let server_domain = ServerDomain::new(vault_store, authentication);

    rocket::build()
        .manage(Mutex::new(server_domain))
        .mount("/", routes![opaque_registration_start])
        .mount("/", routes![opaque_registration_finish])
        .mount("/", routes![opaque_login_start])
        .mount("/", routes![opaque_login_finish])
        .mount("/", routes![retrieve_vault])
        .mount("/", routes![save_vault])
}
