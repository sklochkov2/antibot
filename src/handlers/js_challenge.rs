use crate::config::app_params::*;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use rand::RngCore;
use url::form_urlencoded;

pub async fn js_challenge_handler(
    req: &Request<Incoming>,
    _config: &AppParams,
) -> Response<Full<Bytes>> {
    // Parse GET parameters
    let query = req.uri().query().unwrap_or_default();
    let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    let token = params.iter().find(|(k, _)| k == "token").map(|(_, v)| v);
    let encoded_uri = params.iter().find(|(k, _)| k == "redir").map(|(_, v)| v);

    if token.is_none() || encoded_uri.is_none() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Missing parameters")))
            .unwrap();
    }

    let token = token.unwrap();
    let encoded_uri = encoded_uri.unwrap();

    // Generate AES256 key and IV
    let mut key_bytes = [0u8; 32];
    let mut iv_bytes = [0u8; 12]; // AES-GCM standard nonce length is 12 bytes
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);
    rand::rngs::OsRng.fill_bytes(&mut iv_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("valid key length");
    let nonce = Nonce::from_slice(&iv_bytes);

    // Encrypt token
    let encrypted_token_bytes = match cipher.encrypt(nonce, token.as_bytes()) {
        Ok(ct) => ct,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Encryption failed")))
                .unwrap()
        }
    };

    // Base64 encode values
    let encrypted_token_b64 = general_purpose::STANDARD.encode(&encrypted_token_bytes);
    let key_b64 = general_purpose::STANDARD.encode(&key_bytes);
    let iv_b64 = general_purpose::STANDARD.encode(&iv_bytes);

    // Template substitution
    let challenge_page = _config
        .js_challenge_template
        .replace("{{encrypted_token}}", &encrypted_token_b64)
        .replace("{{key}}", &key_b64)
        .replace("{{iv}}", &iv_b64)
        .replace("{{encoded_uri}}", encoded_uri);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(challenge_page)))
        .unwrap()
}
