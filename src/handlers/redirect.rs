use crate::AppParams;
use crate::{blake3_hash, blake3_hash_from_strings};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use url::form_urlencoded;
use urlencoding::encode;

pub async fn redirect_handler(
    req: &Request<Incoming>,
    config: &AppParams,
) -> Response<Full<Bytes>> {
    // Extract token from path
    let path = req.uri().path();
    let token = path.strip_prefix("/.chk/redirect/").unwrap_or("");
    if token.is_empty() {
        return response_403();
    }

    // Extract 'redirect_uri' query parameter
    let query = req.uri().query().unwrap_or_default();
    let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let encoded_uri = match params
        .iter()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v)
    {
        Some(uri) => encode(uri).to_string(),
        None => {
            return response_403();
        }
    };

    // Split and validate token parts (timestamp:hash)
    //
    let decoded_token = match urlencoding::decode(token) {
        Ok(t) => t,
        Err(_) => {
            return response_403();
        }
    };
    let parts: Vec<&str> = decoded_token.split(':').collect();
    if parts.len() != 2 {
        return response_403();
    }

    let timestamp = parts[0];
    let provided_hash = parts[1];

    let timestamp_secs: u64 = match timestamp.parse() {
        Ok(val) => val,
        Err(_) => {
            return response_403();
        }
    };

    let current_secs = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            return response_403();
        }
    };

    // Check token expiration
    if current_secs.saturating_sub(timestamp_secs) > config.redirect_token_max_age_seconds as u64 {
        return response_403();
    }

    // Reconstruct request signature
    let req_signature = match config.generate_request_signature(req) {
        Some(sig) => sig,
        None => return response_403(),
    };
    let signature_hash = blake3_hash(&req_signature);

    // Validate provided hash against expected hash using available security tokens
    let token_is_valid = config.security_tokens.iter().any(|token_secret| {
        let expected_hash = blake3_hash_from_strings(
            &[
                timestamp.to_string(),
                encoded_uri.clone(),
                signature_hash.clone(),
                token_secret.clone(),
            ],
            config,
        );
        expected_hash == provided_hash
    });

    if !token_is_valid {
        return response_403();
    }

    // Token validated successfully; decode the original URI
    let decoded_uri = match urlencoding::decode(encoded_uri.as_str()) {
        Ok(uri) => uri,
        Err(_) => {
            return response_403();
        }
    };

    // Generate and set security cookie (as per your existing logic)
    let cookie = config.generate_cookie(&req_signature);

    let mut response_builder = Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header("Location", decoded_uri.into_owned());

    if let Some(cookie) = cookie {
        response_builder = response_builder.header("Set-Cookie", cookie.to_string());
    }

    response_builder.body(Full::new(Bytes::new())).unwrap()
}

fn response_403() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
