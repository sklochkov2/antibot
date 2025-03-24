use crate::config::app_params::AppParams;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::header::COOKIE;
use hyper::{Request, Response, StatusCode};
use urlencoding::encode;

pub async fn verify_handler(req: &Request<Incoming>, config: &AppParams) -> Response<Full<Bytes>> {
    // Generate request signature based on configured headers
    let req_signature = match config.generate_request_signature(&req) {
        Some(sig) => sig,
        None => return unauthorized_response(&req, config), // Missing headers; unauthorized
    };

    // Compute the cookie name based on signature hash
    let signature_hash = crate::blake3_hash(&req_signature);
    let cookie_name = config.cookie_name_template.replace("{}", &signature_hash);

    // Extract cookie from request headers
    let cookie_header = req.headers().get(COOKIE).and_then(|v| v.to_str().ok());

    let cookie_value = cookie_header.and_then(|cookies| {
        cookies.split(';').find_map(|cookie| {
            let cookie = cookie.trim();
            cookie.strip_prefix(&format!("{}=", cookie_name))
        })
    });

    // Determine if grace period is required based on HTTP method
    let grace_required = match *req.method() {
        hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS => false,
        _ => true, // POST, PUT, DELETE, etc., require grace period
    };

    // Validate the cookie (including optional grace period)
    if let Some(cookie_value) = cookie_value {
        if config.validate_cookie(cookie_value, &req_signature, grace_required) {
            // Cookie valid; authorized
            return Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap();
        }
    }

    // Cookie invalid or missing; unauthorized
    unauthorized_response(&req, config)
}

fn unauthorized_response(req: &Request<Incoming>, config: &AppParams) -> Response<Full<Bytes>> {
    let current_timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
    {
        Ok(dur) => dur.as_secs().to_string(),
        Err(_) => "0".to_string(),
    };

    // Generate redirect token
    let original_uri = match req.headers().get("x-request-uri") {
        Some(h) => h.to_str().unwrap(),
        None => "/",
    };
    let encoded_uri = encode(&original_uri);
    let req_signature = config.generate_request_signature(req).unwrap_or_default();
    let signature_hash = crate::blake3_hash(&req_signature);
    let redirect_token_hash = crate::blake3_hash_from_strings(
        &[
            current_timestamp.clone(),
            encoded_uri.to_string(),
            signature_hash,
            config.security_tokens.first().cloned().unwrap_or_default(),
        ],
        config,
    );

    let redirect_token = format!("{}:{}", current_timestamp, redirect_token_hash);

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("X-Redir-Path", redirect_token)
        .header("X-Encoded-Uri", original_uri)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
