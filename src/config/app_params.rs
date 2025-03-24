use base64::{engine::general_purpose, Engine};
use blake3;
use cookie::{time::Duration, Cookie, CookieBuilder};
use hyper::body::Incoming;
use hyper::Request;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use urlencoding::encode;

use once_cell::sync::Lazy;
use std::fs;

pub static JS_CHALLENGE_TEMPLATE: Lazy<String> = Lazy::new(|| {
    fs::read_to_string("src/templates/js_challenge.html")
        .expect("Failed to read js_challenge.html template")
});

#[derive(Deserialize, Debug, Clone)]
pub struct AppParams {
    pub security_tokens: Vec<String>,
    pub signature_headers: Vec<String>,
    pub signature_delimiter: String,
    pub cookie_name_template: String,
    pub cookie_max_age_seconds: i64,
    pub redirect_token_max_age_seconds: i64,
    pub js_challenge_template_path: String,

    #[serde(skip)]
    pub js_challenge_template: String,
}

impl AppParams {
    pub fn generate_request_signature(&self, req: &Request<Incoming>) -> Option<String> {
        let headers_list = &self.signature_headers;
        let delimiter = &self.signature_delimiter;

        let mut header_values = Vec::with_capacity(headers_list.len());

        for header_name in headers_list {
            //let value = req.headers().get(header_name)?.to_str().ok()?;
            let value = match req.headers().get(header_name) {
                Some(h) => h.to_str().ok()?,
                None => "",
            };
            header_values.push(value);
        }

        Some(header_values.join(delimiter))
    }

    pub fn generate_cookie(&self, req_signature: &str) -> Option<CookieBuilder<'static>> {
        let signature_hash = blake3_hash(req_signature);
        let cookie_name = self.cookie_name_template.replace("{}", &signature_hash);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs()
            .to_string();
        let current_token = self.security_tokens.first()?;
        let security_token = blake3_hash_from_strings(
            &[timestamp.clone(), signature_hash, current_token.clone()],
            self,
        );

        let cookie_content = format!("{}:{}", timestamp, security_token);
        let cookie_value = general_purpose::STANDARD.encode(cookie_content);

        Some(
            Cookie::build((cookie_name, cookie_value))
                .max_age(Duration::seconds(self.cookie_max_age_seconds * 2))
                .http_only(true)
                .path("/"),
        )
        //.finish())
    }

    pub fn validate_cookie(
        &self,
        cookie_value: &str,
        req_signature: &str,
        grace_required: bool,
    ) -> bool {
        let decoded = match general_purpose::STANDARD.decode(cookie_value) {
            Ok(val) => val,
            Err(_) => return false,
        };

        let content = match String::from_utf8(decoded) {
            Ok(val) => val,
            Err(_) => return false,
        };

        let parts: Vec<&str> = content.split(':').collect();
        if parts.len() != 2 {
            return false;
        }

        let timestamp = parts[0];
        let provided_token = parts[1];

        let timestamp_secs: u64 = match timestamp.parse() {
            Ok(val) => val,
            Err(_) => return false,
        };

        let current_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return false,
        };

        if !grace_required
            && current_secs.saturating_sub(timestamp_secs) > self.cookie_max_age_seconds as u64
        {
            return false; // Cookie expired
        }

        let signature_hash = blake3_hash(req_signature);

        self.security_tokens.iter().any(|token| {
            let expected_token = blake3_hash_from_strings(
                &[timestamp.to_string(), signature_hash.clone(), token.clone()],
                self,
            );
            expected_token == provided_token
        })
    }

    pub fn validate_redirect_token(
        &self,
        redirect_token: &str,
        redirect_url: &str,
        req_signature: &str,
    ) -> bool {
        let parts: Vec<&str> = redirect_token.split(':').collect();
        if parts.len() != 2 {
            return false;
        }

        let timestamp = parts[0];
        let provided_hash = parts[1];

        let timestamp_secs: u64 = match timestamp.parse() {
            Ok(val) => val,
            Err(_) => return false,
        };

        let current_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return false,
        };

        // Separate shorter expiration from cookie lifetime
        if current_secs.saturating_sub(timestamp_secs) > self.redirect_token_max_age_seconds as u64
        {
            return false; // Redirect token expired
        }

        let encoded_url = encode(redirect_url);
        let signature_hash = blake3_hash(req_signature);

        // Check provided hash against all available tokens
        self.security_tokens.iter().any(|token| {
            let expected_hash = blake3_hash_from_strings(
                &[
                    timestamp.to_string(),
                    encoded_url.to_string(),
                    signature_hash.clone(),
                    token.clone(),
                ],
                self,
            );

            expected_hash == provided_hash
        })
    }
}

pub fn blake3_hash(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

pub fn blake3_hash_from_strings(inputs: &[String], config: &AppParams) -> String {
    let mut hasher = blake3::Hasher::new();
    let delimiter_bytes = config.signature_delimiter.as_bytes();

    for (i, input) in inputs.iter().enumerate() {
        if i > 0 {
            hasher.update(delimiter_bytes);
        }
        hasher.update(input.as_bytes());
    }

    hasher.finalize().to_hex().to_string()
}
