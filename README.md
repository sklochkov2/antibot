# Antibot Application

A high-performance HTTP-based antibot verification server implemented in Rust using **Tokio** and **Hyper**. The application integrates seamlessly with **Nginx's auth_request** mechanism, ensuring robust bot detection and traffic protection while remaining fully agnostic of the protected website's logic.

---

## 📌 Application Overview

The antibot server employs a multi-stage verification strategy to differentiate genuine browser clients from automated bots or scripts. It consists of several endpoints that:

- Generate and verify cryptographically secure tokens.
- Verify client-side JavaScript execution capabilities.
- Implement secure cookie-based client verification.
- Ensure robust replay and tampering protection through timestamp and signature checks.

### Verification Flow:

```
Client Request
    │
Nginx auth_request → /.chk/verify
    ├── ✅ Cookie Valid → allow request (200)
    └── ❌ Cookie Missing/Invalid → return redirect token (401)
        │
Client redirected to → /.chk/js/ (JavaScript challenge)
        │
Client JS challenge completed → /.chk/redirect/{token}?redirect_uri={encoded_uri}
        │
Token verified → Set secure cookie, redirect back to original URL (307)
```

---

## 📂 Source Code Structure

```
src/
├── config/
│   ├── app_params.rs       # Configuration structure definition
│   ├── config.rs           # TOML configuration file loading logic
│   └── mod.rs              # Configuration module exports
│
├── handlers/               # HTTP request handlers
│   ├── js_challenge.rs     # JavaScript challenge handler (/.chk/js/)
│   ├── redirect.rs         # Redirect token verification handler (/.chk/redirect/)
│   ├── verify.rs           # Cookie validation handler (/.chk/verify)
│   └── mod.rs              # Handler module exports
│
├── templates/
│   └── js_challenge.html   # JavaScript challenge HTML template
│
├── utils/
│   └── utils.rs            # Utility functions (hashing, cookie handling)
│
├── lib.rs                  # Library root (exports common modules)
├── main.rs                 # Application entry point (server initialization)
└── config                  # Example configuration
    └── example.toml        # Example configuration parameters
```

---

## ⚙️ Configuration Parameters

The application configuration is stored in a TOML file. Its path can be provided in the `CONFOG_PATH` environment variable; `./config.toml` will be used by default.
Parameters include:

| Parameter                          | Description                                           |
| ---------------------------------- | ----------------------------------------------------- |
| **listen**                         | Server socket configuration (TCP or UNIX socket).     |
| **security_tokens**                | Array of secret keys for cookie/token hashing.        |
| **redirect_target**                | Default redirect URL after successful verification.   |
| **signature_headers**              | Ordered list of headers used for request signature.   |
| **signature_delimiter**            | Delimiter for request signature concatenation.        |
| **cookie_name_template**           | Template for cookie name (must contain "{}").         |
| **cookie_max_age_seconds**         | Cookie expiration lifetime (seconds).                 |
| **redirect_token_max_age_seconds** | Redirect token validity lifetime (seconds).           |
| **js_challenge_template_path**     | Path to the Javascript challenge template             |

### Example Configuration (`example.toml`):

```toml
[listen]
type = "Tcp"
addr = "127.0.0.1:8080"

security_tokens = ["current_secret", "old_secret"]
redirect_target = "/"
signature_headers = [
    "x-request-scheme",
    "x-request-ip",
    "x-request-host",
    "x-request-user-agent",
    "x-request-ciphers",
    "x-request-curves",
    "x-request-ssl-protocol",
    "x-request-accept-encoding",
    "x-request-accept-language",
    "x-request-upgrade-insecure-requests",
]
signature_delimiter = "|"
cookie_name_template = "antibot_cookie_{}"
cookie_max_age_seconds = 1800  # 30 minutes
redirect_token_max_age_seconds = 120  # 2 minutes
js_challenge_template_path = "src/templates/js_challenge.html"
```

---

## 🚀 How to Build and Run

### 1\. Prerequisites:

- Rust 1.75+ (Stable)
- Cargo package manager

### 2\. Build Application:

```bash
cargo build --release
```

### 3\. Run Application with Configuration:

```bash
CONFIG_PATH="config/example.toml" ./target/release/antibot
```

### 4\. Nginx Integration Example:

Configure Nginx to use the antibot via `auth_request`:

```nginx
server {
    listen 443 ssl;

    location / {
        auth_request /.chk/verify;

        proxy_set_header X-Request-Scheme $scheme;
        proxy_set_header X-Request-IP $remote_addr;
        proxy_set_header X-Request-Host $http_host;
        proxy_set_header X-Request-User-Agent "$http_user_agent";
        proxy_set_header X-Request-Ciphers "$ssl_ciphers";
        proxy_set_header X-Request-Curves "$ssl_curves";
        proxy_set_header X-Request-SSL-Protocol "$ssl_protocol";
        proxy_set_header X-Request-Accept-Encoding "$http_accept_encoding";
        proxy_set_header X-Request-Accept-Language "$http_accept_language";
        proxy_set_header X-Request-Upgrade-Insecure-Requests "$http_x_upgrade_insecure_requests";
        proxy_set_header X-Request-Allow $search_engine;

        proxy_pass http://your_backend;
    }

    location = /.chk/verify {
        internal;
        proxy_pass http://127.0.0.1:8080/.chk/verify;
        proxy_pass_request_body off;

        proxy_intercept_errors on;
        error_page 401 = @antibot_js;
    }

    location @antibot_js {
        set $redir $upstream_http_x_redir_path;
        set $encoded_uri $upstream_http_x_encoded_uri;
        return 302 /.chk/js/?token=$redir&redir=$encoded_uri;
    }

    location /.chk/js/ {
        proxy_pass http://127.0.0.1:8080/.chk/js/;
    }

    location /.chk/redirect/ {
        proxy_pass http://127.0.0.1:8080/.chk/redirect/;
    }
}
```

The `X-Request-Allow` can be used to exclude some requests from the verification process. If it is set to 1, the verification succeeds without any checks.

---

## 📌 Performance and Scalability

The antibot application demonstrates excellent scalability across CPU cores, efficiently utilizing modern multi-core CPUs with Tokio runtime. It is highly optimized for low-latency, high-RPS scenarios.

Example performance (Ryzen 5950X, single CCD):

- **1 Thread:** ~78K RPS
- **8 Threads (Physical Cores):** ~600K RPS
- **16 Threads (SMT):** ~844K RPS

For best scalability:

- Run with Tokio worker threads set to match physical core count.
- Pin antibot and load-testing tools to separate CPU cores or CCDs to minimize resource contention during benchmarking.

---

## 🛡️ Security Features

- Secure cookie and token generation using Blake3 hashing.
- Timestamp-based expiration and replay protection.
- Secure client-side JavaScript verification challenge (AES-based).
- Robust and tamper-proof redirect/token verification mechanisms.

---

## 📖 License

This software is distributed under the **MIT License**.  

---

## 🚩 Conclusion

This antibot implementation provides a powerful, secure, and highly scalable solution for HTTP request verification, designed to integrate seamlessly with existing infrastructure (e.g., Nginx). Its robust multi-stage approach provides effective protection against automated bots and malicious traffic.
