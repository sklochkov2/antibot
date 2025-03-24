use anyhow::Result;
use hyper::server::conn::http1;
use hyper::{service::service_fn, Request, StatusCode};

use antibot::config::app_params::*;
use antibot::config::config::*;
use antibot::handlers::js_challenge::*;
use antibot::handlers::redirect::*;
use antibot::handlers::verify::*;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::Response;
use hyper_util::rt::TokioIo;
use std::env;
use std::net::SocketAddr;
use std::os::unix::net::UnixListener as StdUnixListener;
use tokio::net::{TcpListener, UnixListener};

async fn handle_request(
    req: Request<Incoming>,
    config: &AppParams,
) -> Result<Response<Full<Bytes>>> {
    match req.uri().path() {
        "/ping" => Ok(Response::new(Full::new(Bytes::from_static(b"pong")))),

        "/.chk/verify" => Ok(verify_handler(&req, config).await),

        path if path.starts_with("/.chk/redirect/") => Ok(redirect_handler(&req, config).await),

        "/.chk/js/" => Ok(js_challenge_handler(&req, config).await),

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))?),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let config_path = match env::var("CONFIG_PATH") {
        Ok(p) => p,
        Err(_) => "./config.toml".to_string(),
    };

    let config: Config = Config::from_file(&config_path);

    match config.listen {
        Listen::Tcp { addr } => {
            let addr: SocketAddr = addr.parse()?;
            let listener = TcpListener::bind(addr).await?;
            println!("Listening on TCP {}", addr);

            loop {
                let (stream, _) = listener.accept().await?;
                let io = TokioIo::new(stream);
                let app_config = config.app.clone();
                tokio::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(|req| handle_request(req, &app_config)))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        }

        Listen::Unix { path } => {
            let _ = std::fs::remove_file(&path);
            let std_listener = StdUnixListener::bind(&path)?;
            let listener = UnixListener::from_std(std_listener)?;
            println!("Listening on Unix socket {}", path);

            loop {
                let (stream, _) = listener.accept().await?;
                let io = TokioIo::new(stream);
                let app_config = config.app.clone();
                tokio::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(|req| handle_request(req, &app_config)))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        }
    }
}
