//! Minimal HTTP/1.1 server over rustls streams.
//!
//! The repository is std-only (no async runtime), so the gateway serves
//! HTTPS/WSS with a thread-per-connection model: a `TcpListener` accept loop
//! wraps each socket in rustls and dispatches to `handle_connection`.

use std::io::{Read, Write};
use std::net::TcpStream;

use rustls::StreamOwned;

use crate::error::GatewayError;

/// Maximum HTTP header size (16 KiB) to prevent unbounded reads.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// A parsed HTTP/1.1 request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    /// Look up a header by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// True if the request is a WebSocket upgrade (`Upgrade: websocket`).
    pub fn is_websocket_upgrade(&self) -> bool {
        self.header("upgrade")
            .map(|v| v.to_ascii_lowercase().contains("websocket"))
            .unwrap_or(false)
            && self
                .header("connection")
                .map(|v| v.to_ascii_lowercase().contains("upgrade"))
                .unwrap_or(false)
    }
}

/// Read and parse an HTTP request head from `reader`.
///
/// Returns `Ok(None)` on clean EOF before any byte is read.
///
/// # Errors
///
/// Returns `GatewayError::WebSocket` if the request exceeds the size limit or
/// is not valid UTF-8.
pub fn read_request<R: Read>(reader: &mut R) -> Result<Option<HttpRequest>, GatewayError> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                break;
            }
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() > MAX_REQUEST_BYTES {
                    return Err(GatewayError::WebSocket(
                        "HTTP request head too large".into(),
                    ));
                }
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(GatewayError::Io(e)),
        }
    }

    let text = String::from_utf8(buf)
        .map_err(|_| GatewayError::WebSocket("request head is not UTF-8".into()))?;
    parse_request_head(&text).map(Some)
}

fn parse_request_head(text: &str) -> Result<HttpRequest, GatewayError> {
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| GatewayError::WebSocket("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() {
        return Err(GatewayError::WebSocket(format!(
            "malformed request line: {request_line}"
        )));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            return Err(GatewayError::WebSocket(format!(
                "malformed header line: {line}"
            )));
        }
    }
    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
    })
}

/// Compute the RFC 6455 `Sec-WebSocket-Accept` value.
pub fn websocket_accept_key(key: &str) -> String {
    use base64::Engine;
    use sha1::Digest;
    const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut digest = sha1::Sha1::new();
    digest.update(key.as_bytes());
    digest.update(GUID);
    base64::engine::general_purpose::STANDARD.encode(digest.finalize())
}

/// Write an HTTP/1.1 101 Switching Protocols response.
pub fn write_websocket_101<W: Write>(w: &mut W, accept_key: &str) -> std::io::Result<()> {
    write!(
        w,
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept_key}\r\n\
         \r\n"
    )
}

/// A static asset served by the gateway.
pub struct StaticAsset {
    pub content_type: &'static str,
    pub bytes: &'static [u8],
}

macro_rules! static_asset {
    ($path:literal, $ct:literal, $file:literal) => {
        (
            $path,
            StaticAsset {
                content_type: $ct,
                bytes: include_bytes!(concat!("../static/", $file)),
            },
        )
    };
}

/// Static assets embedded in the binary (page + xterm.js + app.js).
pub const STATIC_ASSETS: &[(&str, StaticAsset)] = &[
    static_asset!("/", "text/html; charset=utf-8", "index.html"),
    static_asset!("/index.html", "text/html; charset=utf-8", "index.html"),
    static_asset!("/style.css", "text/css; charset=utf-8", "style.css"),
    static_asset!("/app.js", "application/javascript; charset=utf-8", "app.js"),
    static_asset!("/xterm.js", "application/javascript", "xterm.js"),
    static_asset!("/xterm.css", "text/css", "xterm.css"),
    static_asset!(
        "/xterm-addon-fit.js",
        "application/javascript",
        "xterm-addon-fit.js"
    ),
];

/// Look up a static asset by path (with query string stripped).
pub fn lookup_asset(path: &str) -> Option<&'static StaticAsset> {
    let path = path.split('?').next().unwrap_or(path);
    STATIC_ASSETS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, a)| a)
}

/// Write an HTTP/1.1 200 response with the given body.
pub fn write_http_response<W: Write>(
    w: &mut W,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> std::io::Result<()> {
    write!(
        w,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n",
        body.len()
    )?;
    for (k, v) in extra_headers {
        write!(w, "{k}: {v}\r\n")?;
    }
    write!(w, "\r\n")?;
    w.write_all(body)
}

/// Write an HTTP/1.1 404 response.
pub fn write_http_404<W: Write>(w: &mut W) -> std::io::Result<()> {
    let body = b"404 Not Found";
    write!(
        w,
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    w.write_all(body)
}

/// Write an HTTP/1.1 401 response (mesh endpoint auth failure).
pub fn write_http_401<W: Write>(w: &mut W) -> std::io::Result<()> {
    let body = b"401 Unauthorized";
    write!(
        w,
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    w.write_all(body)
}

/// Write an HTTP/1.1 405 response.
pub fn write_http_405<W: Write>(w: &mut W) -> std::io::Result<()> {
    let body = b"405 Method Not Allowed";
    write!(
        w,
        "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    w.write_all(body)
}

/// Type alias for a rustls-wrapped TLS stream.
pub type TlsStream = StreamOwned<rustls::ServerConnection, TcpStream>;