//! Minimal HTTP/1.1 request parsing and response rendering.
//!
//! The product's gateway opens one fresh TLS connection per request
//! (connection pooling is disabled), so the mock only needs to read one
//! request per connection. The parser mirrors the proven hand-rolled reader
//! in `rutilus-infra-redfish`'s tests: bounded header and body reads, with
//! `Expect: 100-continue` honored so a chunked-upload client cannot stall.

use std::io;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

/// Maximum request head (request line + headers) the mock accepts; the
/// product never approaches this, it is a defensive bound only.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Maximum request body the mock accepts; Session creation payloads are
/// well under this bound.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// One HTTP request method the mock routes on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpMethod {
    Get,
    Post,
    Patch,
    Delete,
    /// Any other method is not part of the fixture surface and is routed to
    /// the Redfish-shaped 404.
    Other,
}

impl HttpMethod {
    fn parse(value: &str) -> Self {
        match value {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            _ => Self::Other,
        }
    }

    /// The wire text of this method, for request recording.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Other => "UNKNOWN",
        }
    }
}

/// One parsed HTTP request received by the mock.
pub(crate) struct HttpRequest {
    pub(crate) method: HttpMethod,
    pub(crate) target: String,
    /// Header names are normalized to lowercase so request recording and
    /// lookup are case-insensitive without repeated comparisons.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

/// The parsed request line and headers, before the body is read.
struct RequestHead {
    method: HttpMethod,
    target: String,
    headers: Vec<(String, String)>,
}

impl RequestHead {
    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header_name, value)| {
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.as_str())
        })
    }

    fn content_length(&self) -> Option<usize> {
        self.header_value("content-length")?.parse().ok()
    }

    fn expects_continue(&self) -> bool {
        self.header_value("expect")
            .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
    }
}

/// Reads one complete HTTP request: head up to `\r\n\r\n`, then the body
/// declared by `Content-Length`.
///
/// The client may send the head and body in one TCP segment, so any bytes
/// that arrive after the head terminator are retained and used as the body
/// prefix instead of being dropped; dropping them would stall the body read
/// and close the connection mid-request.
///
/// # Errors
///
/// Returns an I/O error for an oversized, malformed, or truncated request.
pub(crate) async fn read_http_request(
    stream: &mut TlsStream<TcpStream>,
) -> io::Result<HttpRequest> {
    let (buffer, head_end) = read_head(stream).await?;
    let head = parse_head(&buffer[..head_end])?;
    if head.expects_continue() {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    }
    let body = match head.content_length() {
        Some(length) if length <= MAX_BODY_BYTES => {
            let mut body = buffer[head_end..].to_vec();
            if body.len() < length {
                let mut rest = vec![0_u8; length - body.len()];
                stream.read_exact(&mut rest).await?;
                body.extend(rest);
            }
            body
        }
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mock HTTP request body exceeded the limit",
            ));
        }
        None => Vec::new(),
    };
    Ok(HttpRequest {
        method: head.method,
        target: head.target,
        headers: head.headers,
        body,
    })
}

/// Reads the request head bytes up to and including the blank line, and
/// returns the index just past it together with the buffer.
///
/// The returned buffer may contain body bytes that shared the TCP segment
/// with the head; the caller must keep them.
async fn read_head(stream: &mut TlsStream<TcpStream>) -> io::Result<(Vec<u8>, usize)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let bytes = stream.read(&mut chunk).await?;
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mock HTTP request ended before its headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..bytes]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mock HTTP request headers exceeded the limit",
            ));
        }
        if let Some(offset) = find_head_end(&buffer) {
            return Ok((buffer, offset));
        }
    }
}

/// Locates the end of the request head (just past the blank line).
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

/// Parses the request line and headers of an HTTP/1.1 head.
fn parse_head(head_bytes: &[u8]) -> io::Result<RequestHead> {
    let head = std::str::from_utf8(head_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request is not valid UTF-8",
        )
    })?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request has no request line",
        )
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request has no method",
        )
    })?;
    let target = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request has no request target",
        )
    })?;
    let version = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request has no protocol version",
        )
    })?;
    if version != "HTTP/1.1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request is not HTTP/1.1",
        ));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "mock HTTP request has a malformed header line",
            )
        })?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(RequestHead {
        method: HttpMethod::parse(method),
        target: target.to_owned(),
        headers,
    })
}

/// One HTTP response the mock renders, before serialization.
pub(crate) struct HttpResponse {
    pub(crate) status: &'static str,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: String,
}

impl HttpResponse {
    pub(crate) fn json(status: &'static str, body: String) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    pub(crate) fn json_with_headers(
        status: &'static str,
        headers: Vec<(String, String)>,
        body: String,
    ) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

/// Renders one response as HTTP/1.1 bytes with a JSON content type and a
/// `Connection: close` so each connection serves exactly one request.
pub(crate) fn render_response(response: &HttpResponse) -> Vec<u8> {
    let mut rendered = String::with_capacity(256 + response.body.len());
    rendered.push_str("HTTP/1.1 ");
    rendered.push_str(response.status);
    rendered.push_str("\r\n");
    for (name, value) in &response.headers {
        rendered.push_str(name);
        rendered.push_str(": ");
        rendered.push_str(value);
        rendered.push_str("\r\n");
    }
    rendered.push_str("Content-Type: application/json\r\n");
    rendered.push_str("Content-Length: ");
    rendered.push_str(&response.body.len().to_string());
    rendered.push_str("\r\nConnection: close\r\n\r\n");
    rendered.push_str(&response.body);
    rendered.into_bytes()
}

/// One HTTP request the Mock BMC received, captured for wire-sequence tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestRecord {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl RequestRecord {
    pub(crate) fn new(method: &str, path: &str, headers: Vec<(String, String)>) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            headers,
        }
    }

    /// Returns the request method as received on the wire.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the request target as received on the wire.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Looks up one request header by name, case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header_name, value)| {
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.as_str())
        })
    }
}
