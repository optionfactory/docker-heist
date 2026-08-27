//! Minimal HTTP/1.0 client over the local Docker daemon Unix socket, shared by
//! the docker-heist tools.
//!
//! Requests use HTTP/1.0 with `Connection: close`, so the daemon never uses
//! chunked transfer encoding and the response body is simply "everything after
//! the header blank line". This crate has no external dependencies: callers
//! parse the JSON bodies themselves (with whatever they prefer).

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

/// Largest response we will read from the daemon.
const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

/// A parsed HTTP response: the status code and the body (everything after the
/// header blank line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

/// A connection factory for the local Docker daemon socket. Cheap to clone-ish
/// (holds only the path); each `request` opens a fresh short-lived connection.
pub struct Socket {
    path: PathBuf,
}

impl Socket {
    /// Resolve the socket from `DOCKER_HOST` (`unix://` only) or the default,
    /// and check that it exists.
    pub fn from_env() -> Result<Self, String> {
        let path = resolve_socket_path(std::env::var("DOCKER_HOST").ok().as_deref())?;
        if !path.exists() {
            return Err(format!("Docker socket not found at {}", path.display()));
        }
        Ok(Self { path })
    }

    /// Use an explicit socket path (must exist).
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Owner uid of the socket file, for trust checks.
    pub fn owner_uid(&self) -> std::io::Result<u32> {
        Ok(std::fs::metadata(&self.path)?.uid())
    }

    /// Send an HTTP/1.0 request (`Connection: close`) with an optional JSON body
    /// and return the response.
    pub fn request(&self, method: &str, path: &str, json_body: Option<&str>) -> Result<Response, String> {
        let mut stream =
            UnixStream::connect(&self.path).map_err(|e| format!("cannot connect to {}: {e}", self.path.display()))?;
        let timeout = Some(Duration::from_secs(10));
        stream
            .set_read_timeout(timeout)
            .map_err(|e| format!("set read timeout: {e}"))?;
        stream
            .set_write_timeout(timeout)
            .map_err(|e| format!("set write timeout: {e}"))?;

        let mut req =
            format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n");
        if let Some(body) = json_body {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        if let Some(body) = json_body {
            req.push_str(body);
        }

        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("socket write: {e}"))?;
        let mut response = String::new();
        stream
            .take(MAX_RESPONSE)
            .read_to_string(&mut response)
            .map_err(|e| format!("socket read: {e}"))?;
        parse_http_response(&response)
    }
}

/// Resolve a Docker socket path: `DOCKER_HOST=unix:///abs/path`, or the default.
/// Remote schemes (tcp://, ssh://) and relative unix paths are rejected - the
/// heist tools operate only on the local daemon.
pub fn resolve_socket_path(docker_host: Option<&str>) -> Result<PathBuf, String> {
    match docker_host {
        None | Some("") => Ok(PathBuf::from(DEFAULT_SOCKET)),
        Some(host) => match host.strip_prefix("unix://") {
            Some(p) if p.starts_with('/') => Ok(PathBuf::from(p)),
            Some(_) => Err(format!("DOCKER_HOST={host}: unix socket path must be absolute")),
            None => Err(format!(
                "DOCKER_HOST={host}: only a local daemon over a unix:// socket is supported"
            )),
        },
    }
}

/// RFC 3986 percent-encoding of everything but the unreserved characters.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn parse_http_response(response: &str) -> Result<Response, String> {
    let first_line = response.lines().next().ok_or("empty HTTP response from Docker")?;
    let status = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed HTTP status line from Docker: {first_line:?}"))?;
    let body = match response.find("\r\n\r\n") {
        Some(idx) => response[idx + 4..].to_string(),
        None => String::new(),
    };
    Ok(Response { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(resp: &str) -> Result<Response, String> {
        parse_http_response(resp)
    }

    #[test]
    fn socket_path_default_and_unix_scheme() {
        assert_eq!(resolve_socket_path(None).unwrap(), PathBuf::from(DEFAULT_SOCKET));
        assert_eq!(resolve_socket_path(Some("")).unwrap(), PathBuf::from(DEFAULT_SOCKET));
        assert_eq!(
            resolve_socket_path(Some("unix:///custom/docker.sock")).unwrap(),
            PathBuf::from("/custom/docker.sock")
        );
    }

    #[test]
    fn socket_path_rejects_remote_or_relative() {
        assert!(resolve_socket_path(Some("tcp://1.2.3.4:2375")).is_err());
        assert!(resolve_socket_path(Some("ssh://host")).is_err());
        assert!(resolve_socket_path(Some("unix://relative")).is_err());
        assert!(resolve_socket_path(Some("unix://")).is_err());
    }

    #[test]
    fn http_status_and_body() {
        let r = parse("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"Id\":\"abc\"}").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "{\"Id\":\"abc\"}");
        assert_eq!(
            parse("HTTP/1.0 204 No Content\r\n\r\n").unwrap(),
            Response {
                status: 204,
                body: String::new()
            }
        );
        assert_eq!(parse("HTTP/1.0 201\r\n\r\n").unwrap().status, 201); // no reason phrase
    }

    #[test]
    fn http_body_containing_blank_line_is_not_split_twice() {
        let r = parse("HTTP/1.0 200 OK\r\n\r\nline1\r\n\r\nline2").unwrap();
        assert_eq!(r.body, "line1\r\n\r\nline2");
    }

    #[test]
    fn http_rejects_malformed() {
        assert!(parse("").is_err());
        assert!(parse("garbage\r\n\r\n").is_err());
        assert!(parse("HTTP/1.0\r\n\r\n").is_err());
    }

    #[test]
    fn http_lf_only_separator_yields_empty_body() {
        // The splitter requires CRLFCRLF; an LF-only response parses status but
        // yields an empty body.
        let r = parse("HTTP/1.0 201 Created\n\nbody-here").unwrap();
        assert_eq!((r.status, r.body.as_str()), (201, ""));
    }

    #[test]
    fn percent_encoding_of_filter_json() {
        assert_eq!(
            percent_encode(r#"{"label":["docker-bluff.id=ab-12"]}"#),
            "%7B%22label%22%3A%5B%22docker-bluff.id%3Dab-12%22%5D%7D"
        );
    }
}
