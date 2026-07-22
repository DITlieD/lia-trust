//! MCP stdio transport: Content-Length framed JSON-RPC (what Codex speaks).
//!
//! Protocol shape follows the MCP base protocol (headers + body), not NDJSON.

use std::io::{BufRead, Write};

use crate::AdapterError;

/// Read one Content-Length framed JSON-RPC message from `reader`.
/// Returns `Ok(None)` on clean EOF before any headers.
pub fn read_framed_message(reader: &mut impl BufRead) -> Result<Option<String>, AdapterError> {
    let mut content_length: Option<usize> = None;
    let mut saw_any = false;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| AdapterError::Invalid(format!("mcp stdio read header: {e}")))?;
        if n == 0 {
            if !saw_any {
                return Ok(None);
            }
            return Err(AdapterError::Invalid(
                "mcp stdio EOF mid-headers (incomplete message)".into(),
            ));
        }
        saw_any = true;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        // Header names are case-insensitive per HTTP-style framing used by MCP.
        let (name, value) = match trimmed.split_once(':') {
            Some((n, v)) => (n.trim(), v.trim()),
            None => {
                return Err(AdapterError::Invalid(format!(
                    "mcp stdio malformed header line: {trimmed}"
                )))
            }
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length =
                Some(value.parse().map_err(|e| {
                    AdapterError::Invalid(format!("mcp Content-Length parse: {e}"))
                })?);
        }
        // Content-Type and other headers ignored.
    }
    let len = content_length.ok_or_else(|| {
        AdapterError::Invalid("mcp stdio message missing Content-Length header".into())
    })?;
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| AdapterError::Invalid(format!("mcp stdio read body ({len} bytes): {e}")))?;
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| AdapterError::Invalid(format!("mcp stdio body not utf-8: {e}")))
}

/// Write one Content-Length framed JSON-RPC message to `writer`.
pub fn write_framed_message(writer: &mut impl Write, body: &str) -> Result<(), AdapterError> {
    write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body)
        .map_err(|e| AdapterError::Invalid(format!("mcp stdio write: {e}")))?;
    writer
        .flush()
        .map_err(|e| AdapterError::Invalid(format!("mcp stdio flush: {e}")))?;
    Ok(())
}

/// Encode a JSON value as a framed MCP message (for tests / clients).
pub fn frame_json(value: &serde_json::Value) -> Result<Vec<u8>, AdapterError> {
    let body = serde_json::to_string(value).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let mut out = Vec::new();
    write!(out, "Content-Length: {}\r\n\r\n{}", body.len(), body)
        .map_err(|e| AdapterError::Invalid(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_framed_message() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let mut buf = Vec::new();
        write_framed_message(&mut buf, body).unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_framed_message(&mut cur).unwrap().unwrap();
        assert_eq!(got, body);
        assert!(read_framed_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn content_length_case_insensitive() {
        let raw = b"content-length: 2\r\n\r\n{}";
        let mut cur = Cursor::new(&raw[..]);
        let got = read_framed_message(&mut cur).unwrap().unwrap();
        assert_eq!(got, "{}");
    }
}
