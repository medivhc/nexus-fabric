//! N3-1 composition adapters: strict JSON, established SHA-256 and atomic Linux
//! provider persistence. No CLI/API route, transport or executor is installed.
use nexus_domain::task::{
    Sha256Digest, TaskError, TaskErrorCode, TaskId,
    codec::{CanonicalDto, Value},
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::fmt;

/// SHA-256 implementation stays in the composition root; no domain crypto code.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut raw = [0u8; 32];
    raw.copy_from_slice(digest.as_ref());
    Sha256Digest::from_bytes(raw)
}
/// Resumable streaming SHA-256 (N3-12 §5): cloning a state that already
/// covers a verified prefix lets nexusd extend it with appended bytes without
/// re-reading the prefix.
#[derive(Clone)]
pub struct Sha256Stream(ring::digest::Context);

impl Default for Sha256Stream {
    fn default() -> Self {
        Self(ring::digest::Context::new(&ring::digest::SHA256))
    }
}

impl Sha256Stream {
    /// Feeds the next bytes of the stream.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Consumes the state and returns SHA-256 of every byte fed so far;
    /// clone first to keep extending the same prefix.
    #[must_use]
    pub fn finish(self) -> Sha256Digest {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(self.0.finish().as_ref());
        Sha256Digest::from_bytes(raw)
    }
}

/// Shared composition-root SHA-256 for the CLI and nexusd staging adapter,
/// exposed so nexusd can reuse the established crypto dependency through
/// `nexus::n3_acceptance` rather than adding a separate ring/sha2 dependency.
/// Scratch space is bounded; input length and IO duration are not: this reads
/// until EOF. Callers must bound the reader (for example with `Read::take`) and
/// enforce declared size, file identity, content and authorization checks.
pub fn sha256_reader(reader: impl std::io::Read) -> std::io::Result<Sha256Digest> {
    sha256_stream_reader(reader).map(Sha256Stream::finish)
}

/// Like [`sha256_reader`], but returns the unfinished state for extension.
pub fn sha256_stream_reader(mut reader: impl std::io::Read) -> std::io::Result<Sha256Stream> {
    let mut stream = Sha256Stream::default();
    let mut buffer = [0u8; 65_536];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => stream.update(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(stream)
}
/// Opaque provider-generated TaskId, independent of requester/session identifiers.
pub fn new_task_id() -> Result<TaskId, TaskError> {
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|e| {
        TaskError::new(
            TaskErrorCode::PersistenceFailed,
            format!("TaskId randomness unavailable: {e}"),
            true,
        )
    })?;
    TaskId::new(format!(
        "task-{}",
        &Sha256Digest::from_bytes(random).as_str()[7..]
    ))
}
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}
struct StrictVisitor;
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("lossless N3 JSON without duplicate keys or floats")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Integer(i128::from(v))))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Integer(i128::from(v))))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v.into())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v)))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut v = Vec::new();
        while let Some(StrictValue(x)) = seq.next_element()? {
            v.push(x);
        }
        Ok(StrictValue(Value::Array(v)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut v = BTreeMap::new();
        while let Some((k, StrictValue(x))) = map.next_entry::<String, StrictValue>()? {
            if v.insert(k, x).is_some() {
                return Err(de::Error::custom("duplicate JSON key"));
            }
        }
        Ok(StrictValue(Value::Object(v)))
    }
}
/// Parse losslessly, reject duplicate keys, fractional/exponent numbers and
/// isolated surrogates. Negative zero is normalized before serde's float path.
pub fn parse_canonical_json(raw: &[u8]) -> Result<Value, TaskError> {
    let mut normalized = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'"' {
            normalized.push(raw[i]);
            i += 1;
            while i < raw.len() {
                let b = raw[i];
                normalized.push(b);
                i += 1;
                if b == b'\\' {
                    if let Some(&next) = raw.get(i) {
                        normalized.push(next);
                        i += 1;
                    }
                } else if b == b'"' {
                    break;
                }
            }
        } else if raw[i] == b'-' || raw[i].is_ascii_digit() {
            let begin = i;
            while i < raw.len() && matches!(raw[i], b'-' | b'+' | b'0'..=b'9' | b'.' | b'e' | b'E')
            {
                i += 1;
            }
            let token = &raw[begin..i];
            if token.iter().any(|b| matches!(b, b'.' | b'e' | b'E' | b'+')) {
                return Err(TaskError::invalid(
                    "fractional/exponent JSON numbers are forbidden",
                ));
            }
            if token == b"-0" {
                normalized.push(b'0');
            } else {
                normalized.extend_from_slice(token);
            }
        } else {
            normalized.push(raw[i]);
            i += 1;
        }
    }
    serde_json::from_slice::<StrictValue>(&normalized)
        .map(|v| v.0)
        .map_err(|e| TaskError::invalid(format!("invalid N3 JSON: {e}")))
}
/// Decode and validate one versioned DTO, including semantic state constraints.
pub fn decode_dto<T: CanonicalDto>(bytes: &[u8]) -> Result<T, TaskError> {
    T::from_value(parse_canonical_json(bytes)?)
}

#[cfg(test)]
#[path = "n3_acceptance_tests.rs"]
mod tests;

#[cfg(test)]
mod stream_hash_tests {
    use super::sha256_reader;
    use std::io::{self, Read};

    #[test]
    fn known_vectors_short_reads_and_interrupted_do_not_change_digest() {
        struct Fragmented {
            remaining: &'static [u8],
            interrupted: bool,
        }
        impl Read for Fragmented {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if self.remaining.is_empty() {
                    return Ok(0);
                }
                out[0] = self.remaining[0];
                self.remaining = &self.remaining[1..];
                Ok(1)
            }
        }
        assert_eq!(
            sha256_reader(io::empty()).unwrap().as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_reader(Fragmented {
                remaining: b"abc",
                interrupted: false
            })
            .unwrap()
            .as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn stream_error_is_propagated_and_range_is_owned_by_caller() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        assert_eq!(
            sha256_reader(Broken).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            sha256_reader((&b"abcEXTRA"[..]).take(3)).unwrap().as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
