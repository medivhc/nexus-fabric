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
