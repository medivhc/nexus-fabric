//! Dependency-free canonical values shared by N3 wire and persistence adapters.
use super::{Sha256Digest, TaskError};
use std::collections::BTreeMap;

/// Lossless JSON subset: no floating point or duplicate object keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i128),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

/// Typed N3 values; adapters parse JSON before entering the portable domain.
pub trait CanonicalDto: Sized {
    fn to_value(&self) -> Value;
    fn from_value(value: Value) -> Result<Self, TaskError>;
}

impl Value {
    /// Exact UTF-8 bytes under the frozen N3 canonical rules.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        self.write(&mut out);
        out.into_bytes()
    }
    fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Self::Integer(v) => out.push_str(&v.to_string()),
            Self::String(v) => quote(v, out),
            Self::Array(v) => {
                out.push('[');
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    x.write(out);
                }
                out.push(']');
            }
            Self::Object(v) => {
                out.push('{');
                for (i, (k, x)) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    quote(k, out);
                    out.push(':');
                    x.write(out);
                }
                out.push('}');
            }
        }
    }
}
fn quote(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\x0c' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' ' => {
                const HEX: &[u8] = b"0123456789abcdef";
                let n = c as usize;
                out.push_str("\\u00");
                out.push(HEX[n >> 4] as char);
                out.push(HEX[n & 15] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
impl CanonicalDto for String {
    fn to_value(&self) -> Value {
        Value::String(self.clone())
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        if let Value::String(x) = v {
            Ok(x)
        } else {
            Err(TaskError::invalid("expected string"))
        }
    }
}
impl CanonicalDto for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        if let Value::Bool(x) = v {
            Ok(x)
        } else {
            Err(TaskError::invalid("expected boolean"))
        }
    }
}
impl CanonicalDto for u64 {
    fn to_value(&self) -> Value {
        Value::Integer(i128::from(*self))
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        match v {
            Value::Integer(x) if (0..=i128::from(super::MAX_INTEGER)).contains(&x) => Ok(x as u64),
            _ => Err(TaskError::invalid(
                "expected exact nonnegative integer <= 2^53-1",
            )),
        }
    }
}
impl CanonicalDto for u8 {
    fn to_value(&self) -> Value {
        Value::Integer(i128::from(*self))
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        let x = u64::from_value(v)?;
        u8::try_from(x).map_err(|_| TaskError::invalid("exit code exceeds 255"))
    }
}
impl<T: CanonicalDto> CanonicalDto for Vec<T> {
    fn to_value(&self) -> Value {
        Value::Array(self.iter().map(T::to_value).collect())
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        if let Value::Array(x) = v {
            x.into_iter().map(T::from_value).collect()
        } else {
            Err(TaskError::invalid("expected array"))
        }
    }
}
impl<T: CanonicalDto> CanonicalDto for Option<T> {
    fn to_value(&self) -> Value {
        self.as_ref().map_or(Value::Null, T::to_value)
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        if v == Value::Null {
            Ok(None)
        } else {
            T::from_value(v).map(Some)
        }
    }
}
impl CanonicalDto for Sha256Digest {
    fn to_value(&self) -> Value {
        self.as_str().to_string().to_value()
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        Self::parse(String::from_value(v)?)
    }
}
/// SHA-256 is supplied by the composition root's established crypto library.
pub type DigestFn = fn(&[u8]) -> Sha256Digest;
