//! Complete hash-chain and intent/applied validation before any mutation.
use super::super::Result;
use super::{canonical, io, principal_valid, strict_json};
use nexus_domain::{
    ResourceName,
    task::{MAX_INTEGER, Sha256Digest, TaskId},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, path::PathBuf};

pub(super) const LIMIT: u64 = 8 * 1024 * 1024;
const NAME: &str = "task-provider-grant-audit-v1.jsonl";
const FIELDS: [&str; 14] = [
    "schema_version",
    "mutation_id",
    "phase",
    "operation",
    "scope",
    "resource",
    "principal",
    "actor",
    "changed",
    "before_sha256",
    "after_sha256",
    "at_unix",
    "previous_sha256",
    "record_sha256",
];
pub(super) struct Mutation {
    pub(super) id: String,
    pub(super) operation: &'static str,
    pub(super) scope: Value,
    pub(super) resource: String,
    pub(super) principal: String,
    pub(super) actor: String,
    pub(super) before: Option<String>,
    pub(super) after: String,
}
pub(super) struct Journal {
    path: PathBuf,
    file: Option<File>,
    length: u64,
    last: Option<String>,
}
fn digest(value: &Value, optional: bool) -> bool {
    (optional && value.is_null())
        || value
            .as_str()
            .is_some_and(|s| Sha256Digest::parse(s.to_owned()).is_ok())
}
fn record_digest(record: &Value) -> Result<String> {
    let mut record = record.clone();
    record
        .as_object_mut()
        .ok_or_else(|| io::corrupt("audit record must be an object"))?
        .remove("record_sha256");
    Ok(crate::n3_acceptance::sha256(&canonical(&record)?)
        .as_str()
        .to_owned())
}
fn validate(bytes: &[u8], scope: &Value) -> Result<Option<String>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(io::corrupt("operator audit has a torn tail"));
    }
    let mut previous = Value::Null;
    let mut intent: Option<Value> = None;
    let mut seen = BTreeSet::new();
    for line in bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| io::corrupt("operator audit has a torn tail"))?
        .split(|b| *b == b'\n')
    {
        let record = strict_json(line)?;
        let fields = record
            .as_object()
            .ok_or_else(|| io::corrupt("audit record must be an object"))?;
        if fields.len() != FIELDS.len()
            || !FIELDS.iter().all(|name| fields.contains_key(*name))
            || record["schema_version"].as_u64() != Some(1)
            || record["changed"] != true
            || record["scope"] != *scope
            || record["previous_sha256"] != previous
            || !digest(&record["before_sha256"], true)
            || !digest(&record["after_sha256"], false)
            || record["before_sha256"] == record["after_sha256"]
            || (record["operation"] == "revoke" && record["before_sha256"].is_null())
            || !digest(&record["record_sha256"], false)
            || !record["at_unix"]
                .as_u64()
                .is_some_and(|time| time <= MAX_INTEGER)
            || !record["principal"].as_str().is_some_and(principal_valid)
            || !record["actor"].as_str().is_some_and(principal_valid)
            || !record["resource"]
                .as_str()
                .is_some_and(|name| ResourceName::new(name).is_ok())
            || !matches!(record["operation"].as_str(), Some("add" | "revoke"))
            || !record["mutation_id"]
                .as_str()
                .is_some_and(|id| TaskId::new(id.to_owned()).is_ok())
            || record["record_sha256"].as_str() != Some(record_digest(&record)?.as_str())
        {
            return Err(io::corrupt(
                "operator audit shape, scope, checksum or chain differs",
            ));
        }
        match record["phase"].as_str() {
            Some("intent") if intent.is_none() => {
                let id = record["mutation_id"]
                    .as_str()
                    .ok_or_else(|| io::corrupt("missing audit mutation ID"))?;
                if !seen.insert(id.to_owned()) {
                    return Err(io::corrupt("operator audit mutation ID is reused"));
                }
                intent = Some(record.clone());
            }
            Some("applied") => {
                let before = intent
                    .take()
                    .ok_or_else(|| io::corrupt("operator audit applied has no intent"))?;
                for field in [
                    "schema_version",
                    "mutation_id",
                    "operation",
                    "scope",
                    "resource",
                    "principal",
                    "actor",
                    "changed",
                    "before_sha256",
                    "after_sha256",
                ] {
                    if before[field] != record[field] {
                        return Err(io::corrupt("operator audit intent/applied pair differs"));
                    }
                }
            }
            _ => return Err(io::corrupt("operator audit phases are not complete pairs")),
        }
        previous = record["record_sha256"].clone();
    }
    if intent.is_some() {
        return Err(io::corrupt("operator audit has an unresolved intent"));
    }
    Ok(previous.as_str().map(str::to_owned))
}
impl Journal {
    pub(super) fn check(&self, roots: &io::Roots) -> Result<()> {
        roots.check()?;
        match &self.file {
            Some(file) => {
                io::check_file(file, &self.path, true)?;
                if file.metadata().map_err(io::persistence)?.len() != self.length {
                    return Err(io::corrupt("operator audit length changed"));
                }
            }
            None => match std::fs::symlink_metadata(&self.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io::persistence(error)),
                Ok(_) => return Err(io::corrupt("operator audit appeared outside the lease")),
            },
        }
        Ok(())
    }
    pub(super) fn load(roots: &io::Roots, scope: &Value) -> Result<Self> {
        let path = roots.n2.join(NAME);
        let record = io::read_optional(&path, LIMIT, true)?;
        let (file, length, last) = match record {
            Some(record) => {
                let last = validate(&record.bytes, scope)?;
                (Some(record.file), record.bytes.len() as u64, last)
            }
            None => (None, 0, None),
        };
        roots.check()?;
        Ok(Self {
            path,
            file,
            length,
            last,
        })
    }
    pub(super) fn records(&self, mutation: &Mutation) -> Result<(Vec<u8>, Vec<u8>)> {
        let time = crate::n2_store::now_unix_pub();
        if time > MAX_INTEGER {
            return Err(io::corrupt("audit timestamp exceeds exact integer range"));
        }
        let mut record = json!({"schema_version":1,"mutation_id":mutation.id,"phase":"intent",
            "operation":mutation.operation,"scope":mutation.scope,"resource":mutation.resource,
            "principal":mutation.principal,"actor":mutation.actor,"changed":true,
            "before_sha256":mutation.before,"after_sha256":mutation.after,"at_unix":time,
            "previous_sha256":self.last});
        let hash = record_digest(&record)?;
        record["record_sha256"] = json!(hash);
        let mut intent = canonical(&record)?;
        intent.push(b'\n');
        record["phase"] = json!("applied");
        record["previous_sha256"] = record["record_sha256"].clone();
        record["record_sha256"] = json!(record_digest(&record)?);
        let mut applied = canonical(&record)?;
        applied.push(b'\n');
        if self.length + intent.len() as u64 + applied.len() as u64 > LIMIT {
            return Err(io::capacity(
                "operator audit is full; explicit archival or repair is required",
                false,
            ));
        }
        Ok((intent, applied))
    }
    pub(super) fn append(
        &mut self,
        roots: &io::Roots,
        lease: &io::Lease,
        bytes: &[u8],
    ) -> Result<()> {
        let file = io::append(
            roots,
            lease,
            &self.path,
            self.file.as_ref(),
            self.length,
            bytes,
        )?;
        self.file = Some(file);
        self.length += bytes.len() as u64;
        let record = strict_json(
            bytes
                .strip_suffix(b"\n")
                .ok_or_else(|| io::corrupt("missing audit newline"))?,
        )?;
        self.last = record["record_sha256"].as_str().map(str::to_owned);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Journal, Mutation) {
        (
            Journal {
                path: PathBuf::from("unused"),
                file: None,
                length: 0,
                last: None,
            },
            Mutation {
                id: "mutation-1".into(),
                operation: "add",
                scope: json!({"provider":"provider","workspace":"workspace"}),
                resource: "resource".into(),
                principal: format!("ed25519:{}", "01".repeat(16)),
                actor: format!("ed25519:{}", "02".repeat(16)),
                before: None,
                after: format!("sha256:{}", "00".repeat(32)),
            },
        )
    }
    #[test]
    fn complete_pairs_checksums_order_and_torn_intent_are_independently_validated() {
        let (journal, mutation) = fixture();
        let (intent, applied) = journal.records(&mutation).unwrap();
        let complete = [intent.clone(), applied.clone()].concat();
        assert!(validate(&complete, &mutation.scope).is_ok());
        assert!(validate(&intent, &mutation.scope).is_err());
        assert!(validate(&complete[..complete.len() - 1], &mutation.scope).is_err());
        assert!(validate(&applied, &mutation.scope).is_err());
        assert!(
            validate(
                &[intent.clone(), intent.clone(), applied.clone()].concat(),
                &mutation.scope
            )
            .is_err()
        );
        let mut changed = strict_json(applied.strip_suffix(b"\n").unwrap()).unwrap();
        changed["resource"] = json!("different-resource");
        changed["record_sha256"] = json!(record_digest(&changed).unwrap());
        let mut bad_pair = canonical(&changed).unwrap();
        bad_pair.push(b'\n');
        assert!(validate(&[intent.clone(), bad_pair].concat(), &mutation.scope).is_err());
        let mut bad_checksum = complete.clone();
        let index = bad_checksum.iter().position(|b| *b == b'1').unwrap();
        bad_checksum[index] = b'2';
        assert!(validate(&bad_checksum, &mutation.scope).is_err());
        assert!(
            validate(
                &complete,
                &json!({"provider":"another","workspace":"workspace"})
            )
            .is_err()
        );
        assert!(validate(b"\n", &mutation.scope).is_err());
    }
    #[test]
    fn pair_budget_is_reserved_before_writing_any_intent() {
        let (mut journal, mutation) = fixture();
        let (intent, applied) = journal.records(&mutation).unwrap();
        journal.length = LIMIT - (intent.len() + applied.len()) as u64;
        assert!(journal.records(&mutation).is_ok());
        journal.length += 1;
        assert!(journal.records(&mutation).is_err());
    }

    #[test]
    fn valid_checksums_do_not_authorize_impossible_changed_histories() {
        let (journal, mut mutation) = fixture();
        mutation.before = Some(mutation.after.clone());
        let (intent, applied) = journal.records(&mutation).unwrap();
        assert!(validate(&[intent, applied].concat(), &mutation.scope).is_err());
        mutation.before = None;
        mutation.operation = "revoke";
        let (intent, applied) = journal.records(&mutation).unwrap();
        assert!(validate(&[intent, applied].concat(), &mutation.scope).is_err());
        // A genuinely initial, privately-bound zero-byte audit has no intent.
        assert!(validate(b"", &mutation.scope).unwrap().is_none());
    }
}
