//! Private canonical authority and checked admission, independent of filesystem IO.
use super::*;
use nexus_workspace::snapshot::{FrozenSnapshot, SnapshotFile};

pub(super) const GLOBAL: u64 = 16_777_216;
pub(super) const RECORD_LIMIT: u64 = 524_288;
pub(super) const LEDGER_LIMIT: u64 = 4_194_304;
pub(super) const SMALL: u64 = 16_384;
pub(super) const MARKER: &str = "snapshot-staging-required-v1.json";
pub(super) const NAMESPACE: &str = "snapshot-staging-v1";
pub(super) const LEDGER: &str = "ledger-v1.json";
pub(super) const TEMP: &str = ".ledger-v1.tmp";
pub(super) const POLICY: &str = "policy-v1.json";
pub(super) const LOCK: &str = "staging.lock";
pub(super) const MANIFEST: &str = "manifest-v1.json";
pub(super) const SCRATCH: &str = "chunk.tmp";

macro_rules! codec {
    ($t:ident {$($f:ident:$ty:ty),+ $(,)?}) => {
        impl CanonicalDto for $t {
            fn to_value(&self) -> Value { Value::Object(BTreeMap::from([$( (stringify!($f).into(), self.$f.to_value()) ),+])) }
            fn from_value(v: Value) -> Result<Self,TaskError> {
                let Value::Object(mut fields)=v else {return Err(corrupt("authority object expected"))};
                let result=Self {$( $f: <$ty>::from_value(fields.remove(stringify!($f)).ok_or_else(||corrupt(concat!("missing ",stringify!($f))))?)? ),+};
                if !fields.is_empty(){return Err(corrupt("unknown authority field"))} Ok(result)
            }
        }
    }
}
impl CanonicalDto for io::NodeId {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("device".into(), self.device.to_string().to_value()),
            ("inode".into(), self.inode.to_string().to_value()),
        ]))
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        let Value::Object(mut f) = v else {
            return Err(corrupt("invalid inode binding"));
        };
        let mut number = |key: &str| -> Result<u64, TaskError> {
            let s = String::from_value(
                f.remove(key)
                    .ok_or_else(|| corrupt("missing inode binding"))?,
            )?;
            let n = s
                .parse::<u64>()
                .map_err(|_| corrupt("invalid host integer"))?;
            if n.to_string() != s {
                return Err(corrupt("noncanonical host integer"));
            }
            Ok(n)
        };
        let id = Self {
            device: number("device")?,
            inode: number("inode")?,
        };
        if !f.is_empty() {
            return Err(corrupt("unknown inode field"));
        }
        Ok(id)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Policy {
    pub schema_version: u64,
    pub max_reserved_bytes: u64,
    pub max_active_uploads: u64,
}
codec!(Policy {
    schema_version: u64,
    max_reserved_bytes: u64,
    max_active_uploads: u64
});
impl Policy {
    pub fn validate(&self) -> Result<(), TaskError> {
        if self.schema_version != 1
            || self.max_reserved_bytes < GLOBAL
            || self.max_reserved_bytes > MAX_INTEGER
            || !(1..=8).contains(&self.max_active_uploads)
        {
            return Err(TaskError::invalid("invalid staging budget"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Binding {
    pub root: io::NodeId,
    pub n2: io::NodeId,
    pub data: io::NodeId,
    pub n3: io::NodeId,
    pub identity: io::NodeId,
    pub identity_digest: Sha256Digest,
    pub scope: io::NodeId,
    pub scope_digest: Sha256Digest,
    pub provider: String,
    pub workspace: String,
    pub principal: String,
    pub policy_digest: Sha256Digest,
    pub namespace: Option<io::NodeId>,
    pub uploads: Option<io::NodeId>,
    pub lock: Option<io::NodeId>,
    pub policy: Option<io::NodeId>,
}
codec!(Binding{root:io::NodeId,n2:io::NodeId,data:io::NodeId,n3:io::NodeId,identity:io::NodeId,identity_digest:Sha256Digest,scope:io::NodeId,scope_digest:Sha256Digest,provider:String,workspace:String,principal:String,policy_digest:Sha256Digest,namespace:Option<io::NodeId>,uploads:Option<io::NodeId>,lock:Option<io::NodeId>,policy:Option<io::NodeId>});
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Marker {
    pub schema_version: u64,
    pub phase: String,
    pub binding: Binding,
}
codec!(Marker {
    schema_version: u64,
    phase: String,
    binding: Binding
});
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Blob {
    pub digest: Sha256Digest,
    pub size: u64,
    pub offset: u64,
    pub prefix: Sha256Digest,
    pub inode: Option<io::NodeId>,
}
codec!(Blob{digest:Sha256Digest,size:u64,offset:u64,prefix:Sha256Digest,inode:Option<io::NodeId>});
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Chunk {
    pub blob: Sha256Digest,
    pub old: u64,
    pub next: u64,
    pub old_prefix: Sha256Digest,
    pub hash: Sha256Digest,
    pub phase: String,
    pub scratch: Option<io::NodeId>,
}
codec!(Chunk{blob:Sha256Digest,old:u64,next:u64,old_prefix:Sha256Digest,hash:Sha256Digest,phase:String,scratch:Option<io::NodeId>});
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Cleanup {
    // The enclosing original record binds the complete tree to be removed.
    pub directories_durable: bool,
}
codec!(Cleanup {
    directories_durable: bool
});
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Intent {
    Begin,
    Chunk(Chunk),
    Seal,
    Cleanup(Cleanup),
}
impl CanonicalDto for Intent {
    fn to_value(&self) -> Value {
        let (kind, detail) = match self {
            Self::Begin => ("begin", Value::Null),
            Self::Chunk(c) => ("chunk", c.to_value()),
            Self::Seal => ("seal", Value::Null),
            Self::Cleanup(c) => ("cleanup", c.to_value()),
        };
        Value::Object(BTreeMap::from([
            ("kind".into(), kind.to_string().to_value()),
            ("detail".into(), detail),
        ]))
    }
    fn from_value(v: Value) -> Result<Self, TaskError> {
        let Value::Object(mut f) = v else {
            return Err(corrupt("invalid intent"));
        };
        let k = String::from_value(
            f.remove("kind")
                .ok_or_else(|| corrupt("missing intent kind"))?,
        )?;
        let d = f
            .remove("detail")
            .ok_or_else(|| corrupt("missing intent detail"))?;
        if !f.is_empty() {
            return Err(corrupt("unknown intent field"));
        }
        match k.as_str() {
            "begin" if d == Value::Null => Ok(Self::Begin),
            "seal" if d == Value::Null => Ok(Self::Seal),
            "chunk" => Ok(Self::Chunk(Chunk::from_value(d)?)),
            "cleanup" => Ok(Self::Cleanup(Cleanup::from_value(d)?)),
            _ => Err(corrupt("invalid intent variant")),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
    pub id: UploadId,
    pub owner: String,
    pub resource: String,
    pub key: String,
    pub snapshot: SnapshotRef,
    pub manifest: String,
    pub charge: u64,
    pub ceiling: u64,
    pub state: UploadState,
    pub blobs: Vec<Blob>,
    pub directory: Option<io::NodeId>,
    pub blob_directory: Option<io::NodeId>,
    pub manifest_inode: Option<io::NodeId>,
    pub intent: Option<Intent>,
    pub cancelled_at: Option<u64>,
}
codec!(Record{id:UploadId,owner:String,resource:String,key:String,snapshot:SnapshotRef,manifest:String,charge:u64,ceiling:u64,state:UploadState,blobs:Vec<Blob>,directory:Option<io::NodeId>,blob_directory:Option<io::NodeId>,manifest_inode:Option<io::NodeId>,intent:Option<Intent>,cancelled_at:Option<u64>});
impl Record {
    pub fn view(&self, b: &Binding) -> UploadView {
        UploadView {
            schema_version: 1,
            upload_id: self.id.clone(),
            provider: b.provider.clone(),
            workspace: b.workspace.clone(),
            resource: self.resource.clone(),
            snapshot: self.snapshot.clone(),
            state: self.state,
            reserved_bytes: if self.state == UploadState::Cancelled {
                0
            } else {
                self.charge
            },
            blobs: if self.state == UploadState::Cancelled {
                vec![]
            } else {
                self.blobs
                    .iter()
                    .map(|x| UploadBlob {
                        sha256: x.digest.clone(),
                        size_bytes: x.size,
                        durable_offset: x.offset,
                    })
                    .collect()
            },
        }
    }
    pub fn validate(&self, b: &Binding) -> Result<(), TaskError> {
        if !generated_id(&self.id)
            || self.owner.is_empty()
            || self.owner.chars().count() > 256
            || self.snapshot.workspace != b.workspace
            || self.charge == 0
            || self.charge > MAX_INTEGER
            || self.ceiling > RECORD_LIMIT
            || self.to_value().canonical_bytes().len() as u64 > self.ceiling
        {
            return Err(corrupt("invalid record binding or ceiling"));
        }
        TaskId::new(self.resource.clone()).map_err(|_| corrupt("invalid record resource"))?;
        TaskId::new(self.key.clone()).map_err(|_| corrupt("invalid record key"))?;
        if self.state == UploadState::Cancelled {
            self.snapshot
                .verify_digest(sha256)
                .map_err(|_| corrupt("invalid tombstone snapshot"))?;
            self.view(b)
                .validate()
                .map_err(|_| corrupt("invalid tombstone view"))?;
            if !self.manifest.is_empty()
                || !self.blobs.is_empty()
                || self.intent.is_some()
                || self.cancelled_at.is_none_or(|t| t > MAX_INTEGER)
                || self.directory.is_none()
                || self.blob_directory.is_none()
                || self.manifest_inode.is_none()
            {
                return Err(corrupt("invalid compact terminal record"));
            }
            return Ok(());
        }
        let declared = manifest(&self.snapshot, &self.manifest)
            .map_err(|_| corrupt("invalid retained manifest"))?;
        if declared.len() != self.blobs.len()
            || declared
                .iter()
                .zip(&self.blobs)
                .any(|(x, y)| x.digest != y.digest || x.size != y.size || y.offset > y.size)
            || charge(&self.manifest, &self.blobs)? != self.charge
        {
            return Err(corrupt("invalid record declarations or charge"));
        }
        self.view(b)
            .validate()
            .map_err(|_| corrupt("invalid record view"))?;
        match (&self.state, &self.intent) {
            (UploadState::Receiving, Some(Intent::Begin)) => {
                if self
                    .blobs
                    .iter()
                    .any(|x| x.offset != 0 || x.prefix != sha256(&[]))
                {
                    return Err(corrupt("invalid Begin progress"));
                }
            }
            (UploadState::Receiving, Some(Intent::Chunk(c))) => {
                let x = self
                    .blobs
                    .iter()
                    .find(|x| x.digest == c.blob)
                    .ok_or_else(|| corrupt("unknown chunk blob"))?;
                if c.old >= c.next
                    || c.next > x.size
                    || c.next - c.old > 65536
                    || !["writing", "ready", "cleanup"].contains(&c.phase.as_str())
                    || ((c.phase == "cleanup") && (x.offset != c.next))
                    || ((c.phase != "cleanup") && (x.offset != c.old || x.prefix != c.old_prefix))
                    || ((c.phase != "writing") && c.scratch.is_none())
                {
                    return Err(corrupt("invalid chunk intent"));
                }
            }
            (UploadState::Receiving, None | Some(Intent::Seal)) => {}
            (UploadState::Staged, None) => {}
            (UploadState::Cancelling, Some(Intent::Cleanup(_))) => {}
            (UploadState::Cancelled, None) => {}
            _ => return Err(corrupt("illegal state/intent")),
        }
        if self.cancelled_at.is_some() != (self.state == UploadState::Cancelled) {
            return Err(corrupt("invalid tombstone time"));
        }
        if !matches!(self.intent, Some(Intent::Begin))
            && (self.directory.is_none()
                || self.blob_directory.is_none()
                || self.manifest_inode.is_none()
                || self.blobs.iter().any(|x| x.inode.is_none()))
        {
            return Err(corrupt("missing original payload binding"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Transition {
    pub kind: String,
    pub id: Option<UploadId>,
    pub before: Option<Sha256Digest>,
    pub after: Option<Sha256Digest>,
    pub at: u64,
}
codec!(Transition{kind:String,id:Option<UploadId>,before:Option<Sha256Digest>,after:Option<Sha256Digest>,at:u64});
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ledger {
    pub schema_version: u64,
    pub binding: Binding,
    pub generation: u64,
    pub predecessor: Option<Sha256Digest>,
    pub transition: Transition,
    pub records: Vec<Record>,
}
codec!(Ledger{schema_version:u64,binding:Binding,generation:u64,predecessor:Option<Sha256Digest>,transition:Transition,records:Vec<Record>});
pub(super) fn checksum<T: CanonicalDto>(v: &T) -> Sha256Digest {
    sha256(&v.to_value().canonical_bytes())
}
pub(super) fn seal<T: CanonicalDto>(v: &T) -> Vec<u8> {
    Value::Object(BTreeMap::from([
        ("payload".into(), v.to_value()),
        ("checksum".into(), checksum(v).to_value()),
    ]))
    .canonical_bytes()
}
pub(super) fn unseal<T: CanonicalDto>(bytes: &[u8]) -> Result<T, TaskError> {
    let v = parse_canonical_json(bytes).map_err(|_| corrupt("invalid authority JSON"))?;
    if v.canonical_bytes() != bytes {
        return Err(corrupt("noncanonical authority"));
    }
    let Value::Object(mut f) = v else {
        return Err(corrupt("invalid authority envelope"));
    };
    let p = f
        .remove("payload")
        .ok_or_else(|| corrupt("missing authority payload"))?;
    let hash = Sha256Digest::from_value(
        f.remove("checksum")
            .ok_or_else(|| corrupt("missing checksum"))?,
    )
    .map_err(|_| corrupt("invalid checksum"))?;
    if !f.is_empty() || sha256(&p.canonical_bytes()) != hash {
        return Err(corrupt("authority checksum mismatch"));
    }
    T::from_value(p).map_err(|_| corrupt("invalid authority schema"))
}
pub(super) fn basename(d: &Sha256Digest) -> &str {
    &d.as_str()[7..]
}
pub(super) fn generated_id(id: &UploadId) -> bool {
    let s = id.as_str();
    s.len() == 69
        && s.starts_with("task-")
        && s[5..]
            .bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
pub(super) fn manifest(reference: &SnapshotRef, raw: &str) -> Result<Vec<Blob>, TaskError> {
    if raw.len() > 65536 || reference.file_count > 1024 || reference.total_bytes > 67108864 {
        return Err(TaskError::invalid("snapshot admission limit exceeded"));
    }
    let v = parse_canonical_json(raw.as_bytes())?;
    if v.canonical_bytes() != raw.as_bytes() {
        return Err(TaskError::invalid("manifest must be canonical JSON"));
    }
    let files = Vec::<SnapshotFile>::from_value(v)?;
    FrozenSnapshot {
        reference: reference.clone(),
        files: files.clone(),
    }
    .validate(sha256)?;
    let mut unique = BTreeMap::new();
    for f in files {
        if f.size_bytes == 0 && f.sha256 != sha256(&[]) {
            return Err(integrity("empty blob digest mismatch"));
        }
        if let Some(size) = unique.insert(f.sha256.clone(), f.size_bytes) {
            if size != f.size_bytes {
                return Err(integrity("same digest with different size"));
            }
        }
    }
    Ok(unique
        .into_iter()
        .map(|(digest, size)| Blob {
            digest,
            size,
            offset: 0,
            prefix: sha256(&[]),
            inode: None,
        })
        .collect())
}
pub(super) fn charge(raw: &str, blobs: &[Blob]) -> Result<u64, TaskError> {
    let a = |n: u64| -> Result<u64, TaskError> {
        if n == 0 {
            return Ok(0);
        }
        n.checked_add(4095)
            .and_then(|x| (x / 4096).checked_mul(4096))
            .filter(|x| *x <= MAX_INTEGER)
            .ok_or_else(|| TaskError::invalid("charge overflow"))
    };
    let mut n = 0u64;
    for x in blobs {
        n = n
            .checked_add(a(x.size)?)
            .ok_or_else(|| TaskError::invalid("charge overflow"))?
    }
    n.checked_mul(2)
        .and_then(|x| x.checked_add(2 * a(raw.len() as u64).ok()?))
        .and_then(|x| x.checked_add(2 * RECORD_LIMIT + 65536))
        .and_then(|x| x.checked_add(4096 * (blobs.len() as u64 + 6)))
        .filter(|x| *x <= MAX_INTEGER)
        .ok_or_else(|| TaskError::invalid("charge overflow"))
}
pub(super) fn future_ceiling(r: &Record) -> u64 {
    let mut maximal = r.clone();
    let id = io::NodeId {
        device: u64::MAX,
        inode: u64::MAX,
    };
    maximal.directory = Some(id);
    maximal.blob_directory = Some(id);
    maximal.manifest_inode = Some(id);
    maximal.state = UploadState::Cancelling;
    maximal.cancelled_at = Some(MAX_INTEGER);
    maximal.charge = MAX_INTEGER;
    maximal.ceiling = MAX_INTEGER;
    for b in &mut maximal.blobs {
        b.size = MAX_INTEGER;
        b.offset = MAX_INTEGER;
        b.inode = Some(id)
    }
    maximal.intent = Some(Intent::Cleanup(Cleanup {
        directories_durable: false,
    }));
    let mut cleanup = maximal.to_value();
    maximal_numbers(&mut cleanup);
    maximal.intent = Some(Intent::Chunk(Chunk {
        blob: sha256(&[]),
        old: MAX_INTEGER,
        next: MAX_INTEGER,
        old_prefix: sha256(&[]),
        hash: sha256(&[]),
        phase: "cleanup".into(),
        scratch: Some(id),
    }));
    let mut chunk = maximal.to_value();
    maximal_numbers(&mut chunk);
    cleanup
        .canonical_bytes()
        .len()
        .max(chunk.canonical_bytes().len()) as u64
        + 256
}

fn maximal_numbers(value: &mut Value) {
    match value {
        Value::Integer(n) => *n = i128::from(MAX_INTEGER),
        Value::Array(values) => {
            for v in values {
                maximal_numbers(v);
            }
        }
        Value::Object(fields) => {
            for v in fields.values_mut() {
                maximal_numbers(v);
            }
        }
        _ => {}
    }
}
