//! Strict bounded tar inventory; never extract untrusted names into host paths.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub(super) struct Entry<'a> {
    pub(super) kind: u8,
    pub(super) mode: u64,
    pub(super) bytes: &'a [u8],
}
pub(super) fn parse(bytes: &[u8]) -> Result<BTreeMap<String, Entry<'_>>, TaskError> {
    let mut files = BTreeMap::new();
    let mut offset = 0usize;
    let mut override_path: Option<String> = None;
    loop {
        let header = bytes
            .get(offset..offset + 512)
            .ok_or_else(|| corrupt("torn archive header"))?;
        offset += 512;
        if header.iter().all(|b| *b == 0) {
            if override_path.is_some()
                || bytes.len() - offset < 512
                || bytes[offset..].iter().any(|b| *b != 0)
            {
                return Err(corrupt("invalid archive terminator"));
            }
            break;
        }
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        if octal(&header[148..156])? != sum {
            return Err(corrupt("archive checksum mismatch"));
        }
        let size = usize::try_from(octal(&header[124..136])?)
            .map_err(|_| corrupt("oversized archive member"))?;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| corrupt("archive size overflow"))?;
        let data = bytes
            .get(offset..end)
            .ok_or_else(|| corrupt("torn archive member"))?;
        offset = end
            .checked_add((512 - size % 512) % 512)
            .filter(|n| *n <= bytes.len())
            .ok_or_else(|| corrupt("torn archive padding"))?;
        let kind = header[156];
        if kind == b'L' {
            if override_path.is_some() || data.len() > 4097 {
                return Err(corrupt("invalid GNU archive path"));
            }
            override_path = Some(text(data)?);
            continue;
        }
        if kind == b'K' {
            if data.len() > 4097 {
                return Err(corrupt("oversized GNU link"));
            }
            continue;
        }
        if kind == b'x' {
            if override_path.is_some() || size > 16384 {
                return Err(corrupt("invalid extended archive header"));
            }
            let mut left = data;
            let mut seen = BTreeSet::new();
            while !left.is_empty() {
                let space = left
                    .iter()
                    .position(|b| *b == b' ')
                    .ok_or_else(|| corrupt("invalid PAX length"))?;
                let n = std::str::from_utf8(&left[..space])
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .filter(|n| *n > space + 2 && *n <= left.len())
                    .ok_or_else(|| corrupt("invalid PAX record"))?;
                let record = &left[space + 1..n];
                if record.last() != Some(&b'\n') {
                    return Err(corrupt("invalid PAX terminator"));
                }
                let text = std::str::from_utf8(&record[..record.len() - 1])
                    .map_err(|_| corrupt("invalid PAX UTF-8"))?;
                let (key, value) = text
                    .split_once('=')
                    .ok_or_else(|| corrupt("invalid PAX field"))?;
                if !seen.insert(key.to_owned()) {
                    return Err(corrupt("duplicate PAX field"));
                }
                match key {
                    "path" => override_path = Some(value.into()),
                    "mtime" | "atime" | "ctime" | "uid" | "gid" | "uname" | "gname"
                    | "linkpath" => {}
                    _ => return Err(corrupt("unsupported archive extension")),
                }
                left = &left[n..];
            }
            continue;
        }
        let name = if let Some(path) = override_path.take() {
            path
        } else {
            let name = text(&header[..100])?;
            let prefix = text(&header[345..500])?;
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        };
        let name = if kind == b'5' {
            name.strip_suffix('/').unwrap_or(&name).to_owned()
        } else {
            name
        };
        if name == "work" && kind == b'5' {
            continue;
        }
        let relative = name
            .strip_prefix("work/")
            .ok_or_else(|| corrupt("archive escaped working root"))?;
        relative_path(relative)?;
        if files.len() >= 65536
            || files
                .insert(
                    relative.to_owned(),
                    Entry {
                        kind,
                        mode: octal(&header[100..108])?,
                        bytes: data,
                    },
                )
                .is_some()
        {
            return Err(corrupt("duplicate or oversized archive inventory"));
        }
    }
    Ok(files)
}
pub(super) fn regular<'a>(
    entries: &'a BTreeMap<String, Entry<'a>>,
    name: &str,
) -> Result<&'a Entry<'a>, TaskError> {
    relative_path(name)?;
    let mut parent = Path::new(name).parent();
    while let Some(path) = parent {
        if path.as_os_str().is_empty() {
            break;
        }
        let path = path
            .to_str()
            .ok_or_else(|| corrupt("invalid archive directory"))?;
        if entries.get(path).is_none_or(|e| e.kind != b'5') {
            return Err(TaskError::new(
                TaskErrorCode::InvalidPath,
                "non-directory or link in output parent",
                false,
            ));
        }
        parent = Path::new(path).parent();
    }
    let entry = entries.get(name).ok_or_else(|| {
        TaskError::new(
            TaskErrorCode::ArtifactMissing,
            "declared output absent",
            false,
        )
    })?;
    if ![0, b'0'].contains(&entry.kind) {
        return Err(TaskError::new(
            TaskErrorCode::InvalidPath,
            "nonregular archive member",
            false,
        ));
    }
    Ok(entry)
}
fn text(bytes: &[u8]) -> Result<String, TaskError> {
    let n = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..n])
        .map(str::to_owned)
        .map_err(|_| corrupt("archive names must be UTF-8"))
}
fn octal(bytes: &[u8]) -> Result<u64, TaskError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| corrupt("invalid archive integer"))?
        .trim_matches(['\0', ' ']);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| corrupt("invalid archive integer"))
}
