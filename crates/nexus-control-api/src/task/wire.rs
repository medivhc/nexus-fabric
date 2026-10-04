use super::*;
impl CanonicalDto for TaskRequest {
    fn to_value(&self) -> Value {
        let mut fields = BTreeMap::from([("schema_version".into(), 1u64.to_value())]);
        let operation = match self {
            Self::Submit { request } => {
                fields.insert("request".into(), request.to_value());
                "SubmitTask"
            }
            Self::Get { task_id } => {
                fields.insert("task_id".into(), task_id.to_value());
                "GetTask"
            }
            Self::Cancel { task_id } => {
                fields.insert("task_id".into(), task_id.to_value());
                "CancelTask"
            }
            Self::ListArtifacts { task_id } => {
                fields.insert("task_id".into(), task_id.to_value());
                "ListTaskArtifacts"
            }
            Self::ReadLogs {
                task_id,
                stream,
                offset,
                max_bytes,
            } => {
                fields.extend([
                    ("task_id".into(), task_id.to_value()),
                    ("stream".into(), stream.to_value()),
                    ("offset".into(), offset.to_value()),
                    ("max_bytes".into(), max_bytes.to_value()),
                ]);
                "ReadTaskLogs"
            }
            Self::GetArtifact {
                artifact_id,
                offset,
                max_bytes,
            } => {
                fields.extend([
                    ("artifact_id".into(), artifact_id.to_value()),
                    ("offset".into(), offset.to_value()),
                    ("max_bytes".into(), max_bytes.to_value()),
                ]);
                "GetArtifact"
            }
        };
        fields.insert("operation".into(), operation.to_string().to_value());
        Value::Object(fields)
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let mut f = object(value)?;
        version(&mut f)?;
        let result = match take::<String>(&mut f, "operation")?.as_str() {
            "SubmitTask" => Self::Submit {
                request: Box::new(take(&mut f, "request")?),
            },
            "GetTask" => Self::Get {
                task_id: take(&mut f, "task_id")?,
            },
            "CancelTask" => Self::Cancel {
                task_id: take(&mut f, "task_id")?,
            },
            "ListTaskArtifacts" => Self::ListArtifacts {
                task_id: take(&mut f, "task_id")?,
            },
            "ReadTaskLogs" => Self::ReadLogs {
                task_id: take(&mut f, "task_id")?,
                stream: take(&mut f, "stream")?,
                offset: take(&mut f, "offset")?,
                max_bytes: take(&mut f, "max_bytes")?,
            },
            "GetArtifact" => Self::GetArtifact {
                artifact_id: take(&mut f, "artifact_id")?,
                offset: take(&mut f, "offset")?,
                max_bytes: take(&mut f, "max_bytes")?,
            },
            _ => return Err(TaskError::invalid("unknown task operation")),
        };
        end(&f)?;
        result.validate()?;
        Ok(result)
    }
}
macro_rules! record_codec {
    ($type:ty, {$($field:ident),+}) => {
        impl CanonicalDto for $type {
            fn to_value(&self) -> Value {
                Value::Object(BTreeMap::from([$( (stringify!($field).into(), self.$field.to_value()) ),+]))
            }
            fn from_value(value: Value) -> Result<Self, TaskError> {
                let mut f = object(value)?;
                let result = Self { $($field: take(&mut f, stringify!($field))?),+ };
                end(&f)?; result.validate()?; Ok(result)
            }
        }
    }
}
record_codec!(TaskLogsPage, {task_id, stream, offset, bytes, next_offset, eof, truncated});
record_codec!(TaskArtifactPage, {record, offset, bytes, next_offset, eof});
record_codec!(TaskArtifactList, {task_id, records});
impl CanonicalDto for TaskEnvelope {
    fn to_value(&self) -> Value {
        let mut f = BTreeMap::from([("schema_version".into(), 1u64.to_value())]);
        let verdict = match self {
            Self::Success(response) => {
                let (key, value) = match response {
                    TaskResponse::Task(v) => ("task", v.to_value()),
                    TaskResponse::Logs(v) => ("logs", v.to_value()),
                    TaskResponse::Artifacts(v) => ("artifact", v.to_value()),
                    TaskResponse::Artifact(v) => ("artifact", v.to_value()),
                };
                f.insert(key.into(), value);
                "PASS"
            }
            Self::Error { error, task_id } => {
                let mut e = match error.to_value() {
                    Value::Object(e) => e,
                    _ => unreachable!(),
                };
                e.insert("task_id".into(), task_id.to_value());
                f.insert("error".into(), Value::Object(e));
                "FAIL"
            }
        };
        f.insert("verdict".into(), verdict.to_string().to_value());
        Value::Object(f)
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let mut f = object(value)?;
        version(&mut f)?;
        let result = match take::<String>(&mut f, "verdict")?.as_str() {
            "PASS" => {
                let response = if let Some(v) = f.remove("task") {
                    TaskResponse::Task(Box::new(TaskView::from_value(v)?))
                } else if let Some(v) = f.remove("logs") {
                    TaskResponse::Logs(TaskLogsPage::from_value(v)?)
                } else if let Some(v) = f.remove("artifact") {
                    if let Value::Object(ref fields) = v {
                        if fields.contains_key("records") {
                            TaskResponse::Artifacts(TaskArtifactList::from_value(v)?)
                        } else {
                            TaskResponse::Artifact(Box::new(TaskArtifactPage::from_value(v)?))
                        }
                    } else {
                        return Err(TaskError::invalid("expected artifact object"));
                    }
                } else {
                    return Err(TaskError::invalid("missing success payload"));
                };
                Self::Success(response)
            }
            "FAIL" => {
                let mut e = object(
                    f.remove("error")
                        .ok_or_else(|| TaskError::invalid("missing error"))?,
                )?;
                let task_id = take(&mut e, "task_id")?;
                Self::Error {
                    error: TaskError::from_value(Value::Object(e))?,
                    task_id,
                }
            }
            _ => return Err(TaskError::invalid("verdict must be PASS or FAIL")),
        };
        end(&f)?;
        result.validate()?;
        Ok(result)
    }
}
