use kavach_domain::Decision;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchRowStatus {
    Ok,
    ValidationError,
    EvidenceError,
    ParseError,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchResultRow {
    pub line_number: usize,
    pub correlation_id: String,
    pub status: BatchRowStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_hits: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BatchResultRow {
    pub fn write_ndjson_line<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        serde_json::to_writer(&mut *writer, self)?;
        writer.write_all(b"\n")?;
        Ok(())
    }
}
