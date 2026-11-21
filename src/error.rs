//! Machine-readable error codes shared across the CLI / Python / wasm
//! outlets. Hosts (desktop / GUI / web) use the stable `code` + `category`
//! pair for programmatic handling instead of parsing human text.

use std::fmt;

/// Stable error categories returned to hosts. Keep the string forms in
/// `as_str` stable: bump `dpa-wasm`'s schema version whenever a code is
/// added, removed, or renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UnknownOp,
    InputTooLarge,
    ParseFlowFailed,
    EmptySteps,
    InvalidOutputFormat,
    OutputNotUtf8,
    JsonParseFailed,
    YamlParseFailed,
    InvalidArg,
    RunFailed,
    /// Execution exceeded the configured `EngineConfig.timeout` window.
    Timeout,
    /// Execution was cancelled through the `EngineConfig.cancel` flag.
    Cancelled,
    Internal,
}

impl ErrorCode {
    /// Stable machine-readable code string.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownOp => "UNKNOWN_OP",
            ErrorCode::InputTooLarge => "INPUT_TOO_LARGE",
            ErrorCode::ParseFlowFailed => "PARSE_FLOW_FAILED",
            ErrorCode::EmptySteps => "EMPTY_STEPS",
            ErrorCode::InvalidOutputFormat => "INVALID_OUTPUT_FORMAT",
            ErrorCode::OutputNotUtf8 => "OUTPUT_NOT_UTF8",
            ErrorCode::JsonParseFailed => "JSON_PARSE_FAILED",
            ErrorCode::YamlParseFailed => "YAML_PARSE_FAILED",
            ErrorCode::InvalidArg => "INVALID_ARG",
            ErrorCode::RunFailed => "RUN_FAILED",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::Cancelled => "CANCELLED",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    /// Coarse category used for host-side grouping / hint routing.
    pub fn category(self) -> &'static str {
        match self {
            ErrorCode::UnknownOp | ErrorCode::InvalidArg | ErrorCode::InvalidOutputFormat => {
                "input"
            }
            ErrorCode::InputTooLarge => "limit",
            ErrorCode::ParseFlowFailed | ErrorCode::EmptySteps => "flow",
            ErrorCode::OutputNotUtf8 | ErrorCode::JsonParseFailed | ErrorCode::YamlParseFailed => {
                "output"
            }
            ErrorCode::RunFailed | ErrorCode::Timeout | ErrorCode::Cancelled => "run",
            ErrorCode::Internal => "internal",
        }
    }
}

/// Error carrying a stable machine-readable code.
#[derive(Debug)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

/// Build an anyhow error tagged with a stable code.
pub fn coded(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ApiError {
        code,
        message: message.into(),
    })
}

/// Extract the stable code from an error chain; `RunFailed` when untagged.
pub fn extract_code(err: &anyhow::Error) -> ErrorCode {
    err.downcast_ref::<ApiError>()
        .map(|a| a.code)
        .unwrap_or(ErrorCode::RunFailed)
}

/// Serialize an error to the host-facing `{code, category, message}` shape.
pub fn to_json(err: &anyhow::Error) -> serde_json::Value {
    let code = extract_code(err);
    serde_json::json!({
        "code": code.as_str(),
        "category": code.category(),
        "message": format!("{err:#}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_strings_are_stable() {
        assert_eq!(ErrorCode::UnknownOp.as_str(), "UNKNOWN_OP");
        assert_eq!(ErrorCode::InputTooLarge.as_str(), "INPUT_TOO_LARGE");
        assert_eq!(ErrorCode::ParseFlowFailed.as_str(), "PARSE_FLOW_FAILED");
        assert_eq!(ErrorCode::EmptySteps.as_str(), "EMPTY_STEPS");
        assert_eq!(
            ErrorCode::InvalidOutputFormat.as_str(),
            "INVALID_OUTPUT_FORMAT"
        );
        assert_eq!(ErrorCode::OutputNotUtf8.as_str(), "OUTPUT_NOT_UTF8");
        assert_eq!(ErrorCode::JsonParseFailed.as_str(), "JSON_PARSE_FAILED");
        assert_eq!(ErrorCode::YamlParseFailed.as_str(), "YAML_PARSE_FAILED");
        assert_eq!(ErrorCode::InvalidArg.as_str(), "INVALID_ARG");
        assert_eq!(ErrorCode::RunFailed.as_str(), "RUN_FAILED");
        assert_eq!(ErrorCode::Timeout.as_str(), "TIMEOUT");
        assert_eq!(ErrorCode::Cancelled.as_str(), "CANCELLED");
        assert_eq!(ErrorCode::Internal.as_str(), "INTERNAL");
    }

    #[test]
    fn coded_error_extracts_back() {
        let e = coded(ErrorCode::UnknownOp, "unknown op: dpa:nope");
        assert_eq!(extract_code(&e), ErrorCode::UnknownOp);
    }

    #[test]
    fn untagged_error_falls_back_to_run_failed() {
        let e = anyhow::anyhow!("boom");
        assert_eq!(extract_code(&e), ErrorCode::RunFailed);
    }

    #[test]
    fn to_json_has_expected_shape() {
        let e = coded(ErrorCode::JsonParseFailed, "json parse failed");
        let v = to_json(&e);
        assert_eq!(v["code"], "JSON_PARSE_FAILED");
        assert_eq!(v["category"], "output");
        assert!(v["message"].as_str().unwrap().contains("json parse"));
    }
}
