use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cedar policy error: {0}")]
    Cedar(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("policy parse error in {1}: {0}")]
    PolicyParse(String, String),

    #[error("schema error: {0}")]
    Schema(String),

    #[error("invalid principal: {0}")]
    InvalidPrincipal(String),

    #[error("invalid resource: {0}")]
    InvalidResource(String),

    #[error("invalid context: {0}")]
    InvalidContext(String),

    #[error("invalid delegation token: {0}")]
    InvalidToken(String),

    #[error("token expired at {0}")]
    TokenExpired(String),

    #[error("token signature invalid")]
    TokenSignatureInvalid,

    #[error("token not yet valid (nbf={0})")]
    TokenNotYetValid(String),

    #[error("policy validation failed: {0}")]
    Validation(String),

    #[error("entities: {0}")]
    Entities(String),

    #[error("walk: {0}")]
    Walk(String),

    #[error("other: {0}")]
    Other(String),
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Other(e.to_string())
    }
}