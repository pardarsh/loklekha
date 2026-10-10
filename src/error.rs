use pardarsh_core::validation::ValidationIssue;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("authentication required")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Also used for records the viewer may not see, so existence is not leaked.
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("too many requests")]
    RateLimited,
    #[error(transparent)]
    Core(#[from] pardarsh_core::Error),
}

impl AppError {
    pub fn validation_issues(&self) -> Option<&[ValidationIssue]> {
        match self {
            AppError::Core(pardarsh_core::Error::Validation(v)) => Some(&v.issues),
            _ => None,
        }
    }
}
