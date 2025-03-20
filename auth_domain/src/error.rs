use auth_data::AuthDataError;
use std::fmt;
use thiserror::Error;

/// Domain-specific authentication errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Entity not found")]
    NotFound,
    
    #[error("Username already exists")]
    DuplicateUsername,
    
    #[error("Contact is already used in other account")]
    ContactAlreadyUsed,
    
    #[error("Username already taken")]
    UsernameTaken,
    
    #[error("Email already taken")]
    EmailTaken,
    
    #[error("User not found")]
    UserNotFound,

    #[error("OTP error: {0}")]
    OtpError(#[from] OtpError),
    
    #[error("MongoDB error: {0}")]
    MongoError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),

    // Add new variants from service
    #[error("Invalid contact value")]
    InvalidContactValue,
    
    #[error("Invalid username")]
    InvalidUsername,
    
    #[error("Account is locked")]
    AccountLocked,
    
    #[error("Token has expired")]
    TokenExpired,
    
    #[error("Account has been deleted")]
    AccountDeleted,
    
    #[error("Invalid profile data")]
    InvalidProfileData,
    
    #[error("Cannot remove primary contact")]
    CannotRemovePrimaryContact,
    
    #[error("Contact is not verified")]
    ContactNotVerified,
    
    #[error("Token has been revoked")]
    TokenRevoked,
    
    #[error("Token creation error")]
    TokenCreationError,
    
    #[error("Action not permitted")]
    ActionNotPermitted,
    
    #[error("Account permanently deleted")]
    AccountPermanentlyDeleted,
    
    #[error("Data error")]
    DataError(#[from] AuthDataError),
    
    #[error("Unauthorized access")]
    Unauthorized,
    
    #[error("Contact not found")]
    ContactNotFound,

    #[error("Password error: {0}")]
    Password(#[from] PasswordError),

    #[error("Invalid credentials")]
    InvalidCredentials,
}

#[derive(Debug)]
pub enum OtpError {
    Invalid,
    Expired,
    MaxAttemptsReached,
}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtpError::Invalid => write!(f, "Invalid OTP"),
            OtpError::Expired => write!(f, "Expired OTP"),
            OtpError::MaxAttemptsReached => write!(f, "Maximum OTP attempts reached"),
        }
    }
}

impl std::error::Error for OtpError {}

#[derive(Debug)]
pub enum PasswordError {
    TooWeak,
    SameAsCurrent,
    PreviouslyUsed,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordError::TooWeak => write!(f, "Password does not meet strength requirements"),
            PasswordError::SameAsCurrent => write!(f, "New password must be different from current password"),
            PasswordError::PreviouslyUsed => write!(f, "Password has been used previously"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Result type for authentication operations
pub type AuthResult<T> = Result<T, AuthError>;
