//! Error messages for the data layer

use thiserror::Error;

/// Error type for data operations
#[derive(Debug, Error)]
pub enum DataError {
    #[error("Database error: {0}")]
    Database(#[from] mongodb::error::Error),
    
    #[error("BSON serialization error: {0}")]
    Bson(#[from] bson::ser::Error),
    
    #[error("BSON deserialization error: {0}")]
    BsonDe(#[from] bson::de::Error),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Username is already taken")]
    UsernameTaken,
    
    #[error("Email is already in use")]
    EmailTaken,
    
    #[error("OTP not found or expired")]
    OtpNotFound,
    
    #[error("Invalid OTP")]
    InvalidOtp,
    
    #[error("Entity conversion error: {0}")]
    ConversionError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type for data operations
pub type DataResult<T> = Result<T, DataError>; 