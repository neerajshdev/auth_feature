use thiserror::Error;

pub type DataResult<T> = Result<T, AuthDataError>;

#[derive(Debug, Error)]
pub enum AuthDataError {
    
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
    
    #[error("OTP not found")]
    OtpNotFound,
    
    #[error("MongoDB error: {0}")]
    MongoError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("{0}")]
    NotFound(String),
}

impl From<mongodb::error::Error> for AuthDataError {
    fn from(err: mongodb::error::Error) -> Self {
        Self::MongoError(err.to_string())
    }
}

impl From<bson::ser::Error> for AuthDataError {
    fn from(err: bson::ser::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<bson::de::Error> for AuthDataError {
    fn from(err: bson::de::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
} 