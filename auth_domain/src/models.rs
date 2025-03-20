use crate::error::AuthError;
use auth_data::entities::{ActionType, Contact, ContactType, Gender};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of login identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginIdentifierType {
    Username,
    Contact(ContactType),
}

/// Authentication result containing user profile and session token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,        // User ID
    pub exp: usize,         // Expiration timestamp
    pub iat: usize,         // Issued at timestamp
    pub iss: String,        // Issuer
    pub aud: String,        // Audience
    pub roles: Vec<String>, // User roles
    pub jti: String,        // Unique token identifier
}

/// Claims for action tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionClaims {
    pub sub: String,        // User ID
    pub action_type: ActionType,
    pub action_id: String,  // Action ID
    pub iat: i64,           // Issued at
    pub exp: i64,           // Expiration
    pub iss: String,        // Issuer
    pub aud: Vec<String>,   // Audience
    pub jti: String,        // Unique token identifier
}

/// Claims for challenge tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeClaims {
    pub sub: String,        // User ID or temporary ID
    pub action_type: ActionType,
    pub action_id: String,  // Action ID
    pub challenge_id: String,
    pub contact_value: Option<String>, // Optional contact value
    pub contact_type: ContactType,
    pub iat: i64,           // Issued at
    pub exp: i64,           // Expiration
    pub iss: String,        // Issuer
    pub aud: Vec<String>,   // Audience
    pub jti: String,        // Unique token identifier
}

/// Login data variants
#[derive(Debug, Clone)]
pub enum LoginData {
    Email(String, String),    // Email, Password
    Username(String, String), // Username, Password
    Phone(String, String),    // Phone, Password
}


#[derive(Debug, Clone)]
pub enum CheckUsernameResult {
    Valid,
    Invalid,
    AlreadyTaken,
}


/// Data for updating user profile
#[derive(Debug, Clone)]
pub struct ProfileUpdateData {
    pub fullname: Option<String>,
    pub profile_picture: Option<String>,
    pub gender: Option<Gender>,
    pub country: Option<String>,
    pub bio: Option<String>,
    pub birthdate: Option<DateTime<Utc>>,
}

/// Username validator
pub struct UsernameValidator;

impl UsernameValidator {
    /// Validate username format
    pub fn validate(username: &str) -> bool {
        if username.len() < 3 || username.len() > 30 {
            return false;
        }
        
        username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    }
}

/// Token types for JWT
#[derive(Debug, Serialize, Deserialize)]
pub enum TokenType {
    Access,
    Refresh,
    Challenge,
}

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug, Clone)]
pub struct SessionResult {
    pub user: User,
    pub session_token: String,
}


#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub fullname: String,
    pub birthdate: DateTime<Utc>,
    pub gender: Gender,
    pub country: Option<String>,
    pub bio: Option<String>,
    pub profile_picture: Option<String>,
    pub contacts: Vec<Contact>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}


#[derive(Debug, PartialEq)]
pub enum PasswordStrength {
    TooWeak,      // Doesn't meet minimum requirements
    Basic,        // Meets minimum requirements
    Strong,       // Good complexity
    VeryStrong,   // Excellent complexity
}