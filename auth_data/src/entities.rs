//! Database entities for authentication

use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::str::FromStr;
use bson::Bson;
use bson::doc;
use chrono::{DateTime, Utc};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum Gender {
    Male = 1,
    Female = 2,
    Other = 3,
}

impl Default for Gender {
    fn default() -> Self {
        Self::Other
    }
}

/// Contact type enum
#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum ContactType {
    #[default]
    Email,
    Phone,
}

impl Display for ContactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContactType::Email => write!(f, "Email"),
            ContactType::Phone => write!(f, "Phone"),
        }
    }
}

/// Contact information
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Contact {
    pub contact_type: ContactType,
    pub contact_value: String,
    pub is_primary: Option<bool>,
    pub verified_at: Option<DateTime<Utc>>,
    pub verification_token: Option<String>,
} 

impl Contact {
    pub fn new(contact_type: ContactType, value: String, is_primary: bool) -> Self {
        Self {
            contact_type,
            contact_value: value,
            is_primary: Some(is_primary),
            verified_at: None,
            verification_token: None,
        }
    }
}

/// Resolve the primary contact from a list of contacts
pub fn resolve_primary_contact(contacts: &Vec<Contact>) -> Option<Contact> {
    for contact in contacts {
        if contact.is_primary.unwrap_or(false) {
            return Some(contact.clone());   
        }
    }

    contacts.first().cloned()
}

/// User entity for MongoDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntity {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub username: String,
    pub fullname: String,
    pub salted_hash: SaltedHash,
    pub birthdate: DateTime<Utc>,
    pub gender: Gender,
    pub country: Option<String>,
    pub bio: Option<String>,
    pub profile_picture: Option<String>,
    pub contacts: Vec<Contact>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub password_last_changed: Option<DateTime<Utc>>,
    pub deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    pub roles: Vec<String>,
    pub failed_login_attempts: Option<u32>,
    pub salted_hash_history: Option<Vec<SaltedHash>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltedHash {
    pub hash: String,
    pub salt: String,
}

impl From<SaltedHash> for Bson {
    fn from(sh: SaltedHash) -> Bson {
        Bson::Document(doc! {
            "hash": sh.hash,
            "salt": sh.salt
        })
    }
}

impl UserEntity {
    pub fn new(
        username: String,
        salted_hash: SaltedHash,
        fullname: String,
        birthdate: DateTime<Utc>,
        gender: Gender,
        country: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            username,
            salted_hash,
            fullname,
            birthdate,
            gender,
            country,
            bio: None,
            profile_picture: None,
            contacts: Vec::new(),
            created_at: now,
            updated_at: now,
            password_last_changed: Some(now),
            deleted: false,
            deleted_at: None,
            roles: vec!["viewer".to_string()],
            failed_login_attempts: None,
            salted_hash_history: None,
        }
    }
}

/// OTP entity for email verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpEntity {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub contact: Contact,
    pub otp_code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verified: bool,
    pub attempts: u32,
}

/// User creation data for repository
#[derive(Debug, Clone)]
pub struct UserCreationData {
    pub username: String,
    pub fullname: String,
    pub password: String,
    pub contact_type: Option<ContactType>,
    pub contact_value: Option<String>,
    pub country: Option<String>,
    pub birthdate: DateTime<Utc>,
    pub gender: Gender,
    pub roles: Vec<String>,
}


/// Action types for OTP challenges
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum ActionType {
    Registration,
    PasswordReset,
    DeleteAccount,
    AddContact,
}

impl Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::Registration => write!(f, "Registration"),
            ActionType::PasswordReset => write!(f, "PasswordReset"),
            ActionType::DeleteAccount => write!(f, "DeleteAccount"),
            ActionType::AddContact => write!(f, "AddContact"),
        }
    }
}

impl FromStr for ActionType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Registration" => Ok(ActionType::Registration),
            "PasswordReset" => Ok(ActionType::PasswordReset),
            "DeleteAccount" => Ok(ActionType::DeleteAccount),
            "AddContact" => Ok(ActionType::AddContact),
            _ => Err(()),
        }
    }
}
