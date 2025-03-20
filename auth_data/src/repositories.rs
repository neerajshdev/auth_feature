//! Repository implementations for authentication data access

use crate::entities::{Contact, ContactType, Gender, OtpEntity, UserCreationData, UserEntity};
use crate::error::AuthDataError;
use crate::SaltedHash;
use async_trait::async_trait;
use bson::{doc, oid::ObjectId};
use chrono::Utc;
use mongodb::bson::Document;
use mongodb::options::ClientOptions;
use mongodb::Client;
use mongodb::{Collection, Database};
use std::sync::Arc;
use tokio::sync::RwLock;
use bson::Bson;

/// User repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Find a user by ID
    async fn find_by_id(&self, id: &ObjectId) -> Result<Option<UserEntity>, AuthDataError>;

    /// Find a user by username
    async fn find_by_username(&self, username: &str) -> Result<Option<UserEntity>, AuthDataError>;

    /// Find a user by username or email (for login)
    async fn find_by_username_or_email(
        &self,
        username_or_email: &str,
    ) -> Result<Option<UserEntity>, AuthDataError>;

    /// Create a new user
    async fn create_user(
        &self,
        user_data: UserCreationData,
        password_hash: String,
        password_salt: String,
    ) -> Result<UserEntity, AuthDataError>;

    /// Save a user
    async fn save(&self, user: &UserEntity) -> Result<(), AuthDataError>;

    /// Delete a user
    async fn delete_user(&self, id: &ObjectId) -> Result<bool, AuthDataError>;

    /// Add contact to user
    async fn add_contact(
        &self,
        user_id: &ObjectId,
        contact: Contact,
    ) -> Result<bool, AuthDataError>;

    /// Update contact
    async fn update_contact(
        &self,
        user_id: &ObjectId,
        contact_value: &str,
        updated_contact: Contact,
    ) -> Result<bool, AuthDataError>;

    /// Remove contact
    async fn remove_contact(
        &self,
        user_id: &ObjectId,
        contact_value: &str,
    ) -> Result<bool, AuthDataError>;

    /// Update primary contact for a user
    /// Sets the specified contact as primary and ensures only one contact of that type is primary
    async fn update_primary_contact(
        &self,
        user_id: &ObjectId,
        contact_type: ContactType,
        contact_value: &str,
    ) -> Result<bool, AuthDataError>;

    /// Check if username exists
    async fn username_exists(&self, username: &str) -> Result<bool, AuthDataError>;

    /// Check if email exists
    async fn email_exists(&self, email: &str) -> Result<bool, AuthDataError>;

    /// Find a user by contact information
    async fn find_by_contact(
        &self,
        contact_type: ContactType,
        contact_value: &str,
    ) -> Result<Option<UserEntity>, AuthDataError>;

    /// Update password and add old password to history
    async fn update_password_and_salted_hash_history(
        &self,
        user_id: &ObjectId,
        new_salted_hash: SaltedHash,
        old_salted_hash: SaltedHash,
    ) -> Result<bool, AuthDataError>;

    /// Restore a user
    async fn restore_user(&self, id: &ObjectId) -> Result<bool, AuthDataError>;

    /// Add role to user
    async fn add_role(&self, user_id: &ObjectId, role: &str) -> Result<bool, AuthDataError>;

    /// Remove role from user
    async fn remove_role(&self, user_id: &ObjectId, role: &str) -> Result<bool, AuthDataError>;

    /// Get user roles
    async fn get_roles(&self, user_id: &ObjectId) -> Result<Vec<String>, AuthDataError>;

    /// Get failed login attempts for a user
    async fn get_failed_login_attempts(&self, user_id: &ObjectId) -> Result<u32, AuthDataError>;

    /// Get password history for a user
    async fn get_salted_hash_history(&self, user_id: &ObjectId) -> Result<Vec<SaltedHash>, AuthDataError>;

    /// Reset failed login attempts for a user
    async fn reset_failed_login_attempts(&self, user_id: &ObjectId) -> Result<(), AuthDataError>;

    /// Unlock user account
    async fn unlock_account(&self, user_id: &ObjectId) -> Result<(), AuthDataError>;

    /// Update user entity
    async fn update(&self, user: &UserEntity) -> Result<(), AuthDataError>;

    /// Mark a contact as verified for a user
    async fn mark_contact_as_verified(
        &self,
        user_id: &ObjectId,
        jti: &str,
    ) -> Result<(), AuthDataError>;
}

/// OTP repository trait
#[async_trait]
pub trait OtpRepository: Send + Sync {
    /// Create a new OTP
    async fn create_otp(&self, contact: Contact, code: &str) -> Result<OtpEntity, AuthDataError>;

    /// Find OTP by contact
    async fn find_otp_by_contact(
        &self,
        contact_type: ContactType,
        contact_value: &str,
    ) -> Result<Option<OtpEntity>, AuthDataError>;

    /// Find OTP challenge by ID
    async fn find_otp_by_id(&self, id: &str) -> Result<OtpEntity, AuthDataError>;

    /// Save OTP challenge
    async fn save_otp(&self, challenge: OtpEntity) -> Result<(), AuthDataError>;

    /// Update OTP challenge
    async fn update_otp(&self, challenge: OtpEntity) -> Result<(), AuthDataError>;

    /// Verify OTP
    async fn verify_otp(
        &self,
        contact_type: ContactType,
        contact_value: &str,
        code: &str,
    ) -> Result<bool, AuthDataError>;

    /// Mark OTP as verified
    async fn mark_otp_verified(&self, id: &str) -> Result<bool, AuthDataError>;

    /// Delete expired OTPs
    async fn delete_expired_otps(&self) -> Result<(), AuthDataError>;
}

/// Data for updating user profile
#[derive(Debug, Clone)]
pub struct UserProfileUpdate {
    pub fullname: Option<String>,
    pub profile_picture: Option<String>,
    pub gender: Option<Gender>,
    pub country: Option<String>,
    pub bio: Option<String>,
    pub birthdate: Option<chrono::DateTime<chrono::Utc>>,
}

/// MongoDB implementation of UserRepository
pub struct MongoUserRepository {
    db: Arc<RwLock<Database>>,
    collection_name: String,
}

impl MongoUserRepository {
    /// Create a new MongoDB user repository
    pub fn new(db: Arc<RwLock<Database>>, collection_name: String) -> Self {
        Self {
            db,
            collection_name,
        }
    }

    /// Get the users collection
    async fn collection(&self) -> Collection<UserEntity> {
        self.db.read().await.collection(&self.collection_name)
    }
}

#[async_trait]
impl UserRepository for MongoUserRepository {
    async fn find_by_id(&self, id: &ObjectId) -> Result<Option<UserEntity>, AuthDataError> {
        let filter = doc! { "_id": id };
        let coll = self.collection().await;
        let result = coll.find_one(filter).await?;
        Ok(result)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<UserEntity>, AuthDataError> {
        let filter = doc! { 
            "username": username, 
            "deleted": false 
        };
        let coll = self.collection().await;
        let result = coll.find_one(filter).await?;
        Ok(result)
    }

    async fn find_by_username_or_email(
        &self,
        username_or_email: &str,
    ) -> Result<Option<UserEntity>, AuthDataError> {
        let filter = doc! {
            "$or": [
                { "username": username_or_email },
                { "email": username_or_email }
            ],
            "deleted": false
        };
        let coll = self.collection().await;
        let result = coll.find_one(filter).await?;

        Ok(result)
    }

    async fn create_user(
        &self,
        user_data: UserCreationData,
        password_hash: String,
        password_salt: String,
    ) -> Result<UserEntity, AuthDataError> {
        let now = Utc::now().into();
        let id = ObjectId::new();

        let contact = Contact {
            contact_type: user_data.contact_type.unwrap(),
            contact_value: user_data.contact_value.unwrap(),
            is_primary: Some(true),
            verified_at: Some(now),
            verification_token: None,
        };

        let user = UserEntity {
            id: Some(id),
            username: user_data.username.clone(),
            fullname: user_data.fullname.clone(),
            salted_hash: SaltedHash {
                hash: password_hash,
                salt: password_salt,
            },
            birthdate: user_data.birthdate,
            gender: user_data.gender,
            country: user_data.country.clone(),
            bio: None,
            profile_picture: None,
            contacts: vec![contact],
            created_at: now,
            updated_at: now,
            password_last_changed: Some(now),
            deleted: false,
            deleted_at: None,
            roles: vec!["viewer".to_string()],
            failed_login_attempts: Some(0),
            salted_hash_history: Some(Vec::new()),
        };

        let collection = self.collection().await;
        collection.insert_one(user.clone()).await?;

        Ok(user)
    }

    async fn save(&self, user: &UserEntity) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        collection.insert_one(user.clone()).await?;
        Ok(())
    }

    async fn delete_user(&self, id: &ObjectId) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": id };


        tracing::info!("Soft Deleting user with id: {}", id);

        let update = doc! {
            "$set": {
                "deleted": true,
                "deleted_at": Utc::now()
            }
        };

        let result = collection.update_one(filter, update).await?;

        if result.modified_count == 0 {
            return Err(AuthDataError::UserNotFound);
        }

        tracing::info!("User soft deleted with id: {}", id);

        Ok(result.modified_count > 0)
    }

    async fn add_contact(
        &self,
        user_id: &ObjectId,
        contact: Contact,
    ) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;

        let filter = doc! {
            "_id": user_id,
            "contacts": {
                "$elemMatch": {
                    "value": &contact.contact_value
                }
            }
        };

        let exists = collection.find_one(filter).await?.is_some();
        if exists {
            return Err(AuthDataError::InternalError(
                "Contact already exists".to_string(),
            ));
        }

        if contact.is_primary.unwrap_or(false) {
            let filter = doc! {
                "_id": user_id,
                "contacts.contact_type": bson::to_bson(&contact.contact_type)?
            };

            let update = doc! {
                "$set": { "contacts.$.is_primary": false }
            };

            let options = mongodb::options::UpdateOptions::builder()
                .array_filters(vec![
                    doc! { "elem.contact_type": bson::to_bson(&contact.contact_type)? },
                ])
                .build();

            let _ = collection
                .update_one(filter, update)
                .with_options(options)
                .await?;
        }

        let filter = doc! { "_id": user_id };
        let contact_bson = bson::to_bson(&contact)?;
        let update = doc! { "$push": { "contacts": contact_bson } };

        let result = collection.update_one(filter, update).await?;

        Ok(result.modified_count > 0)
    }

    async fn update_contact(
        &self,
        user_id: &ObjectId,
        contact_value: &str,
        updated_contact: Contact,
    ) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;

        if updated_contact.is_primary.unwrap_or(false) {
            let filter = doc! {
                "_id": user_id,
                "contacts": {
                    "$elemMatch": {
                        "contact_type": updated_contact.contact_type.to_string(),
                        "is_primary": true,
                        "contact_value": { "$ne": contact_value }
                    }
                }
            };

            let update = doc! {
                "$set": { "contacts.$.is_primary": false }
            };

            let _ = collection.update_one(filter, update).await?;
        }

        let filter = doc! {
            "_id": user_id,
            "contacts": {
                "$elemMatch": {
                    "contact_value": contact_value
                }
            }
        };

        let update = doc! {
            "$set": {
                "contacts.$.contact_type": updated_contact.contact_type.to_string(),
                "contacts.$.value": updated_contact.contact_value,
                "contacts.$.verified_at": updated_contact.verified_at,
                "contacts.$.is_primary": updated_contact.is_primary,
            }
        };

        let result = collection.update_one(filter, update).await?;

        Ok(result.modified_count > 0)
    }

    async fn remove_contact(
        &self,
        user_id: &ObjectId,
        contact_value: &str,
    ) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;

        let filter = doc! { "_id": user_id };
        let update = doc! {
            "$pull": {
                "contacts": {
                    "contact_value": contact_value
                }
            }
        };

        let result = collection.update_one(filter, update).await?;

        Ok(result.modified_count > 0)
    }

    async fn update_primary_contact(
        &self,
        user_id: &ObjectId,
        contact_type: ContactType,
        contact_value: &str,
    ) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;

        // First, unset any existing primary contacts of the same type
        let filter = doc! {
            "_id": user_id,
            "contacts": {
                "$elemMatch": {
                    "contact_type": contact_type.to_string(),
                    "is_primary": true
                }
            }
        };

        let update = doc! {
            "$set": { "contacts.$.is_primary": false }
        };

        let _ = collection.update_one(filter, update).await?;

        // Now set the specified contact as primary
        let filter = doc! {
            "_id": user_id,
            "contacts": {
                "$elemMatch": {
                    "contact_type": contact_type.to_string(),
                    "contact_value": contact_value
                }
            }
        };

        let update = doc! {
            "$set": { "contacts.$.is_primary": true }
        };

        let result = collection.update_one(filter, update).await?;

        Ok(result.modified_count > 0)
    }

    async fn username_exists(&self, username: &str) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "username": username };

        let count = collection.count_documents(filter).await?;
        Ok(count > 0)
    }

    async fn email_exists(&self, email: &str) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "email": email };

        let count = collection.count_documents(filter).await?;
        Ok(count > 0)
    }

    async fn find_by_contact(
        &self,
        contact_type: ContactType,
        contact_value: &str,
    ) -> Result<Option<UserEntity>, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! {
            "contacts": {
                "$elemMatch": {
                    "contact_type": contact_type.to_string(),
                    "contact_value": contact_value
                }
            }
        };

        let result = collection.find_one(filter).await?;
        Ok(result)
    }

    async fn update_password_and_salted_hash_history(
        &self,
        user_id: &ObjectId,
        new_salted_hash: SaltedHash,
        old_salted_hash: SaltedHash,
    ) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };

        let update = doc! {
            "$set": {
                "salted_hash": Bson::from(new_salted_hash),
                "password_last_changed": Utc::now()
            },
            "$push": {
                "salted_hash_history": {
                    "$each": [Bson::from(old_salted_hash)],
                    "$slice": -5 // Keep only the last 5 passwords
                }
            }
        };

        let result = collection.update_one(filter, update).await?;
        Ok(result.modified_count > 0)
    }

    async fn restore_user(&self, id: &ObjectId) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": id, "deleted": true };
        let update = doc! {
            "$set": {
                "deleted": false,
                "deleted_at": null
            }
        };

        let result = collection.update_one(filter, update).await?;

        if result.modified_count == 0 {
            return Err(AuthDataError::UserNotFound);
        }

        Ok(result.modified_count > 0)
    }

    async fn add_role(&self, user_id: &ObjectId, role: &str) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };
        let update = doc! { "$addToSet": { "roles": role } };

        let result = collection.update_one(filter, update).await?;
        Ok(result.modified_count > 0)
    }

    async fn remove_role(&self, user_id: &ObjectId, role: &str) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };
        let update = doc! { "$pull": { "roles": role } };

        let result = collection.update_one(filter, update).await?;
        Ok(result.modified_count > 0)
    }

    async fn get_roles(&self, user_id: &ObjectId) -> Result<Vec<String>, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };

        let document_collection: Collection<Document> = collection.clone_with_type();
        let user_doc = document_collection
            .find_one(filter)
            .projection(doc! { "roles": 1 })
            .await?
            .ok_or(AuthDataError::UserNotFound)?;

        // Extract roles from the document
        let roles = user_doc
            .get_array("roles")
            .map_err(|e| AuthDataError::InternalError(format!("Failed to get roles: {}", e)))?;

        let roles: Vec<String> = roles
            .into_iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        Ok(roles)
    }

    async fn get_failed_login_attempts(&self, user_id: &ObjectId) -> Result<u32, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };

        // Use document collection for projection
        let document_collection: Collection<Document> = collection.clone_with_type();
        let user_doc = document_collection
            .find_one(filter)
            .projection(doc! { "failed_login_attempts": 1 })
            .await?
            .ok_or(AuthDataError::UserNotFound)?;

        // Extract failed_login_attempts from the document
        let attempts = user_doc
            .get_i32("failed_login_attempts")
            .map(|v| v as u32)
            .unwrap_or(0);

        Ok(attempts)
    }

    async fn get_salted_hash_history(&self, user_id: &ObjectId) -> Result<Vec<SaltedHash>, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };

        let document_collection: Collection<Document> = collection.clone_with_type();
        let user_doc = document_collection
            .find_one(filter)
            .projection(doc! { "salted_hash_history": 1 })
            .await?
            .ok_or(AuthDataError::UserNotFound)?;

        let history = user_doc
            .get_array("salted_hash_history")
            .map(|arr| {
                arr.into_iter()
                    .filter_map(|v| bson::from_bson(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_else(|_| Vec::new());

        Ok(history)
    }

    async fn reset_failed_login_attempts(&self, user_id: &ObjectId) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };
        let update = doc! { "$set": { "failed_login_attempts": 0 } };
        
        collection.update_one(filter, update).await?;
        Ok(())
    }

    async fn unlock_account(&self, user_id: &ObjectId) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": user_id };
        let update = doc! { 
            "$set": { 
                "failed_login_attempts": 0,
                "locked_until": null  // If you have a lock expiration field
            } 
        };
        
        collection.update_one(filter, update).await?;
        Ok(())
    }

    async fn update(&self, user: &UserEntity) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        let id = user.id.clone().ok_or(AuthDataError::UserNotFound)?;
        let filter = doc! { "_id": id };
        collection.replace_one(filter, user.clone()).await?;
        Ok(())
    }

    async fn mark_contact_as_verified(
        &self,
        user_id: &ObjectId,
        jti: &str,
    ) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! {
            "_id": user_id,
            "contacts.verification_token": jti
        };

        let update = doc! {
            "$set": {
                "contacts.$.verified_at": bson::DateTime::now(),
            }, 
            "$unset": {
                "contacts.$.verification_token": 1
            }
        };

        let result = collection
            .update_one(filter, update)
            .await
            .map_err(|e| AuthDataError::MongoError(e.to_string()))?;

        if result.matched_count == 0 {
            return Err(AuthDataError::NotFound("Contact not found".to_string()));
        }

        Ok(())
    }
}

/// MongoDB implementation of OtpRepository
pub struct MongoOtpRepository {
    db: Arc<RwLock<Database>>,
    collection_name: String,
}

impl MongoOtpRepository {
    /// Create a new MongoDB OTP repository
    pub fn new(db: Arc<RwLock<Database>>, collection_name: String) -> Self {
        Self {
            db,
            collection_name,
        }
    }

    /// Get the OTP collection
    async fn collection(&self) -> Collection<OtpEntity> {
        self.db.read().await.collection(&self.collection_name)
    }
}

#[async_trait]
impl OtpRepository for MongoOtpRepository {
    async fn create_otp(&self, contact: Contact, code: &str) -> Result<OtpEntity, AuthDataError> {
        let collection = self.collection().await;

        let id = ObjectId::new();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(10);

        let otp = OtpEntity {
            id,
            contact,
            otp_code: code.to_string(),
            created_at: now.into(),
            expires_at: expires_at.into(),
            verified: false,
            attempts: 0,
        };

        collection.insert_one(&otp).await?;
        Ok(otp)
    }

    async fn find_otp_by_contact(
        &self,
        contact_type: ContactType,
        contact_value: &str,
    ) -> Result<Option<OtpEntity>, AuthDataError> {
        let collection = self.collection().await;
        let now = Utc::now();

        let filter = doc! {
            "contact.contact_type": bson::to_bson(&contact_type)?,
            "contact.contact_value": contact_value,
            "expires_at": { "$gt": now }
        };

        let result = collection.find_one(filter).await?;
        Ok(result)
    }

    async fn find_otp_by_id(&self, id: &str) -> Result<OtpEntity, AuthDataError> {
        let collection = self.collection().await;

        // parse id to object id
        let id = ObjectId::parse_str(id)
            .map_err(|e| AuthDataError::InternalError(format!("Invalid ID: {}", e)))?;

        let filter = doc! { "_id": id };

        let result = collection.find_one(filter).await?;
        match result {
            Some(entity) => Ok(entity),
            None => Err(AuthDataError::OtpNotFound),
        }
    }

    async fn save_otp(&self, challenge: OtpEntity) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        collection.insert_one(challenge).await?;
        Ok(())
    }

    async fn update_otp(&self, challenge: OtpEntity) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": &challenge.id };
        collection.replace_one(filter, challenge).await?;
        Ok(())
    }

    async fn verify_otp(
        &self,
        contact_type: ContactType,
        contact_value: &str,
        code: &str,
    ) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let now = Utc::now();

        let filter = doc! {
            "contact.contact_type": bson::to_bson(&contact_type)?,
            "contact.contact_value": contact_value,
            "code": code,
            "verified": false,
            "expires_at": { "$gt": now }
        };

        let result = collection.find_one(filter).await?;

        match result {
            Some(otp) => {
                self.mark_otp_verified(&otp.id.to_string()).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn mark_otp_verified(&self, id: &str) -> Result<bool, AuthDataError> {
        let collection = self.collection().await;
        let filter = doc! { "_id": id };
        let update = doc! { "$set": { "verified": true } };

        let result = collection.update_one(filter, update).await?;

        Ok(result.modified_count > 0)
    }

    async fn delete_expired_otps(&self) -> Result<(), AuthDataError> {
        let collection = self.collection().await;
        let now = Utc::now();

        // Delete all OTPs that have expired
        let filter = doc! {
            "expires_at": { "$lt": now }
        };

        collection.delete_many(filter).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::oid::ObjectId;
    use chrono::Utc;
    use mongodb::{options::ClientOptions, Client};
    use tokio::sync::RwLock;



    async fn setup_test_db() -> Arc<RwLock<Database>> {
        let mongo_uri = std::env::var("MONGO_DB_URI").expect("MONGO_DB_URI must be set");
        let client_options = ClientOptions::parse(&mongo_uri).await.unwrap();
        let client = Client::with_options(client_options).unwrap();
        let db = client.database("test_auth_db");
        
        // Clean up test data
        db.collection::<Document>("test_users")
            .delete_many(doc! {})
            .await
            .unwrap();

        Arc::new(RwLock::new(db))
    }

    fn create_test_user() -> UserEntity {
        UserEntity {
            id: Some(ObjectId::new()),
            username: "testuser".to_string(),
            fullname: "Test User".to_string(),
            salted_hash: SaltedHash {
                hash: "hash".to_string(),
                salt: "salt".to_string(),
            },
            birthdate: Utc::now().into(),
            gender: Gender::Male,
            country: Some("US".to_string()),
            bio: None,
            profile_picture: None,
            contacts: vec![Contact {
                contact_type: ContactType::Email,
                contact_value: "test@example.com".to_string(),
                is_primary: Some(true),
                verified_at: Some(Utc::now().into()),
                verification_token: None,
            }],
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            password_last_changed: Some(Utc::now().into()),
            deleted: false,
            deleted_at: None,
            roles: vec!["viewer".to_string()],
            failed_login_attempts: Some(0),
            salted_hash_history: Some(Vec::new()),
        }
    }


    #[tokio::test]
    async fn test_after_update_password_history_should_contain_old_password_hash() {
        let db = setup_test_db().await;
        let repo = MongoUserRepository::new(db, "test_users".to_string());
        
        // Create test user
        let username = format!("testuser_{}", Utc::now().timestamp());
        let created_user = repo.create_user(
            UserCreationData {
                username: username.clone(),
                fullname: "Test User".to_string(),
                password: "password".to_string(),
                contact_type: Some(ContactType::Email),
                contact_value: Some("test@example.com".to_string()),
                birthdate: Utc::now().into(),
                gender: Gender::Male,
                country: Some("US".to_string()),
                roles: vec!["viewer".to_string()],
            },
            "old_hash".to_string(),
            "old_salt".to_string(),
        )
        .await
        .unwrap();

        // Update password
        let updated = repo.update_password_and_salted_hash_history(
            &created_user.id.unwrap(),
            SaltedHash {
                hash: "new_hash".to_string(),
                salt: "new_salt".to_string(),
            },
            SaltedHash {
                hash: "old_hash".to_string(),
                salt: "old_salt".to_string(),
            },
        )
        .await
        .unwrap();
        assert!(updated);

        // Verify password history
        let user = repo.find_by_id(&created_user.id.unwrap())
            .await
            .unwrap()
            .unwrap();
            
        assert!(user.salted_hash_history.unwrap().iter().any(|sh| sh.hash == "old_hash"));
    }
    
    #[tokio::test]
    async fn test_create_and_find_user() {
        let db = setup_test_db().await;
        let repo = MongoUserRepository::new(db, "test_users".to_string());
        
        let user = create_test_user();
        let username = format!("testuser_{}", Utc::now().timestamp()); // Unique username
        let created_user = repo.create_user(
            UserCreationData {
                username: username.clone(),
                fullname: user.fullname.clone(),
                password: "password".to_string(),
                contact_type: Some(ContactType::Email),
                contact_value: Some("test@example.com".to_string()),
                birthdate: user.birthdate,
                gender: user.gender,
                country: user.country.clone(),
                roles: vec!["viewer".to_string()],
            },
            user.salted_hash.hash,
            user.salted_hash.salt,
        )
        .await
        .unwrap();

        let found_user = repo.find_by_id(&created_user.id.unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found_user.username, username);
        assert_eq!(found_user.contacts.len(), 1);
    }

    #[tokio::test]
    async fn test_update_user() {
        let db = setup_test_db().await;
        let repo = MongoUserRepository::new(db, "test_users".to_string());
        
        // Create initial user
        let username = format!("testuser_{}", Utc::now().timestamp()); // Unique username
        let created_user = repo.create_user(
            UserCreationData {
                username: username.clone(),
                fullname: "Test User".to_string(),
                password: "password".to_string(),
                contact_type: Some(ContactType::Email),
                contact_value: Some("test@example.com".to_string()),
                birthdate: Utc::now().into(),
                gender: Gender::Male,
                country: Some("US".to_string()),
                roles: vec!["viewer".to_string()],
            },
            "hash".to_string(),
            "salt".to_string(),
        )
        .await
        .unwrap();

        // Update the user
        let mut user_to_update = created_user.clone();
        user_to_update.fullname = "Updated Name".to_string();
        repo.update(&user_to_update).await.unwrap();

        // Verify the update
        let updated_user = repo.find_by_id(&user_to_update.id.unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated_user.fullname, "Updated Name");
    }

    #[tokio::test]
    async fn test_delete_user() {
        let db = setup_test_db().await;
        let repo = MongoUserRepository::new(db, "test_users".to_string());
        
        // Create user and store the returned entity
        let username = format!("testuser_{}", Utc::now().timestamp()); // Unique username
        let created_user = repo.create_user(
            UserCreationData {
                username: username.clone(),
                fullname: "Test User".to_string(),
                password: "password".to_string(),
                contact_type: Some(ContactType::Email),
                contact_value: Some("test@example.com".to_string()),
                birthdate: Utc::now().into(),
                gender: Gender::Male,
                country: Some("US".to_string()),
                roles: vec!["viewer".to_string()],
            },
            "hash".to_string(),
            "salt".to_string(),
        )
        .await
        .unwrap();

        // Delete the user using the ID from the created user
        let deleted = repo.delete_user(&created_user.id.unwrap())
            .await
            .unwrap();
        assert!(deleted);

        // Verify the user is marked as deleted
        let deleted_user = repo.find_by_id(&created_user.id.unwrap())
            .await
            .unwrap();
        
        // Check that the user is marked as deleted
        match deleted_user {
            Some(user) => {
                assert!(user.deleted);
                assert!(user.deleted_at.is_some());
            }
            None => panic!("User should still exist but be marked as deleted"),
        }

        // Verify the user cannot be found in normal queries
        let found_user = repo.find_by_username(&username)
            .await
            .unwrap();
        assert!(found_user.is_none(), "Deleted user should not be found in normal queries");
    }

    #[tokio::test]
    async fn test_add_and_remove_role() {
        let db = setup_test_db().await;
        let repo = MongoUserRepository::new(db, "test_users".to_string());
        
        // Create user and store the returned entity
        let username = format!("testuser_{}", Utc::now().timestamp()); // Unique username
        let created_user = repo.create_user(
            UserCreationData {
                username: username.clone(),
                fullname: "Test User".to_string(),
                password: "password".to_string(),
                contact_type: Some(ContactType::Email),
                contact_value: Some("test@example.com".to_string()),
                birthdate: Utc::now().into(),
                gender: Gender::Male,
                country: Some("US".to_string()),
                roles: vec!["viewer".to_string()],
            },
            "hash".to_string(),
            "salt".to_string(),
        )
        .await
        .unwrap();

        // Add role
        let added = repo.add_role(&created_user.id.unwrap(), "admin")
            .await
            .unwrap();
        assert!(added);

        // Verify role was added
        let roles = repo.get_roles(&created_user.id.unwrap())
            .await
            .unwrap();
        assert!(roles.contains(&"admin".to_string()));

        // Remove role
        let removed = repo.remove_role(&created_user.id.unwrap(), "admin")
            .await
            .unwrap();
        assert!(removed);

        // Verify role was removed
        let roles = repo.get_roles(&created_user.id.unwrap())
            .await
            .unwrap();
        assert!(!roles.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn test_find_by_contact() {
        let db = setup_test_db().await;
        let repo = MongoUserRepository::new(db, "test_users".to_string());
        
        let user = create_test_user();
        let username = format!("testuser_{}", Utc::now().timestamp()); // Unique username
        repo.create_user(
            UserCreationData {
                username: username.clone(),
                fullname: user.fullname.clone(),
                password: "password".to_string(),
                contact_type: Some(ContactType::Email),
                contact_value: Some("test@example.com".to_string()),
                birthdate: user.birthdate,
                gender: user.gender,
                country: user.country.clone(),
                roles: vec!["viewer".to_string()],
            },
            user.salted_hash.hash,
            user.salted_hash.salt,
        )
        .await
        .unwrap();

        let found_user = repo.find_by_contact(ContactType::Email, "test@example.com")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found_user.username, username);
    }
}
