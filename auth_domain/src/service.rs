use crate::error::{AuthError, OtpError, PasswordError};
use crate::hashing_service::HashingService;
use crate::mappers::user_entity_to_user;
use crate::models::*;
use crate::models::{AuthResult, SessionResult, User};
use crate::TokenService;
use async_trait::async_trait;
use auth_data::entities::{Contact, ContactType};
use auth_data::repositories::{OtpRepository, UserRepository};
use auth_data::{AuthDataError, Gender, UserCreationData};
use bson::oid::ObjectId;
use bson::Uuid;
use chrono::{DateTime, Duration, Utc};
use rand::{thread_rng, Rng};
use std::sync::Arc;
use tracing::{debug, error, info};

use auth_data::entities::ActionType;

// Add the new module
use crate::password_strength;
use crate::utils::{is_valid_email, is_valid_phone};
/// Auth service trait defining authentication operations
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Start OTP challenge for an action
    async fn otp_challenge(
        &self,
        contact_value: String,
        contact_type: ContactType,
        action_type: ActionType,
        session_token: Option<String>,
    ) -> AuthResult<String>;

    /// Confirm an OTP and return action token
    async fn confirm_otp(&self, challenge_token: &str, otp: &str) -> AuthResult<String>;

    /// Register a new user
    async fn register(
        &self,
        action_token: &str,
        data: UserCreationData,
    ) -> AuthResult<SessionResult>;

    /// Log in a user
    async fn login(&self, login_data: LoginData) -> AuthResult<SessionResult>;

    async fn logout(&self, session_token: &str) -> AuthResult<()>;
    
    async fn refresh(&self, session_token: &str) -> AuthResult<String>;

    /// Update user password
    async fn update_password(
        &self,
        session_token: &str,
        current_password: &str,
        new_password: &str,
    ) -> AuthResult<bool>;

    /// Reset password with action token
    async fn reset_password(&self, action_token: &str, new_password: &str) -> AuthResult<bool>;

    /// Delete user account
    async fn delete_account(&self, action_token: &str) -> AuthResult<bool>;

    /// Update user profile
    async fn update_profile(&self, user_id: &str, data: ProfileUpdateData) -> AuthResult<User>;

    /// Get user profile
    async fn get_profile(&self, session_token: &str) -> AuthResult<User>;

    /// Check if username is available
    async fn check_username(&self, session_token: &str, username: &str) -> AuthResult<CheckUsernameResult>;

    /// Add a contact to user
    async fn add_contact(&self, action_token: &str) -> AuthResult<bool>;

    /// Remove a contact from user
    async fn remove_contact(&self, user_id: &str, contact_type: ContactType) -> AuthResult<bool>;

    /// Set primary contact
    async fn set_primary_contact(
        &self,
        user_id: &str,
        contact_type: ContactType,
    ) -> AuthResult<bool>;

    /// Validate session token
    async fn validate_token(&self, token: &str) -> AuthResult<String>;

    /// Check password strength
    /// Returns PasswordStrength enum indicating the strength level
    fn check_password_strength(&self, password: &str) -> PasswordStrength;

    /// Add role to user
    async fn add_role(&self, user_id: &str, role: &str) -> AuthResult<bool>;

    /// Remove role from user
    async fn remove_role(&self, user_id: &str, role: &str) -> AuthResult<bool>;

    /// Get user roles
    async fn get_roles(&self, user_id: &str) -> AuthResult<Vec<String>>;
}

/// Implementation of AuthService
pub struct AuthServiceImpl {
    user_repository: Arc<dyn UserRepository>,
    otp_repository: Arc<dyn OtpRepository>,
    token_service: Arc<dyn TokenService>,
    hashing_service: Arc<dyn HashingService>,
    retention_period: chrono::Duration,
}

impl AuthServiceImpl {
    /// Create a new auth service instance
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        otp_repository: Arc<dyn OtpRepository>,
        token_service: Arc<dyn TokenService>,
        hashing_service: Arc<dyn HashingService>,
        retention_period: Duration,
    ) -> Self {
        Self {
            user_repository,
            otp_repository,
            token_service,
            hashing_service,
            retention_period,
        }
    }

    /// Generate random OTP code
    fn generate_otp(&self) -> String {
        let mut rng = thread_rng();
        format!("{:06}", rng.gen_range(100000..=999999))
    }

    fn check_password_strength(&self, password: &str) -> PasswordStrength {
        password_strength::check_password_strength(password)
    }
}

#[async_trait]
impl AuthService for AuthServiceImpl {
    async fn otp_challenge(
        &self,
        contact_value: String,
        contact_type: ContactType,
        action_type: ActionType,
        session_token: Option<String>,
    ) -> AuthResult<String> {
        // Validate contact value based on type
        match contact_type {
            ContactType::Email => {
                if !is_valid_email(&contact_value) {
                    return Err(AuthError::InvalidContactValue);
                }
            }
            ContactType::Phone => {
                if !is_valid_phone(&contact_value) {
                    return Err(AuthError::InvalidContactValue);
                }
            }
        }

        let action_id = uuid::Uuid::new_v4().to_string();

        let user_id = match action_type {
            ActionType::AddContact => {
                // Ensure session token is provided
                let session_token = session_token.ok_or(AuthError::Unauthorized)?;

                // Validate session token and get user ID
                let claims = self.token_service.validate_session_token(&session_token)?;
                let user_id = ObjectId::parse_str(&claims.sub).unwrap();

                // Add unverified contact
                let contact = Contact {
                    contact_type,
                    contact_value: contact_value.clone(),
                    is_primary: Some(false),
                    verified_at: None,
                    // use action id as verification token
                    verification_token: Some(action_id.clone()),
                };

                self.user_repository.add_contact(&user_id, contact).await?;

                claims.sub
            }
            ActionType::Registration => {
                // For Registration, create a new user entity first
                let user = self
                    .user_repository
                    .create_user(
                        UserCreationData {
                            username: format!("temp_{}", Uuid::new()), // Temporary username
                            fullname: "".to_string(),
                            password: "".to_string(),
                            contact_type: Some(contact_type),
                            contact_value: Some(contact_value.clone()),
                            birthdate: Utc::now(),
                            gender: Gender::Other,
                            country: None,
                            roles: vec![],
                        },
                        "".to_string(), // Temporary password hash
                        "".to_string(), // Temporary salt
                    )
                    .await
                    .map_err(|e| {
                        error!("Failed to create temporary user: {}", e);
                        AuthError::DataError(e.into())
                    })?;

                user.id.expect("User does not have id").to_hex()
            }
            _ => {
                // for other actions, contact can be used to find the user
                self.user_repository
                    .find_by_contact(contact_type, &contact_value)
                    .await
                    .map_err(|e| {
                        error!("Failed to find user: {}", e);
                        AuthError::DataError(e.into())
                    })?
                    .ok_or(AuthError::UserNotFound)?
                    .id
                    .expect("User does not have id")
                    .to_hex()
            }
        };

        // Generate OTP code
        let otp_code = self.generate_otp();

        let contact = Contact {
            contact_type,
            contact_value: contact_value.clone(),
            is_primary: Some(false),
            verified_at: None,
            verification_token: None,
        };

        let otp = self
            .otp_repository
            .create_otp(contact, &otp_code)
            .await
            .map_err(|e| {
                error!("Failed to create OTP: {}", e);
                AuthError::DataError(e.into())
            })?;

        // Create challenge token
        let challenge_token = self
            .token_service
            .create_challenge_token(
                &user_id,              // User ID (current user or temporary)
                action_type,           // Action type
                &otp.id.to_hex(),      // Challenge ID
                Duration::minutes(10), // Expiration
                Some(contact_value),   // Contact value being added
                contact_type,          // Contact type
                &action_id,            // Action ID
            )
            .map_err(|e| {
                error!("Failed to create challenge token: {}", e);
                e
            })?;

        Ok(challenge_token)
    }

    async fn confirm_otp(&self, challenge_token: &str, otp: &str) -> AuthResult<String> {
        // Clean up expired OTPs first
        self.otp_repository
            .delete_expired_otps()
            .await
            .map_err(|e| {
                error!("Failed to clean up expired OTPs: {}", e);
                AuthError::DataError(e.into())
            })?;

        // Validate challenge token
        let claims = self
            .token_service
            .validate_challenge_token(challenge_token)
            .map_err(|e| {
                error!("Failed to validate challenge token: {}", e);
                e
            })?;

        // Find OTP challenge
        let mut challenge = self
            .otp_repository
            .find_otp_by_id(&claims.challenge_id)
            .await
            .map_err(|e| {
                error!("Failed to find OTP: {}", e);
                AuthError::DataError(e.into())
            })?;

        // Check if OTP is expired
        if Utc::now() > challenge.expires_at {
            return Err(AuthError::OtpError(OtpError::Expired));
        }

        // Check if max attempts reached
        if challenge.attempts >= 3 {
            return Err(AuthError::OtpError(OtpError::MaxAttemptsReached));
        }

        // Verify OTP code
        if challenge.otp_code != otp {
            // Increment attempts
            challenge.attempts += 1;
            self.otp_repository
                .update_otp(challenge)
                .await
                .map_err(|e| {
                    error!("Failed to update OTP attempts: {}", e);
                    AuthError::DataError(e.into())
                })?;

            return Err(AuthError::OtpError(OtpError::Invalid));
        }

        // Mark OTP as verified
        challenge.verified = true;
        self.otp_repository
            .update_otp(challenge)
            .await
            .map_err(|e| {
                error!("Failed to mark OTP as verified: {}", e);
                AuthError::DataError(e.into())
            })?;

        // Create action token using the subject from the claims
        let action_token = self
            .token_service
            .create_action_token(&claims.sub, claims.action_type, &claims.action_id)
            .map_err(|e| {
                error!("Failed to create action token: {}", e);
                e
            })?;

        Ok(action_token)
    }

    async fn register(
        &self,
        action_token: &str,
        data: UserCreationData,
    ) -> AuthResult<SessionResult> {
        // Validate password strength
        if self.check_password_strength(&data.password) == PasswordStrength::TooWeak {
            return Err(AuthError::Password(PasswordError::TooWeak));
        }

        // Validate user data
        if data.username.len() < 3 || data.username.len() > 20 {
            return Err(AuthError::InvalidUsername);
        }

        // Validate action token
        let claims = self
            .token_service
            .validate_action_token(action_token)
            .map_err(|e| {
                error!("Failed to validate action token: {}", e);
                e
            })?;

        // Ensure action is for registration
        if claims.action_type != ActionType::Registration {
            return Err(AuthError::ActionNotPermitted);
        }

        // Parse the user ID
        let user_id = ObjectId::parse_str(&claims.sub).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        // Find the temporary user
        let mut user = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find temporary user: {}", e);
                AuthError::DataError(e.into())
            })?
            .ok_or(AuthError::UserNotFound)?;

        // Check if username exists
        let username_exists = self
            .user_repository
            .username_exists(&data.username)
            .await
            .map_err(|e| {
                error!("Failed to check username existence: {}", e);
                AuthError::DataError(e.into())
            })?;

        if username_exists {
            return Err(AuthError::UsernameTaken);
        }

        // Contact details is already added in the otp challenge
        // so we need to update the user without the contact details

        // Update user with registration data
        user.username = data.username;
        user.fullname = data.fullname;
        user.birthdate = data.birthdate;
        user.gender = data.gender;
        user.country = data.country;
        user.roles = data.roles;

        // Hash and store password
        let salted_hash = self.hashing_service.hash_password(&data.password);
        user.salted_hash = salted_hash;
        user.created_at = Utc::now();
        user.updated_at = Utc::now();

        // Update user in database
        self.user_repository.update(&user).await.map_err(|e| {
            error!("Failed to update user: {}", e);
            AuthError::DataError(e)
        })?;

        // Generate session token using the existing user entity
        let user_id = user.id.map(|id| id.to_hex()).unwrap_or_default();
        let session_token = self
            .token_service
            .create_session_token(&user_id, user.roles.clone())
            .map_err(|e| {
                error!("Failed to create session token: {}", e);
                e
            })?;

        // Convert to profile using the existing user entity
        let profile = user_entity_to_user(user);

        Ok(SessionResult {
            user: profile,
            session_token,
        })
    }

    async fn login(&self, login_data: LoginData) -> AuthResult<SessionResult> {
        let (user, password) = match login_data {
            LoginData::Email(email, password) => {
                let user = self
                    .user_repository
                    .find_by_contact(ContactType::Email, &email)
                    .await
                    .map_err(|e| {
                        error!("Failed to find user by email: {}", e);
                        AuthError::DataError(e.into())
                    })?
                    .ok_or(AuthError::InvalidCredentials)?;
                (user, password)
            }
            LoginData::Username(username, password) => {
                let user = self
                    .user_repository
                    .find_by_username(&username)
                    .await
                    .map_err(|e| {
                        error!("Failed to find user by username: {}", e);
                        AuthError::DataError(e.into())
                    })?
                    .ok_or(AuthError::InvalidCredentials)?;
                (user, password)
            }
            LoginData::Phone(phone, password) => {
                let user = self
                    .user_repository
                    .find_by_contact(ContactType::Phone, &phone)
                    .await
                    .map_err(|e| {
                        error!("Failed to find user by phone: {}", e);
                        AuthError::DataError(e.into())
                    })?
                    .ok_or(AuthError::InvalidCredentials)?;
                (user, password)
            }
        };

        if user.deleted {
            if let Some(deleted_at) = user.deleted_at {
                if Utc::now() - deleted_at < self.retention_period {
                    // Restore account automatically
                    self.user_repository
                        .restore_user(&user.id.unwrap())
                        .await
                        .map_err(|e| {
                            error!("Failed to restore user: {}", e);
                            AuthError::DataError(e.into())
                        })?;
                } else {
                    return Err(AuthError::AccountPermanentlyDeleted);
                }
            }
        }

        // Check failed login attempts
        let failed_attempts = self
            .user_repository
            .get_failed_login_attempts(&user.id.unwrap())
            .await
            .map_err(|e| {
                error!("Failed to get failed login attempts: {}", e);
                AuthError::DataError(e.into())
            })?;

        if failed_attempts >= 5 {
            return Err(AuthError::AccountLocked);
        }

        // Verify password
        let valid = self.hashing_service.verify(&password, &user.salted_hash);

        if !valid {
            return Err(AuthError::InvalidCredentials);
        }

        // Generate session token
        let user_id = user.id.map(|id| id.to_hex()).unwrap_or_default();
        let session_token = self
            .token_service
            .create_session_token(&user_id, user.roles.clone())
            .map_err(|e| {
                error!("Failed to create session token: {}", e);
                e
            })?;

        // Handle successful login
        self.user_repository
            .reset_failed_login_attempts(&user.id.unwrap())
            .await
            .map_err(|e| {
                error!("Failed to reset failed login attempts: {}", e);
                AuthError::DataError(e.into())
            })?;

        Ok(SessionResult {
            user: user_entity_to_user(user),
            session_token,
        })
    }

    async fn logout(&self, session_token: &str) -> AuthResult<()> {
        unimplemented!("Logout is not implemented")
    }

    async fn refresh(&self, session_token: &str) -> AuthResult<String> {
        unimplemented!("refresh is not implemented")
    }

    async fn update_password(
        &self,
        session_token: &str,
        current_password: &str,
        new_password: &str,
    ) -> AuthResult<bool> {
        // Validate session token
        if self.token_service.is_token_revoked(session_token).await? {
            return Err(AuthError::TokenRevoked);
        }

        let user_id = self
            .token_service
            .validate_session_token(session_token)
            .map_err(|e| {
                error!("Failed to validate session token: {}", e);
                e
            })?
            .sub;

        // Check if new password is same as current
        if current_password == new_password {
            return Err(AuthError::Password(PasswordError::SameAsCurrent));
        }

        // Validate new password strength
        if self.check_password_strength(new_password) == PasswordStrength::TooWeak {
            return Err(AuthError::Password(PasswordError::TooWeak));
        }

        // Parse the user ID
        let user_id = ObjectId::parse_str(&user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        // Find user
        let user = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find user: {}", e);
                AuthError::DataError(e)
            })?
            .ok_or(AuthError::UserNotFound)?;

        // Verify current password
        let valid = self
            .hashing_service
            .verify(current_password, &user.salted_hash);

        if !valid {
            return Err(AuthError::InvalidCredentials);
        }

        // Verify if new password is in history
        let new_salted_hash = self.hashing_service.hash_password(new_password);

        // Get full password history with salts
        let salted_hash_history = self
            .user_repository
            .get_salted_hash_history(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to get password history: {}", e);
                AuthError::DataError(e.into())
            })?;

        // Check if new password matches any historical password
        for old_salted_hash in salted_hash_history {
            if self.hashing_service.verify(new_password, &old_salted_hash) {
                return Err(AuthError::Password(PasswordError::PreviouslyUsed));
            }
        }

        // Update password and add current password to history
        let updated = self
            .user_repository
            .update_password_and_salted_hash_history(
                &user_id,
                new_salted_hash,
                user.salted_hash, // Add current password to history
            )
            .await
            .map_err(|e| {
                error!("Failed to update password: {}", e);
                AuthError::DataError(e)
            })?;

        Ok(updated)
    }

    async fn reset_password(&self, action_token: &str, new_password: &str) -> AuthResult<bool> {
        // Validate action token expiration
        let claims = self
            .token_service
            .validate_action_token(action_token)
            .map_err(|e| {
                error!("Failed to validate action token: {}", e);
                e
            })?;

        if claims.exp < Utc::now().timestamp() {
            return Err(AuthError::TokenExpired);
        }

        // Check if user is deleted
        let user_id = ObjectId::parse_str(&claims.sub).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        let user = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find user: {}", e);
                AuthError::DataError(e.into())
            })?
            .ok_or(AuthError::UserNotFound)?;

        if user.deleted {
            return Err(AuthError::AccountDeleted);
        }

        // Validate new password strength
        if self.check_password_strength(new_password) == PasswordStrength::TooWeak {
            return Err(AuthError::Password(PasswordError::TooWeak));
        }

        // Hash new password
        let new_password_hash = self.hashing_service.hash_password(new_password);

        // Update password
        let updated = self
            .user_repository
            .update_password_and_salted_hash_history(&user_id, new_password_hash, user.salted_hash)
            .await
            .map_err(|e| {
                error!("Failed to update password: {}", e);
                AuthError::DataError(e)
            })?;

        Ok(updated)
    }

    async fn delete_account(&self, action_token: &str) -> AuthResult<bool> {
        // Add confirmation step
        let claims = self
            .token_service
            .validate_action_token(action_token)
            .map_err(|e| {
                error!("Failed to validate action token: {}", e);
                e
            })?;

        if claims.action_type != ActionType::DeleteAccount {
            return Err(AuthError::ActionNotPermitted);
        }

        let user_id = ObjectId::parse_str(&claims.sub).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        let deleted = self
            .user_repository
            .delete_user(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to delete user: {}", e);
                AuthError::DataError(e)
            })?;

        Ok(deleted)
    }

    async fn update_profile(&self, user_id: &str, data: ProfileUpdateData) -> AuthResult<User> {
        // Validate profile data
        if let Some(fullname) = &data.fullname {
            if fullname.len() > 100 {
                return Err(AuthError::InvalidProfileData);
            }
        }

        // Parse the user ID
        let user_id = ObjectId::parse_str(user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        // Find user
        let user = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find user: {}", e);
                AuthError::DataError(e)
            })?
            .ok_or(AuthError::UserNotFound)?;

        // Update user entity
        let mut updated_user = user.clone();
        if let Some(fullname) = data.fullname {
            updated_user.fullname = fullname;
        }
        if let Some(profile_picture) = data.profile_picture {
            updated_user.profile_picture = Some(profile_picture);
        }
        if let Some(gender) = data.gender {
            updated_user.gender = gender;
        }
        if let Some(country) = data.country {
            updated_user.country = Some(country);
        }
        if let Some(bio) = data.bio {
            updated_user.bio = Some(bio);
        }
        if let Some(birthdate) = data.birthdate {
            updated_user.birthdate = birthdate.into();
        }

        // Save updated user
        self.user_repository
            .update(&updated_user)
            .await
            .map_err(|e| {
                error!("Failed to update profile: {}", e);
                AuthError::DataError(e)
            })?;

        // Convert to domain profile
        let profile = user_entity_to_user(updated_user);

        Ok(profile)
    }

    async fn get_profile(&self, session_token: &str) -> AuthResult<User> {
        // Validate session token and get user ID
        let user_id = self
            .token_service
            .validate_session_token(session_token)
            .map_err(|e| {
                error!("Failed to validate session token: {}", e);
                e
            })?
            .sub;

        // Parse the user ID
        let user_id = ObjectId::parse_str(&user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        // Find user
        let user = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find user: {}", e);
                AuthError::DataError(e)
            })?
            .ok_or(AuthError::UserNotFound)?;

        // Convert to domain profile
        let profile = user_entity_to_user(user);

        Ok(profile)
    }

    async fn check_username(&self, session_token: &str, username: &str) -> AuthResult<CheckUsernameResult> {
        // Validate session token
        self
            .token_service
            .validate_session_token(session_token)
            .map_err(|e| {
                error!("Failed to validate session token: {}", e);
                e
            })?;

        // Validate username format
        if username.len() < 3 || username.len() > 20 {
            return Ok(CheckUsernameResult::Invalid);
        }

        // Check if username exists
        let exists = self
            .user_repository
            .username_exists(username)
            .await
            .map_err(|e| {
                error!("Failed to check username: {}", e);
                AuthError::DataError(e)
            })?;

        Ok(if exists {
            CheckUsernameResult::AlreadyTaken
        } else {
            CheckUsernameResult::Valid
        })
    }

    async fn add_contact(&self, action_token: &str) -> AuthResult<bool> {
        // Validate action token
        let claims = self
            .token_service
            .validate_action_token(action_token)
            .map_err(|e| {
                error!("Failed to validate action token: {}", e);
                e
            })?;

        let user_id = ObjectId::parse_str(&claims.sub).unwrap();

        // Mark contact as verified
        self.user_repository
            .mark_contact_as_verified(&user_id, &claims.jti)
            .await
            .map_err(|e| AuthError::DataError(e))?;

        Ok(true)
    }

    async fn remove_contact(&self, user_id: &str, contact_type: ContactType) -> AuthResult<bool> {
        // Parse the user ID
        let user_id = ObjectId::parse_str(user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        // Find user
        let user = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find user: {}", e);
                AuthError::DataError(e)
            })?
            .ok_or(AuthError::UserNotFound)?;

        // Find the contact to remove
        let contact = user
            .contacts
            .iter()
            .find(|c| c.contact_type == contact_type)
            .ok_or(AuthError::ContactNotFound)?;

        // Check if contact is primary
        if contact.is_primary.unwrap_or(false) {
            return Err(AuthError::CannotRemovePrimaryContact);
        }

        // Remove contact
        self.user_repository
            .remove_contact(&user_id, &contact.contact_value)
            .await
            .map_err(|e| {
                error!("Failed to remove contact: {}", e);
                AuthError::DataError(e)
            })?;

        Ok(true)
    }

    async fn set_primary_contact(
        &self,
        user_id: &str,
        contact_type: ContactType,
    ) -> AuthResult<bool> {
        // Parse the user ID
        let user_id = ObjectId::parse_str(user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        // Find user
        let user = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find user: {}", e);
                AuthError::DataError(e)
            })?
            .ok_or(AuthError::UserNotFound)?;

        // Find the contact to set as primary
        let contact = user
            .contacts
            .iter()
            .find(|c| c.contact_type == contact_type)
            .ok_or(AuthError::ContactNotFound)?;

        // Check if contact is verified
        if contact.verified_at.is_none() {
            return Err(AuthError::ContactNotVerified);
        }

        // Update primary contact
        self.user_repository
            .update_primary_contact(&user_id, contact_type, &contact.contact_value)
            .await
            .map_err(|e| {
                error!("Failed to set primary contact: {}", e);
                AuthError::DataError(e)
            })?;

        Ok(true)
    }

    async fn validate_token(&self, token: &str) -> AuthResult<String> {
        // Check if token is revoked
        if self.token_service.is_token_revoked(token).await? {
            return Err(AuthError::TokenRevoked);
        }

        let user_id = self
            .token_service
            .validate_session_token(token)
            .map_err(|e| {
                error!("Failed to validate session token: {}", e);
                e
            })?
            .sub;

        // Parse the user ID
        let user_id = ObjectId::parse_str(&user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        let user_exists = self
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| {
                error!("Failed to find user: {}", e);
                AuthError::DataError(e)
            })?
            .is_some();

        if !user_exists {
            return Err(AuthError::UserNotFound);
        }

        Ok(user_id.to_hex())
    }

    /// Check password strength
    /// Returns PasswordStrength enum indicating the strength level
    fn check_password_strength(&self, password: &str) -> PasswordStrength {
        password_strength::check_password_strength(password)
    }

    async fn add_role(&self, user_id: &str, role: &str) -> AuthResult<bool> {
        let user_id = ObjectId::parse_str(user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        self.user_repository
            .add_role(&user_id, role)
            .await
            .map_err(|e| {
                error!("Failed to add role: {}", e);
                AuthError::DataError(e)
            })
    }

    async fn remove_role(&self, user_id: &str, role: &str) -> AuthResult<bool> {
        let user_id = ObjectId::parse_str(user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        self.user_repository
            .remove_role(&user_id, role)
            .await
            .map_err(|e| {
                error!("Failed to remove role: {}", e);
                AuthError::DataError(e)
            })
    }

    async fn get_roles(&self, user_id: &str) -> AuthResult<Vec<String>> {
        let user_id = ObjectId::parse_str(user_id).map_err(|e| {
            error!("Failed to parse user ID: {}", e);
            AuthError::DataError(AuthDataError::InternalError(e.to_string()))
        })?;

        self.user_repository.get_roles(&user_id).await.map_err(|e| {
            error!("Failed to get roles: {}", e);
            AuthError::DataError(e)
        })
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing_service::SHA256HashingService;
    use crate::token_service::{JwtTokenService, TokenConfig};
    use auth_data::repositories::{MongoOtpRepository, MongoUserRepository};
    use auth_data::UserEntity;
    use jsonwebtoken::Algorithm;
    use mongodb::{
        bson::{doc, Document},
        Client,
    };
    use std::env;
    use std::error::Error;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tracing::{info, Level};
    use tracing_subscriber;

    const TEST_USER_PASSWORD: &str = "password123";
    const TEST_USER_USERNAME: &str = "test_user";
    const TEST_USER_EMAIL: &str = "test_user@example.com";

    // Add a new function to clear test databases
    async fn clear_test_databases() -> Result<(), Box<dyn Error>> {
        let mongo_uri = env::var("MONGO_DB_URI").expect("MONGO_DB_URI must be set");
        let client = Client::with_uri_str(&mongo_uri).await?;
        let db = client.database("test_auth_db");

        // Clean up test data
        db.collection::<Document>("test_users")
            .delete_many(doc! {})
            .await?;
        db.collection::<Document>("test_otps")
            .delete_many(doc! {})
            .await?;

        Ok(())
    }


    // Add a setup function that will run before each test
    async fn setup() -> AuthServiceImpl {
        // setup tracing
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(Level::DEBUG)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

        clear_test_databases()
            .await
            .expect("Failed to clear test databases");

        let mongo_uri = env::var("MONGO_DB_URI").expect("MONGO_DB_URI must be set");
        let client = Client::with_uri_str(&mongo_uri)
            .await
            .expect("Failed to connect to MongoDB");
        let db = client.database("test_auth_db");
        let db = Arc::new(RwLock::new(db));

        let user_repo = Arc::new(MongoUserRepository::new(
            db.clone(),
            "test_users".to_string(),
        ));
        let otp_repo = Arc::new(MongoOtpRepository::new(db, "test_otps".to_string()));
        let token_service = Arc::new(JwtTokenService::new(TokenConfig {
            secret: "secret".to_owned(),
            algorithm: Algorithm::HS256,
            audience: vec!["audience".to_owned()],
            issuer: "issuer".to_owned(),
        }));
        let hashing_service = Arc::new(SHA256HashingService::new(16));

        AuthServiceImpl::new(
            user_repo,
            otp_repo,
            token_service,
            hashing_service,
            chrono::Duration::days(30),
        )
    }

    #[tokio::test]
    async fn test_user_registration() {
        let service = setup().await;
        let email = format!("test_{}@example.com", Uuid::new().to_string());

        // 1. Start OTP challenge for registration
        let challenge_token = service
            .otp_challenge(
                email.clone(),
                ContactType::Email,
                ActionType::Registration,
                None,
            )
            .await
            .expect("Failed to generate challenge token");

        // 2. Validate challenge token
        let claims = service
            .token_service
            .validate_challenge_token(&challenge_token)
            .expect("Failed to validate challenge token");

        assert_eq!(claims.action_type, ActionType::Registration);
        assert_eq!(claims.contact_type, ContactType::Email);
        assert_eq!(claims.contact_value, Some(email.clone()));

        // 3. Retrieve OTP code
        let otp_entity = service
            .otp_repository
            .find_otp_by_id(&claims.challenge_id)
            .await
            .expect("Failed to find OTP entity");

        // 4. Confirm OTP to get action token
        let action_token = service
            .confirm_otp(&challenge_token, &otp_entity.otp_code)
            .await
            .expect("Failed to confirm OTP");

        // 5. Validate action token
        let action_claims = service
            .token_service
            .validate_action_token(&action_token)
            .expect("Failed to validate action token");

        assert_eq!(action_claims.action_type, ActionType::Registration);

        // 6. Complete registration
        let user_data = UserCreationData {
            username: "test_user_123".to_owned(),
            fullname: "Test User".to_owned(),
            password: "password123".to_owned(),
            contact_type: Some(ContactType::Email),
            contact_value: Some(email.clone()),
            birthdate: Utc::now(),
            gender: auth_data::Gender::Male,
            country: Some("US".to_owned()),
            roles: vec!["viewer".to_string()],
        };

        let reg_result = service
            .register(&action_token, user_data)
            .await
            .expect("User registration failed");

        // 7. Verify registration results
        assert!(!reg_result.user.id.is_empty());
        assert!(!reg_result.session_token.is_empty());
        assert_eq!(reg_result.user.username, "test_user_123");
        assert_eq!(reg_result.user.fullname, "Test User");
        assert_eq!(
            reg_result.user.contacts.first().unwrap().contact_value,
            email
        );

        // 8. Verify user exists in repository
        let user_id = ObjectId::parse_str(&reg_result.user.id).expect("Invalid user ID");
        let user_entity = service
            .user_repository
            .find_by_id(&user_id)
            .await
            .expect("Failed to find user")
            .expect("User not found");

        assert_eq!(user_entity.username, "test_user_123");
        assert_eq!(user_entity.fullname, "Test User");
        assert_eq!(user_entity.contacts.first().unwrap().contact_value, email);
    }


    #[tokio::test]
    async fn test_user_login() {
        let service = setup().await;
        
        // Create test user
        let user_entity = create_test_user(&service).await.unwrap();
        
        // Test successful login with correct credentials
        let login_result = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                TEST_USER_PASSWORD.to_owned(),
            ))
            .await;
            
        assert!(login_result.is_ok());
        let session_result = login_result.unwrap();
        assert!(!session_result.session_token.is_empty());
        assert_eq!(session_result.user.username, TEST_USER_USERNAME);
        
        // Test failed login with incorrect password
        let failed_login = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                "wrong_password".to_owned(),
            ))
            .await;
            
        assert!(failed_login.is_err());
        assert!(matches!(
            failed_login.unwrap_err(),
            AuthError::InvalidCredentials
        ));
        
        // Test failed login with non-existent email
        let non_existent_login = service
            .login(LoginData::Email(
                "nonexistent@example.com".to_owned(),
                "password".to_owned(),
            ))
            .await;
            
        assert!(non_existent_login.is_err());
        assert!(matches!(
            non_existent_login.unwrap_err(),
            AuthError::InvalidCredentials
        ));
    }

    #[tokio::test]
    async fn test_password_reset_for_nonexistent_user() {
        let service = setup().await;

        // Attempt to request OTP for non-existent user
        let result = service
            .otp_challenge(
                "nonexistent@example.com".to_owned(), // contact_value
                ContactType::Email,                   // contact_type
                ActionType::PasswordReset,            // action_type
                None,                                 // session_token
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::UserNotFound));
    }

    #[tokio::test]
    async fn test_password_reset() {
        let service = setup().await;

        let user_entity = create_test_user(&service).await.unwrap();
        // 1. Start OTP challenge for password reset
        let challenge_token = service
            .otp_challenge(
                TEST_USER_EMAIL.to_owned(),
                ContactType::Email,
                ActionType::PasswordReset,
                None,
            )
            .await
            .expect("Failed to generate challenge token");

        // 2. Validate challenge token
        let claims = service
            .token_service
            .validate_challenge_token(&challenge_token)
            .expect("Failed to validate challenge token");

        assert_eq!(claims.action_type, ActionType::PasswordReset);
        assert_eq!(claims.contact_type, ContactType::Email);
        assert_eq!(claims.contact_value, Some(TEST_USER_EMAIL.to_owned()));

        // 3. Retrieve OTP code
        let otp_entity = service
            .otp_repository
            .find_otp_by_id(&claims.challenge_id)
            .await
            .expect("Failed to find OTP entity");

        // 4. Confirm OTP to get action token
        let action_token = service
            .confirm_otp(&challenge_token, &otp_entity.otp_code)
            .await
            .expect("Failed to confirm OTP");

        // 5. Validate action token
        let action_claims = service
            .token_service
            .validate_action_token(&action_token)
            .expect("Failed to validate action token");

        assert_eq!(action_claims.action_type, ActionType::PasswordReset);

        // 6. Reset password
        let new_password = "newpassword456";
        service
            .reset_password(&action_token, new_password)
            .await
            .expect("Failed to reset password");

        // 7. Verify new password works
        let login_result = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                new_password.to_owned(),
            ))
            .await;

        assert!(login_result.is_ok());
        let session = login_result.unwrap();
        assert_eq!(session.user.id, user_entity.id.unwrap().to_string());
    }

    #[tokio::test]
    async fn test_user_login_with_invalid_password() {
        let service = setup().await;
        let user_entity = create_test_user(&service).await.unwrap();

        let login_result = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                "invalid_password".to_owned(),
            ))
            .await;
        assert!(login_result.is_err());
    }

    #[tokio::test]
    async fn test_user_login_with_invalid_email() {
        let service = setup().await;
        let user_entity = create_test_user(&service).await.unwrap();

        let login_result = service
            .login(LoginData::Email(
                "invalid_email".to_owned(),
                TEST_USER_PASSWORD.to_owned(),
            ))
            .await;
        assert!(login_result.is_err());
    }

    #[tokio::test]
    async fn test_user_login_with_invalid_username() {
        let service = setup().await;
        let user_entity = create_test_user(&service).await.unwrap();

        let login_result = service
            .login(LoginData::Username(
                "invalid_username".to_owned(),
                TEST_USER_PASSWORD.to_owned(),
            ))
            .await;
        assert!(login_result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_and_login_within_retention_period() {
        let service = setup().await;
        let user_entity = create_test_user(&service).await.unwrap();

        // 1. Start OTP challenge for account deletion
        let challenge_token = service
            .otp_challenge(
                TEST_USER_EMAIL.to_owned(),
                ContactType::Email,
                ActionType::DeleteAccount,
                None,
            )
            .await
            .expect("Failed to generate challenge token");

        // 2. Validate challenge token and get challenge ID
        let claims = service
            .token_service
            .validate_challenge_token(&challenge_token)
            .expect("Failed to validate challenge token");

        // 3. Retrieve OTP code
        let otp_entity = service
            .otp_repository
            .find_otp_by_id(&claims.challenge_id)
            .await
            .expect("Failed to find OTP entity");

        // 4. Confirm OTP to get action token
        let action_token = service
            .confirm_otp(&challenge_token, &otp_entity.otp_code)
            .await
            .expect("Failed to confirm OTP");

        // 5. Delete account
        let delete_result = service
            .delete_account(&action_token)
            .await
            .expect("Failed to delete account");

        assert!(delete_result);

        // 6. Verify user is soft deleted
        let user_id = user_entity.id.unwrap();
        let deleted_user = service
            .user_repository
            .find_by_id(&user_id)
            .await
            .expect("Failed to find user")
            .expect("User not found");

        assert!(deleted_user.deleted_at.is_some());

        // 7. Attempt login within retention period
        let login_result = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                TEST_USER_PASSWORD.to_owned(),
            ))
            .await;

        assert!(login_result.is_ok());
        let session = login_result.unwrap();
        assert_eq!(session.user.id, user_entity.id.unwrap().to_string());
    }

    #[tokio::test]
    async fn test_delete_user_and_login_after_retention_period() {
        let service = setup().await;
        let user_entity = create_test_user(&service).await.unwrap();
        let user_id = user_entity.id.unwrap().to_string();
        let email = TEST_USER_EMAIL.to_owned();

        // 1. Start OTP challenge for account deletion
        let challenge_token = service
            .otp_challenge(
                email.clone(),
                ContactType::Email,
                ActionType::DeleteAccount,
                None,
            )
            .await
            .expect("Failed to generate challenge token");

        // 2. Validate challenge token
        let claims = service
            .token_service
            .validate_challenge_token(&challenge_token)
            .expect("Failed to validate challenge token");

        // 3. Retrieve OTP code
        let otp_entity = service
            .otp_repository
            .find_otp_by_id(&claims.challenge_id)
            .await
            .expect("Failed to find OTP entity");

        // 4. Confirm OTP to get action token
        let action_token = service
            .confirm_otp(&challenge_token, &otp_entity.otp_code)
            .await
            .expect("Failed to confirm OTP");

        // 5. Delete account
        let delete_result = service
            .delete_account(&action_token)
            .await
            .expect("Failed to delete account");

        assert!(delete_result);

        // 6. Find the updated user entity
        let mut user_entity = service
            .user_repository
            .find_by_id(&ObjectId::parse_str(&user_id).unwrap())
            .await
            .expect("Failed to find user")
            .unwrap();

        // 6. Edit the deleted_at date to be before the retention period
        user_entity.deleted_at = Some(
            DateTime::from(user_entity.deleted_at.unwrap()) - service.retention_period,
        );

        service
            .user_repository
            .update(&user_entity)
            .await
            .expect("Failed to update user entity");

        // 7. Attempt login after retention period
        let login_result = service
            .login(LoginData::Email(
                email.clone(),
                TEST_USER_PASSWORD.to_owned(),
            ))
            .await;

        assert!(login_result.is_err());
        assert!(matches!(
            login_result.unwrap_err(),
            AuthError::AccountPermanentlyDeleted
        ));
    }

    #[tokio::test]
    async fn test_update_password() {
        let service = setup().await;
        let user_entity = create_test_user(&service).await.unwrap();

        // 1. Login with current password
        let login_result = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                TEST_USER_PASSWORD.to_owned(),
            ))
            .await;
        assert!(login_result.is_ok());
        let session_token = login_result.unwrap().session_token;

        // 2. Update password
        let new_password = "new_secure_password123";
        let update_result = service
            .update_password(&session_token, TEST_USER_PASSWORD, new_password)
            .await;

        assert!(update_result.is_ok());

        // 3. Verify old password no longer works
        let old_login_result = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                TEST_USER_PASSWORD.to_owned(),
            ))
            .await;
        assert!(old_login_result.is_err());

        // 4. Verify new password works
        let new_login_result = service
            .login(LoginData::Email(
                TEST_USER_EMAIL.to_owned(),
                new_password.to_owned(),
            ))
            .await;
        assert!(new_login_result.is_ok());

        // 5. Test password reuse prevention
        let old_password = new_password.clone();
        let new_password = TEST_USER_PASSWORD.to_owned();

        let reuse_result = service
            .update_password(&session_token, &old_password, &new_password)
            .await;

        assert!(reuse_result.is_err());
        assert!(matches!(
            reuse_result.unwrap_err(),
            AuthError::Password(PasswordError::PreviouslyUsed)
        ));
    }

    async fn create_test_user(service: &AuthServiceImpl) -> Result<UserEntity, AuthDataError> {
        let user_data = UserCreationData {
            username: TEST_USER_USERNAME.to_owned(),
            fullname: "Test User".to_owned(),
            password: TEST_USER_PASSWORD.to_owned(),
            contact_type: Some(ContactType::Email),
            contact_value: Some(TEST_USER_EMAIL.to_owned()),
            birthdate: Utc::now(),
            gender: auth_data::Gender::Male,
            country: Some("US".to_owned()),
            roles: vec!["viewer".to_string()],
        };

        // Create user directly in repository
        let salted_hash = service.hashing_service.hash_password("password123");
        service
            .user_repository
            .create_user(user_data, salted_hash.hash, salted_hash.salt)
            .await
    }
}
