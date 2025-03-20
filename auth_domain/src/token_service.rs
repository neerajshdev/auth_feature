use crate::models::{ActionClaims, ChallengeClaims, SessionClaims};
use async_trait::async_trait;
use auth_data::entities::ActionType;
use auth_data::ContactType;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;
use crate::error::AuthError;

pub struct TokenConfig {
    pub secret: String,
    pub audience: Vec<String>,
    pub issuer: String,
    pub algorithm: Algorithm,
}

impl TokenConfig {
    pub fn new(
        secret: String,
        audience: Vec<String>,
        issuer: String,
        algorithm: Algorithm,
    ) -> Self {
        Self {
            secret,
            audience,
            issuer,
            algorithm,
        }
    }
}

/// Token service for creating and validating tokens
#[async_trait]
pub trait TokenService: Send + Sync {
    fn new(config: TokenConfig) -> Self
    where
        Self: Sized;

    fn create_challenge_token(
        &self,
        user_id: &str,
        action_type: ActionType,
        challenge_id: &str,
        expires_in: Duration,
        contact_value: Option<String>,
        contact_type: ContactType,
        action_id: &str,
    ) -> Result<String, AuthError>;

    fn validate_challenge_token(&self, token: &str) -> Result<ChallengeClaims, AuthError>;

    fn create_action_token(
        &self,
        user_id: &str,
        action_type: ActionType,
        action_id: &str,
    ) -> Result<String, AuthError>;

    fn validate_action_token(&self, token: &str) -> Result<ActionClaims, AuthError>;

    fn create_session_token(&self, user_id: &str, roles: Vec<String>) -> Result<String, AuthError>;

    fn validate_session_token(&self, token: &str) -> Result<SessionClaims, AuthError>;

    async fn is_token_revoked(&self, token: &str) -> Result<bool, AuthError>;
}

pub struct JwtTokenService {
    config: TokenConfig,
}

impl JwtTokenService {
    pub(crate) fn new(config: TokenConfig) -> Self {
        Self { config }
    }

    fn encode<T>(&self, claims: &T) -> Result<String, AuthError>
    where
        T: Serialize,
    {
        let key = EncodingKey::from_secret(self.config.secret.as_bytes());
        encode(&Header::new(self.config.algorithm), &claims, &key)
            .map_err(|_| AuthError::TokenCreationError)
    }

    fn decode<T>(&self, token: &str) -> Result<T, AuthError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let key = DecodingKey::from_secret(self.config.secret.as_bytes());
        let mut validation = Validation::new(self.config.algorithm);
        validation.set_audience(&self.config.audience);
        validation.set_issuer(&[&self.config.issuer]);
        jsonwebtoken::decode::<T>(token, &key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|_| AuthError::Unauthorized)
    }
}

#[async_trait]
impl TokenService for JwtTokenService {
    fn new(config: TokenConfig) -> Self
    where
        Self: Sized,
    {
        JwtTokenService::new(config)
    }

    fn create_challenge_token(
        &self,
        user_id: &str,
        action_type: ActionType,
        challenge_id: &str,
        expires_in: Duration,
        contact_value: Option<String>,
        contact_type: ContactType,
        action_id: &str,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let claims = ChallengeClaims {
            sub: user_id.to_string(),
            action_id: action_id.to_string(),
            challenge_id: challenge_id.to_string(),
            action_type,
            contact_value,
            contact_type,
            iat: now.timestamp(),
            exp: (now + expires_in).timestamp(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
        };

        self.encode(&claims)
    }

    fn validate_challenge_token(&self, token: &str) -> Result<ChallengeClaims, AuthError> {
        self.decode(token)
    }

    fn create_action_token(
        &self,
        user_id: &str,
        action_type: ActionType,
        action_id: &str,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let claims = ActionClaims {
            sub: user_id.to_string(),
            action_type,
            action_id: action_id.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(10)).timestamp(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
        };

        self.encode(&claims)
    }

    fn validate_action_token(&self, token: &str) -> Result<ActionClaims, AuthError> {
        self.decode(token)
    }

    fn create_session_token(&self, user_id: &str, roles: Vec<String>) -> Result<String, AuthError> {
        let now = Utc::now();
        let expiry = now + Duration::days(30);

        let claims = SessionClaims {
            sub: user_id.to_string(),
            exp: expiry.timestamp() as usize,
            iat: now.timestamp() as usize,
            iss: self.config.issuer.clone(),
            aud: self.config.audience[0].clone(),
            roles,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        self.encode(&claims)
    }

    fn validate_session_token(&self, token: &str) -> Result<SessionClaims, AuthError> {
        self.decode(token)
    }

    async fn is_token_revoked(&self, token: &str) -> Result<bool, AuthError> {
        // Implementation of is_token_revoked method
        Ok(false) // Placeholder return, actual implementation needed
    }
}
