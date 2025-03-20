use auth_data::{ActionType, Contact, ContactType, Gender};
use auth_domain::{AuthError, User};
use chrono::Utc;
use prost_types::Timestamp;
use crate::proto_stub::auth::protobuf::otp_challenge_request::ActionTypeMsg;
use crate::proto_stub::auth::protobuf::{ContactMessage, GenderMessage, UserProfileMessage};

impl From<User> for UserProfileMessage {
    fn from(profile: User) -> Self {
        UserProfileMessage {
            id: profile.id,
            username: profile.username,
            fullname: profile.fullname,
            profile_picture: profile.profile_picture,
            gender: profile.gender as i32,
            country: profile.country,
            bio: profile.bio,
            birthdate: Some(profile.birthdate.to_timestamp()),
            contacts: profile.contacts.into_iter().map(ContactMessage::from).collect(),
            created_at: Some(profile.created_at.to_timestamp()),
            updated_at: Some(profile.updated_at.to_timestamp()),
        }
    }
}

impl From<Contact> for ContactMessage {

    fn from(contact: Contact) -> Self {
        let contact_type: ContactTypeMsg = contact.contact_type.into();
        Self {
            contact_type: contact_type as i32,
            value: contact.contact_value,
            is_primary: contact.is_primary.unwrap_or(false),
            verified_at: contact.verified_at.map(|time| time.to_timestamp()),
        }   
    }
}

impl From<ContactType> for ContactTypeMsg {
    fn from(contact_type: ContactType) -> Self {
        match contact_type {
            ContactType::Email => ContactTypeMsg::Email,
            ContactType::Phone => ContactTypeMsg::Phone,
        }
    }
}

pub trait ToTimestamp {
    fn to_timestamp(&self) -> Timestamp;
}

pub trait ToChrono {
    fn to_chrono(&self) -> chrono::DateTime<Utc>;
}

impl ToChrono for Timestamp {
    fn to_chrono(&self) -> chrono::DateTime<Utc> {
        chrono::DateTime::from_timestamp(self.seconds, self.nanos as u32).unwrap()
    }
}

impl ToTimestamp for chrono::DateTime<Utc> {
    fn to_timestamp(&self) -> Timestamp {
        Timestamp {
            seconds: self.timestamp(),
            nanos: self.timestamp_subsec_nanos() as i32,
        }
    }
}

impl From<ActionTypeMsg> for ActionType {
    fn from(action_type: ActionTypeMsg) -> Self {
        match action_type {
            ActionTypeMsg::Registration => ActionType::Registration,
            ActionTypeMsg::PasswordReset => ActionType::PasswordReset,
            ActionTypeMsg::DeleteAccount => ActionType::DeleteAccount,
            ActionTypeMsg::AddContact => ActionType::AddContact,
        }
    }
}

impl From<ContactTypeMsg> for ContactType {
    fn from(contact_type: ContactTypeMsg) -> Self {
        match contact_type {
            ContactTypeMsg::Email => ContactType::Email,
            ContactTypeMsg::Phone => ContactType::Phone,
        }
    }
}

impl From<GenderMessage> for Gender {
    fn from(gender: GenderMessage) -> Self {
        match gender {
            GenderMessage::Male => Gender::Male,
            GenderMessage::Female => Gender::Female,
            GenderMessage::Other => Gender::Other,
        }
    }
}




use tonic::{Code, Status};
use crate::proto_stub::auth::protobuf::contact_message::ContactTypeMsg;

pub trait IntoStatus {
    fn into_status(self) -> Status;
}


impl IntoStatus for AuthError {
    fn into_status(self) -> Status {
        match self {
            // 404 Not Found
            AuthError::NotFound => Status::new(Code::NotFound, "Entity not found"),
            AuthError::UserNotFound => Status::new(Code::NotFound, "User not found"),
            AuthError::ContactNotFound => Status::new(Code::NotFound, "Contact not found"),

            // 409 Conflict (for duplicate resources)
            AuthError::DuplicateUsername => Status::new(Code::AlreadyExists, "Username already exists"),
            AuthError::ContactAlreadyUsed => Status::new(Code::AlreadyExists, "Contact is already used in other account"),
            AuthError::UsernameTaken => Status::new(Code::AlreadyExists, "Username already taken"),
            AuthError::EmailTaken => Status::new(Code::AlreadyExists, "Email already taken"),

            // 400 Bad Request (invalid input)
            AuthError::InvalidContactValue => Status::new(Code::InvalidArgument, "Invalid contact value"),
            AuthError::InvalidUsername => Status::new(Code::InvalidArgument, "Invalid username"),
            AuthError::InvalidProfileData => Status::new(Code::InvalidArgument, "Invalid profile data"),
            AuthError::CannotRemovePrimaryContact => Status::new(Code::InvalidArgument, "Cannot remove primary contact"),
            AuthError::InvalidCredentials => Status::new(Code::InvalidArgument, "Invalid credentials"),

            // 401 Unauthorized
            AuthError::Unauthorized => Status::new(Code::Unauthenticated, "Unauthorized access"),

            // 403 Forbidden
            AuthError::AccountLocked => Status::new(Code::PermissionDenied, "Account is locked"),
            AuthError::TokenExpired => Status::new(Code::PermissionDenied, "Token has expired"),
            AuthError::AccountDeleted => Status::new(Code::PermissionDenied, "Account has been deleted"),
            AuthError::ContactNotVerified => Status::new(Code::PermissionDenied, "Contact is not verified"),
            AuthError::TokenRevoked => Status::new(Code::PermissionDenied, "Token has been revoked"),
            AuthError::ActionNotPermitted => Status::new(Code::PermissionDenied, "Action not permitted"),
            AuthError::AccountPermanentlyDeleted => Status::new(Code::PermissionDenied, "Account permanently deleted"),

            // 500 Internal Server Error (catch-all for server-side issues)
            AuthError::OtpError(err) => Status::new(Code::Internal, format!("OTP error: {}", err)),
            AuthError::MongoError(err) => Status::new(Code::Internal, format!("MongoDB error: {}", err)),
            AuthError::SerializationError(err) => Status::new(Code::Internal, format!("Serialization error: {}", err)),
            AuthError::InternalError(err) => Status::new(Code::Internal, format!("Internal error: {}", err)),
            AuthError::TokenCreationError => Status::new(Code::Internal, "Token creation error"),
            AuthError::DataError(err) => Status::new(Code::Internal, format!("Data error: {}", err)),
            AuthError::Password(err) => Status::new(Code::Internal, format!("Password error: {}", err)),
        }
    }
}