use tonic::{Request, Response, Status};

use crate::mapper::{IntoStatus, ToChrono};
use crate::proto_stub::auth::protobuf::auth_grpc_service_server::AuthGrpcService;
use crate::proto_stub::auth::protobuf::check_username_response::CheckResult;
use crate::proto_stub::auth::protobuf::confirm_otp_response::ErrorCodeMsg;
use crate::proto_stub::auth::protobuf::login_request::LoginBy;
use crate::proto_stub::auth::protobuf::otp_challenge_request::ActionTypeMsg;
use crate::proto_stub::auth::protobuf::update_password_response::PasswordErrorMsg;
use crate::proto_stub::auth::protobuf::{DeleteAccountRequest, DeleteAccountResponse, GenderMessage, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, OtpChallengeRequest, OtpChallengeResponse, RefreshTokenRequest, RefreshTokenResponse, RegisterRequest, RegisterResponse, ResetPasswordRequest, ResetPasswordResponse};
use auth_data::entities::UserCreationData;
use auth_domain::error::AuthError;
use auth_domain::models::{CheckUsernameResult, LoginData};
use auth_domain::service::AuthService;
use proto_stub::auth::protobuf::ContactMessage;

// Add these missing imports
use crate::proto_stub::auth::protobuf::{
    AddContactRequest, AddContactResponse, AddRoleRequest, AddRoleResponse, CheckUsernameRequest,
    CheckUsernameResponse, ConfirmOtpRequest, ConfirmOtpResponse, GetProfileRequest,
    GetProfileResponse, GetRolesRequest, GetRolesResponse, RemoveContactRequest,
    RemoveContactResponse, RemoveRoleRequest, RemoveRoleResponse, SetPrimaryContactRequest,
    SetPrimaryContactResponse, UpdatePasswordRequest, UpdatePasswordResponse, UpdateProfileRequest,
    UpdateProfileResponse,
};
use auth_data::entities::ActionType;
use auth_domain::models::ProfileUpdateData;
use crate::proto_stub;
use crate::proto_stub::auth::protobuf::contact_message::ContactTypeMsg;

pub struct AuthGrpcServiceImpl {
    auth_service: Box<dyn AuthService + Send + Sync>,
}

impl AuthGrpcServiceImpl {
    pub fn new(auth_service: Box<dyn AuthService + Send + Sync>) -> Self {
        Self { auth_service }
    }
}

#[tonic::async_trait]
impl AuthGrpcService for AuthGrpcServiceImpl {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();

        // Convert protobuf LoginBy to domain LoginData
        let login_data = match req.login_by {
            Some(login_by) => match login_by {
                LoginBy::Email(email) => LoginData::Email(email, req.password),
                LoginBy::Username(username) => LoginData::Username(username, req.password),
                LoginBy::Phone(phone) => LoginData::Phone(phone, req.password),
            },
            None => return Err(Status::invalid_argument("Login identifier is required")),
        };

        // Call domain service with the proper login data
        let result = self.auth_service.login(login_data).await;

        match result {
            Ok(auth_result) => Ok(Response::new(LoginResponse {
                session_token: auth_result.session_token,
                user: Some(auth_result.user.into()),
            })),
            Err(AuthError::InvalidCredentials) => {
                Err(Status::unauthenticated("Invalid credentials"))
            }
            Err(AuthError::AccountLocked) => Err(Status::permission_denied("Account is locked")),
            Err(AuthError::InternalError(_)) => Err(Status::internal("Internal server error")),
            _ => Err(Status::unknown("Unknown error occurred")),
        }
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let req = request.into_inner();

        if req.session_token.is_empty() {
            return Err(Status::invalid_argument("Session token is required"));
        }

        let result = self.auth_service.logout(&req.session_token).await;

        match result {
            Ok(_) => Ok(Response::new(LogoutResponse {
                success: true,
                message: "Logged out successfully".to_string(),
            })),
            Err(AuthError::InvalidCredentials) => {
                Err(Status::unauthenticated("Invalid session token"))
            }
            Err(AuthError::InternalError(_)) => Err(Status::internal("Internal server error")),
            _ => Err(Status::unknown("Unknown error occurred")),
        }
    }

    
    async fn refresh_token(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        let req = request.into_inner();

        if req.refresh_token.is_empty() {
            return Err(Status::invalid_argument("Refresh token is required"));
        }

        // service not implemented
        Err(Status::unimplemented("Refresh token not implemented"))
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        // Validate required fields
        if req.action_token.is_empty() || req.username.is_empty() || req.password.is_empty() {
            return Err(Status::invalid_argument(
                "Action token, username and password are required",
            ));
        }
        // Convert protobuf to UserCreationData
        let user_data = UserCreationData {
            username: req.username,
            fullname: req.fullname,
            password: req.password,
            birthdate: Default::default(),
            gender: Default::default(),
            country: req.country,
            // user contact details are already taken in the otp challenge request
            contact_type: None, 
            contact_value: None,
            roles: req.roles.into_iter().map(|r| r.into()).collect(),
        };

        // Call domain service with action token and user data
        let result = self
            .auth_service
            .register(&req.action_token, user_data)
            .await;

        match result {
            Ok(auth_result) => Ok(Response::new(RegisterResponse {
                user: Some(auth_result.user.into()),
                session_token: auth_result.session_token,
            })),

            Err(e) => Err(e.into_status()),
        }
    }

    async fn delete_account(
        &self,
        request: Request<DeleteAccountRequest>,
    ) -> Result<Response<DeleteAccountResponse>, Status> {
        let req = request.into_inner();

        if req.session_token.is_empty() {
            return Err(Status::invalid_argument("Session token is required"));
        }

        self.auth_service.delete_account(&req.session_token)
        .await
        .map_err(|e| e.into_status())?;

        Ok(Response::new(DeleteAccountResponse {
            success: true,
            message: "Account deleted successfully".to_string(),
        }))
    }

    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResetPasswordResponse>, Status> {
        let req = request.into_inner();

        // Validate required fields
        if req.action_token.is_empty() || req.new_password.is_empty() {
            return Err(Status::invalid_argument(
                "Action token and new password are required",
            ));
        }

        // Call domain service to reset the password
        self.auth_service.reset_password(&req.action_token, &req.new_password)
        .await
        .map_err(|e| e.into_status())?;

        Ok(Response::new(ResetPasswordResponse {
            success: true,
            message: "Password has been reset successfully".to_string(),
        }))
    }

    async fn otp_challenge(
        &self,
        request: Request<OtpChallengeRequest>,
    ) -> Result<Response<OtpChallengeResponse>, Status> {
        let req = request.into_inner();

        // Validate required fields
        if req.contact_value.is_empty() {
            return Err(Status::invalid_argument("Contact value is required"));
        }

        // Extract action type from the request
        let action_type = match ActionTypeMsg::try_from(req.action_type) {
            Ok(msg) => match msg {
                ActionTypeMsg::Registration => ActionType::Registration,
                ActionTypeMsg::PasswordReset => ActionType::PasswordReset,
                ActionTypeMsg::DeleteAccount => ActionType::DeleteAccount,
                ActionTypeMsg::AddContact => ActionType::AddContact,
            },
            Err(_) => return Err(Status::invalid_argument("Invalid action type")),
        };

        let contact_type = ContactTypeMsg::try_from(req.contact_type).unwrap();

        let challenge_token = self
            .auth_service
            .otp_challenge(
                req.contact_value,
                contact_type.into(),
                action_type,
                req.session_token,
            )
            .await
            .map_err(|e| e.into_status())?;

        Ok(Response::new(OtpChallengeResponse {
            otp_challenge_token: challenge_token,
            message: "OTP has been sent to your email".to_string(),
        }))
    }

    async fn confirm_otp(
        &self,
        request: Request<ConfirmOtpRequest>,
    ) -> Result<Response<ConfirmOtpResponse>, Status> {
        let req = request.into_inner();

        if req.challenge_token.is_empty() || req.otp.is_empty() {
            return Err(Status::invalid_argument(
                "Challenge token and OTP are required",
            ));
        }

        let action_token = self
            .auth_service
            .confirm_otp(&req.challenge_token, &req.otp)
            .await
            .map_err(|e| e.into_status())?;

        Ok(Response::new(ConfirmOtpResponse {
            action_token: Some(action_token),
            success: true,
            error_code: ErrorCodeMsg::None as i32,
        }))
    }

    async fn update_password(
        &self,
        request: Request<UpdatePasswordRequest>,
    ) -> Result<Response<UpdatePasswordResponse>, Status> {
        let req = request.into_inner();

        // Validate required fields
        if req.current_password.is_empty() || req.new_password.is_empty() {
            return Err(Status::invalid_argument(
                "Current and new password are required",
            ));
        }

        // Call domain service to update password
        self.auth_service.update_password(&req.session_token, &req.current_password, &req.new_password)
        .await
        .map_err(|e| e.into_status())?;

        Ok(Response::new(UpdatePasswordResponse {
            success: true,
            message: "Password updated successfully".to_string(),
            error_code: PasswordErrorMsg::None as i32,
        }))
    }


    async fn get_profile(
        &self,
        request: Request<GetProfileRequest>,
    ) -> Result<Response<GetProfileResponse>, Status> {
        let req = request.into_inner();

        if req.session_token.is_empty() {
            return Err(Status::invalid_argument("Session token is required"));
        }

        let profile = self.auth_service.get_profile(&req.session_token).await
        .map_err(|e| e.into_status())?;

        Ok(Response::new(GetProfileResponse {
            user: Some(profile.into()),
        }))
    }

    async fn update_profile(
        &self,
        request: Request<UpdateProfileRequest>,
    ) -> Result<Response<UpdateProfileResponse>, Status> {
        let req = request.into_inner();

        if req.session_token.is_empty() {
            return Err(Status::invalid_argument("Session token is required"));
        }

        let profile = self
            .auth_service
            .update_profile(&req.session_token, 
                ProfileUpdateData {
                    fullname: req.fullname,
                    gender: req.gender.map(|g| {
                        GenderMessage::try_from(g).unwrap().into()
                    }),
                    country: req.country,
                    bio: req.bio,
                    birthdate: req.birthdate.map(|ts| ts.to_chrono()),
                    profile_picture: req.profile_picture,
                }
            )
            .await
            .map_err(|e| e.into_status())?;

        Ok(Response::new(UpdateProfileResponse {
            user: Some(profile.into()),
        }))
    }

    async fn add_contact(
        &self,
        request: Request<AddContactRequest>,
    ) -> Result<Response<AddContactResponse>, Status> {
        let req = request.into_inner();

        if req.session_token.is_empty() || req.action_token.is_empty() {
            return Err(Status::invalid_argument(
                "Session token and action token are required",
            ));
        }

        let result = self
            .auth_service
            .add_contact(&req.action_token)
            .await
            .map_err(|e| e.into_status())?;

        Ok(Response::new(AddContactResponse {
            success: result,
        }))
    }

    async fn remove_contact(
        &self,
        request: Request<RemoveContactRequest>,
    ) -> Result<Response<RemoveContactResponse>, Status> {
        // TODO: Implement contact removal logic
        unimplemented!()
    }

    async fn set_primary_contact(
        &self,
        request: Request<SetPrimaryContactRequest>,
    ) -> Result<Response<SetPrimaryContactResponse>, Status> {
        // TODO: Implement primary contact setting logic
        unimplemented!()
    }

    async fn check_username(
        &self,
        request: Request<CheckUsernameRequest>,
    ) -> Result<Response<CheckUsernameResponse>, Status> {
        let req = request.into_inner();

        // Validate session token
        if req.session_token.is_empty() {
            return Err(Status::invalid_argument("Session token is required"));
        }

        // Validate username is provided
        if req.username.is_empty() {
            return Err(Status::invalid_argument("Username is required"));
        }

        // Call domain service to check username availability
        let result = self
            .auth_service
            .check_username(&req.session_token, &req.username)
            .await
            .map_err(|e| e.into_status())?;

        Ok(Response::new(CheckUsernameResponse {
            result: match result {
                CheckUsernameResult::Valid => CheckResult::Valid as i32,
                CheckUsernameResult::AlreadyTaken => CheckResult::AlreadyTaken as i32,
                CheckUsernameResult::Invalid => CheckResult::Invalid as i32,
            },
        }))
    }

    async fn add_role(
        &self,
        request: Request<AddRoleRequest>,
    ) -> Result<Response<AddRoleResponse>, Status> {
        // TODO: Implement role addition logic
        unimplemented!()
    }

    async fn remove_role(
        &self,
        request: Request<RemoveRoleRequest>,
    ) -> Result<Response<RemoveRoleResponse>, Status> {
        // TODO: Implement role removal logic
        unimplemented!()
    }

    async fn get_roles(
        &self,
        request: Request<GetRolesRequest>,
    ) -> Result<Response<GetRolesResponse>, Status> {
        // TODO: Implement role retrieval logic
        unimplemented!()
    }
}
