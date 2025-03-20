use crate::models::User;
use auth_data::entities::UserEntity;


pub fn user_entity_to_user(user: UserEntity) -> User {
    User {
        id: user.id.map(|id| id.to_hex()).unwrap_or_default(),
        username: user.username,
        fullname: user.fullname,
        birthdate: user.birthdate.into(),
        gender: user.gender,
        country: user.country,
        bio: user.bio,
        profile_picture: user.profile_picture,
        contacts: user.contacts,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
} 

