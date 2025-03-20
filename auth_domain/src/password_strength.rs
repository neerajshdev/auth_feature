use crate::models::PasswordStrength;

/// Checks the strength of a password and returns a PasswordStrength enum
pub fn check_password_strength(password: &str) -> PasswordStrength {
    let mut score = 0;

    // Length check
    if password.len() >= 8 {
        score += 1;
    }
    if password.len() >= 12 {
        score += 1;
    }

    // Character type checks
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        score += 1;
    }
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        score += 1;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        score += 1;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        score += 1;
    }

    match score {
        0..=2 => PasswordStrength::TooWeak,
        3..=4 => PasswordStrength::Basic,
        5..=6 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_strength() {
        assert_eq!(check_password_strength("short"), PasswordStrength::TooWeak);
        assert_eq!(check_password_strength("longenough"), PasswordStrength::Basic);
        assert_eq!(check_password_strength("GoodPass1"), PasswordStrength::Strong);
        assert_eq!(check_password_strength("Very$tr0ngPass!"), PasswordStrength::VeryStrong);
    }
} 