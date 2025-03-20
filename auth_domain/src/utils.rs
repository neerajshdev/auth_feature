use regex::Regex;

/// Validates an email address using regex and additional checks
pub fn is_valid_email(email: &str) -> bool {
    // More robust email validation using regex
    let email_regex = Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        .expect("Failed to compile email regex");

    // Check length constraints
    if email.len() > 254 {
        return false;
    }

    // Validate using regex
    if !email_regex.is_match(email) {
        return false;
    }

    // Check for consecutive dots
    if email.contains("..") {
        return false;
    }

    // Split into local and domain parts
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    // Validate domain part
    let domain = parts[1];
    if domain.len() > 253 {
        return false;
    }

    // Check for valid TLD
    let domain_parts: Vec<&str> = domain.split('.').collect();
    if domain_parts.len() < 2 {
        return false;
    }

    // Last part (TLD) should be at least 2 characters
    if domain_parts.last().map(|tld| tld.len() < 2).unwrap_or(true) {
        return false;
    }

    true
}

/// Validates a phone number
pub fn is_valid_phone(phone: &str) -> bool {
    // Allow '+' as the first character for international numbers
    let mut chars = phone.chars();
    if let Some(first_char) = chars.next() {
        if first_char == '+' {
            // After '+', the rest should be numeric
            chars.all(|c| c.is_numeric()) && phone.len() >= 10
        } else {
            // If no '+', the entire string should be numeric
            phone.chars().all(|c| c.is_numeric()) && phone.len() >= 10
        }
    } else {
        // Empty string is invalid
        false
    }
} 