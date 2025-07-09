use bcrypt::{hash, verify, DEFAULT_COST};
use regex::Regex;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("Password hashing failed: {0}")]
    HashingFailed(String),
    #[error("Password verification failed: {0}")]
    VerificationFailed(String),
    #[error("Password validation failed: {0}")]
    ValidationFailed(String),
    #[error("Password too weak: {violations:?}")]
    WeakPassword { violations: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct PasswordConfig {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
    pub bcrypt_cost: u32,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            bcrypt_cost: DEFAULT_COST,
        }
    }
}

pub struct PasswordService {
    config: PasswordConfig,
    uppercase_regex: Regex,
    lowercase_regex: Regex,
    number_regex: Regex,
    special_char_regex: Regex,
}

impl PasswordService {
    pub fn new(config: PasswordConfig) -> Self {
        Self {
            config,
            uppercase_regex: Regex::new(r"[A-Z]").unwrap(),
            lowercase_regex: Regex::new(r"[a-z]").unwrap(),
            number_regex: Regex::new(r"[0-9]").unwrap(),
            special_char_regex: Regex::new(r"[!@#$%^&*(),.?:{}|<>]").unwrap(),
        }
    }

    // Hash a password using bcrypt
    pub fn hash_password(&self, password: &str) -> Result<String, PasswordError> {
        // Validate password before hashing
        self.validate_password_strength(password)?;

        hash(password, self.config.bcrypt_cost)
            .map_err(|e| PasswordError::HashingFailed(e.to_string()))
    }

    // Verify a password against its hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, PasswordError> {
        verify(password, hash)
            .map_err(|e| PasswordError::VerificationFailed(e.to_string()))
    }

    // Validate password strength according to configured rules
    pub fn validate_password_strength(&self, password: &str) -> Result<(), PasswordError> {
        let mut violations = Vec::new();

        // Check minimum length
        if password.len() < self.config.min_length {
            violations.push(format!("Password must be at least {} chars", self.config.min_length));
        }

        // Check for uppercase letters
        if self.config.require_uppercase && !self.uppercase_regex.is_match(password) {
            violations.push("Password must contain uppercase letters".to_string());
        }

        // Check for lowercase letters
        if self.config.require_lowercase && !self.lowercase_regex.is_match(password) {
            violations.push("Password must contain lowercase letters".to_string());
        }

        // Check for numbers
        if self.config.require_numbers && !self.number_regex.is_match(password) {
            violations.push("Password must contain numbers".to_string());
        }

        // Check for special characters
        if self.config.require_special_chars && !self.special_char_regex.is_match(password) {
            violations.push("Password must contain special characters".to_string());
        }

        if !violations.is_empty() {
            return Err(PasswordError::WeakPassword { violations });
        }

        Ok(())
    }

    // Generate password strength score (0-100)
    pub fn calculate_password_strength(&self, password: &str) -> u8 {
        let mut score = 0u8;

        // Length score (max 25 points)
        let length_score = (password.len().min(20) * 25 / 20) as u8;
        score += length_score.min(25);

        // Character variety (max 40 points)
        let mut variety_score = 0;
        if self.uppercase_regex.is_match(password) { variety_score += 10; }
        if self.lowercase_regex.is_match(password) { variety_score += 10; }
        if self.number_regex.is_match(password) { variety_score += 10; }
        if self.special_char_regex.is_match(password) { variety_score += 10; }
        score += variety_score;

        // Complexity bonus (max 20 points)
        let unique_chars = password.chars().collect::<std::collections::HashSet<_>>().len();
        let complexity_score = (unique_chars.min(10) * 20 / 10) as u8;
        score += complexity_score;

        score.min(100)
    }

    // Generate a secure random password
    pub fn generate_secure_password(&self, length: usize) -> String {
        use rand::{thread_rng, Rng};
        use rand::seq::SliceRandom;
        use rand::prelude::IteratorRandom;

        let mut rng = thread_rng();
        let length = length.max(self.config.min_length);
        
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let lowercase = "abcdefghijklmnopqrstuvwxyz";
        let numbers = "0123456789";
        let special = "!@#$%^&*()";
        
        let mut password = String::new();
        
        // Ensure at least one character from each required category
        if self.config.require_uppercase {
            password.push(uppercase.chars().choose(&mut rng).unwrap());
        }
        if self.config.require_lowercase {
            password.push(lowercase.chars().choose(&mut rng).unwrap());
        }
        if self.config.require_numbers {
            password.push(numbers.chars().choose(&mut rng).unwrap());
        }
        if self.config.require_special_chars {
            password.push(special.chars().choose(&mut rng).unwrap());
        }
        
        // Fill the rest with random characters from all categories
        let all_chars = format!("{}{}{}{}", uppercase, lowercase, numbers, special);
        let all_chars: Vec<char> = all_chars.chars().collect();
        
        while password.len() < length {
            password.push(*all_chars.choose(&mut rng).unwrap());
        }
        
        // Shuffle the password to avoid predictable patterns
        let mut password_chars: Vec<char> = password.chars().collect();
        password_chars.shuffle(&mut rng);
        
        password_chars.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> PasswordService {
        PasswordService::new(PasswordConfig::default())
    }

    #[test]
    fn test_password_hashing_and_verification() {
        let service = create_test_service();
        let password = "StrongPassword123!";
        
        // Hash password
        let hash = service.hash_password(password).unwrap();
        assert!(!hash.is_empty());
        assert_ne!(hash, password);
        
        // Verify correct password
        assert!(service.verify_password(password, &hash).unwrap());
        
        // Verify incorrect password
        assert!(!service.verify_password("WrongPassword123!", &hash).unwrap());
    }

    #[test]
    fn test_password_strength_validation() {
        let service = create_test_service();
        
        // Strong password should pass
        assert!(service.validate_password_strength("StrongPassword123!").is_ok());
        
        // Weak passwords should fail
        assert!(service.validate_password_strength("weak").is_err());
        assert!(service.validate_password_strength("password").is_err());
        assert!(service.validate_password_strength("12345678").is_err());
    }

    #[test]
    fn test_password_strength_calculation() {
        let service = create_test_service();
        
        let strong_password = "MyVeryStrongP@ssw0rd!";
        let weak_password = "password";
        
        let strong_score = service.calculate_password_strength(strong_password);
        let weak_score = service.calculate_password_strength(weak_password);
        
        assert!(strong_score > weak_score);
        assert!(strong_score >= 60); // Should be considered strong
        assert!(weak_score <= 40);   // Should be considered weak
    }

    #[test]
    fn test_password_generation() {
        let service = create_test_service();
        
        let password = service.generate_secure_password(12);
        assert_eq!(password.len(), 12);
        
        // Generated password should pass validation
        assert!(service.validate_password_strength(&password).is_ok());
        
        // Should have good strength score
        let score = service.calculate_password_strength(&password);
        assert!(score >= 60);
    }
} 