use anyhow::{Result, ensure};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

pub fn hash_password(password: &str) -> Result<String> {
    ensure!(
        password.len() >= 8,
        "password must contain at least 8 characters"
    );
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("failed to generate secure random salt"))?;

    let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).unwrap();
    let mut hash = [0u8; HASH_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &mut hash,
    );

    Ok(format!(
        "$pbkdf2-sha256$i={}${}${}",
        iterations,
        hex::encode(salt),
        hex::encode(hash),
    ))
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 5 || parts[1] != "pbkdf2-sha256" {
        return false;
    }
    let iterations: u32 = match parts[2].strip_prefix("i=").and_then(|s| s.parse().ok()) {
        Some(it) => it,
        None => return false,
    };
    let iterations = match NonZeroU32::new(iterations) {
        Some(it) => it,
        None => return false,
    };
    let salt = match hex::decode(parts[3]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let expected_hash = match hex::decode(parts[4]) {
        Ok(h) => h,
        Err(_) => return false,
    };
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &expected_hash,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_password_roundtrip() {
        let password = "SuperSecretPassword123!";
        let encoded = hash_password(password).unwrap();
        assert!(encoded.starts_with("$pbkdf2-sha256$i=100000$"));
        assert!(verify_password(password, &encoded));
        assert!(!verify_password("WrongPassword123!", &encoded));
        assert!(!verify_password("", &encoded));
    }

    #[test]
    fn short_password_rejected() {
        assert!(hash_password("short").is_err());
    }
}
