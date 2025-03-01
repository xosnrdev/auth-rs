use anyhow::anyhow;
use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};

use super::AppResult;

pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Unable to hash password ({})", e))
        .map(|hash| hash.to_string())
}

pub fn check_password(password: &str, password_hash: &str) -> AppResult<bool> {
    let argon2 = Argon2::default();

    let hash = PasswordHash::new(password_hash)
        .map_err(|e| anyhow!("Unable to parse password ({})", e))?;

    match argon2.verify_password(password.as_bytes(), &hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
