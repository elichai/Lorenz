use crate::secret::Secret;
use crate::Error;
use lazy_static::lazy_static;
use rand_os::OsRng;
use ring::digest::SHA256;
use ring::hkdf;
use ring::hmac::SigningKey;
use rustc_hex::ToHex;
use std::fmt;
use std::str::FromStr;
use x25519_dalek::{PublicKey, StaticSecret};

lazy_static! {
    static ref SALT: SigningKey = SigningKey::new(&SHA256, b"Lorenz");
}

pub struct EphemeralKey(StaticSecret);

impl EphemeralKey {
    pub fn new() -> Result<Self, Error> {
        let mut rng = OsRng::new()?;
        Ok(Self(StaticSecret::new(&mut rng)))
    }

    pub fn derive_secret(&self, other: &PublicKey, len: usize) -> Secret {
        let mut res = vec![0u8; len];
        let shared = self.0.diffie_hellman(&other);
        hkdf::extract_and_expand(&SALT, shared.as_bytes(), &[], &mut res);

        Secret::from_vec(res)
    }

    pub fn get_public(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }
}

impl From<[u8; 32]> for EphemeralKey {
    #[inline]
    fn from(bytes: [u8; 32]) -> EphemeralKey {
        EphemeralKey(bytes.into())
    }
}

pub struct UserSecretKey(StaticSecret);

impl UserSecretKey {
    pub fn new() -> Result<Self, Error> {
        let mut rng = OsRng::new()?;
        Ok(Self(StaticSecret::new(&mut rng)))
    }

    pub fn derive_secret(&self, other: &PublicKey, len: usize) -> Secret {
        let mut res = vec![0u8; len];
        let shared = self.0.diffie_hellman(&other);
        hkdf::extract_and_expand(&SALT, shared.as_bytes(), &[], &mut res);

        Secret::from_vec(res)
    }

    pub fn get_public(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }
}

impl fmt::Display for UserSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "privateKey: {}", self.0.to_bytes().to_hex::<String>())?;
        writeln!(f, "publicKey: {}", self.get_public().as_bytes().to_hex::<String>())
    }
}

impl fmt::Debug for UserSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for UserSecretKey {
    type Err = Error;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        let mut hex = secret_parse_hex32(hex).unwrap();
        let result = StaticSecret::from(hex);
        hex = [0u8; 32]; // TODO: actual cleanup.

        Ok(UserSecretKey(result))
    }
}

use rustc_hex::{FromHex, FromHexError};
// TODO: CleanUp.
pub fn secret_parse_hex32(hex: &str) -> Result<[u8; 32], FromHexError> {
    let mut first_chars = hex.chars().take(2).collect::<String>();
    let hex = if first_chars.as_str() == "0x" { hex.chars().skip(2).collect() } else { hex.to_owned() };
    if hex.len() != 64 {
        // TODO: formalize an error
        return Err(FromHexError::InvalidHexLength);
    }
    let hex_vec: Vec<u8> = hex.from_hex()?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&hex_vec);
    Ok(result)
}

pub fn get_user_keys(amount: usize) -> Result<Vec<UserSecretKey>, Error> {
    let mut rng = OsRng::new()?;
    let mut res = Vec::with_capacity(amount);

    for _ in 0..amount {
        let private = StaticSecret::new(&mut rng);
        res.push(UserSecretKey(private))
    }
    Ok(res)
}
