use crate::secret::Secret;
use crate::Error;
use lazy_static::lazy_static;
use rand_os::OsRng;
use ring::digest::SHA256;
use ring::hkdf;
use ring::hmac::SigningKey;
use rustc_hex::{FromHex, ToHex};
use std::fmt;
use std::str::FromStr;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

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

#[cfg_attr(test, derive(Clone))]
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
        let mut private = self.0.to_bytes().to_hex::<String>();
        let public = self.get_public().as_bytes().to_hex::<String>();
        writeln!(f, "privateKey: 0x{}", private)?;
        private.zeroize();
        writeln!(f, "publicKey: 0x{}", public)
    }
}

pub fn secret_parse_hex32(hex: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut first_chars = hex.chars().take(2).collect::<String>();
    let mut hex = if first_chars.as_str() == "0x" { hex.chars().skip(2).collect() } else { hex.to_owned() };
    first_chars.zeroize();
    drop(first_chars);
    if hex.len() != 64 {
        // TODO: formalize an error
        hex.zeroize();
        return Err(Error::BadKeyLength);
    }
    let mut hex_vec: Vec<u8> = hex.from_hex().map_err(Error::bad_key)?;
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&hex_vec);
    hex_vec.zeroize();
    drop(hex_vec);
    Ok(result)
}

impl fmt::Debug for UserSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for UserSecretKey {
    type Err = Error;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        let hex = secret_parse_hex32(hex)?;
        let result = StaticSecret::from(*hex);

        Ok(UserSecretKey(result))
    }
}

impl Zeroize for EphemeralKey {
    fn zeroize(&mut self) {
        use std::{mem, ptr, sync::atomic};
        let zeroed = EphemeralKey([0u8; 32].into());
        unsafe {
            let ptr = self as *mut Self;
            ptr::write_volatile(ptr, mem::zeroed());
            ptr::write_volatile(ptr, zeroed);
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl Zeroize for UserSecretKey {
    fn zeroize(&mut self) {
        use std::{mem, ptr, sync::atomic};
        let zeroed = UserSecretKey([0u8; 32].into());
        unsafe {
            let ptr = self as *mut Self;
            ptr::write_volatile(ptr, mem::zeroed());
            ptr::write_volatile(ptr, zeroed);
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }
    }
}

impl Drop for UserSecretKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}
