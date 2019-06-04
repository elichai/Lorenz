use crate::secret::Secret;
use crate::Error;
use lazy_static::lazy_static;
use rand_os::OsRng;
use ring::digest::SHA256;
use ring::hkdf;
use ring::hmac::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};

lazy_static! {
    static ref SALT: SigningKey = SigningKey::new(&SHA256, b"Lorenz");
}

pub struct EphemeralKey(StaticSecret);

impl EphemeralKey {
    pub fn new() -> Result<Self, Error> {
        let mut rng = OsRng::new().map_err(Error::io)?;
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

pub struct UserKey {
    pub private: StaticSecret,
    pub public: PublicKey,
}

pub fn get_user_keys(amount: usize) -> Result<Vec<UserKey>, Error> {
    let mut rng = OsRng::new().map_err(Error::io)?;
    let mut res = Vec::with_capacity(amount);

    for _ in 0..amount {
        let private = StaticSecret::new(&mut rng);
        let public = PublicKey::from(&private);
        res.push(UserKey { public, private })
    }
    Ok(res)
}
