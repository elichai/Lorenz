use ring::aead::{
    self, seal_in_place, Aad, Nonce, SealingKey, AES_256_GCM, CHACHA20_POLY1305,
};
use ring::rand::{SecureRandom, SystemRandom};
use crate::Error;

pub enum Scheme {
    AES256GCM,
    Chacha20Poly1305,
}

pub fn encrypt(key: &[u8], mut data: Vec<u8>, scheme: Scheme) -> Result<Vec<u8>, Error> {
    let algorithm = scheme_to_algorithm(scheme);
    if key.len() != algorithm.key_len() {
        return Err(Error::BadKeyLength);
    }
    let key = SealingKey::new(algorithm, key).map_err(Error::encryption)?;
    let nonce = get_random_nonce()?;

    data.extend(vec![0u8; algorithm.tag_len()]);
    let s = seal_in_place(&key, nonce, Aad::empty(), &mut data, 0).map_err(Error::encryption)?;

    debug_assert_eq!(s, data.len());

    Ok(data)
}

fn get_random_nonce() -> Result<Nonce, Error> {
    let rand_gen = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rand_gen.fill(&mut nonce).map_err(Error::io)?;
    Ok(Nonce::assume_unique_for_key(nonce))
}

fn scheme_to_algorithm(scheme: Scheme) -> &'static aead::Algorithm {
    match scheme {
        Scheme::AES256GCM => &AES_256_GCM,
        Scheme::Chacha20Poly1305 => &CHACHA20_POLY1305,
    }
}
