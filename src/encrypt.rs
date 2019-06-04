use crate::Error;
use ring::aead::{
    self, open_in_place, seal_in_place, Aad, Nonce, OpeningKey, SealingKey, AES_256_GCM,
    CHACHA20_POLY1305, NONCE_LEN,
};
use ring::rand::{SecureRandom, SystemRandom};

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
    let (nonce, raw_nonce) = get_random_nonce()?;

    data.extend(vec![0u8; algorithm.tag_len()]);
    let s = seal_in_place(&key, nonce, Aad::empty(), &mut data, algorithm.tag_len())
        .map_err(Error::encryption)?;

    debug_assert_eq!(s, data.len());

    data.extend(&raw_nonce);

    Ok(data)
}

pub fn decrypt(key: &[u8], mut data: Vec<u8>, scheme: Scheme) -> Result<Vec<u8>, Error> {
    let algorithm = scheme_to_algorithm(scheme);
    if key.len() != algorithm.key_len() {
        return Err(Error::BadKeyLength);
    }
    let nonce = data.split_off(data.len() - NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(&nonce).unwrap(); // Can never fail.

    let key = OpeningKey::new(algorithm, key).map_err(Error::decryption)?;

    let plaintext =
        open_in_place(&key, nonce, Aad::empty(), 0, &mut data).map_err(Error::decryption)?;

    Ok(plaintext.to_vec())
}

fn get_random_nonce() -> Result<(Nonce, [u8; 12]), Error> {
    let rand_gen = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rand_gen.fill(&mut nonce).map_err(Error::io)?;
    Ok((Nonce::assume_unique_for_key(nonce), nonce))
}

fn scheme_to_algorithm(scheme: Scheme) -> &'static aead::Algorithm {
    match scheme {
        Scheme::AES256GCM => &AES_256_GCM,
        Scheme::Chacha20Poly1305 => &CHACHA20_POLY1305,
    }
}
