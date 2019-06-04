use crate::Error;
use ring::aead::{
    self, seal_in_place, Aad, Nonce, SealingKey, AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN,
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
    println!("key: {:?}", key);
    let key = SealingKey::new(algorithm, key).map_err(Error::encryption)?;
    let (nonce, raw_nonce) = get_random_nonce()?;

    data.extend(vec![0u8; algorithm.tag_len()+5]);
    let s = seal_in_place(
        &key,
        nonce,
        Aad::empty(),
        &mut data,
        algorithm.tag_len()
    )
    .map_err(Error::encryption)?;

    debug_assert_eq!(s, data.len());

    data.extend(&raw_nonce);

    Ok(data)
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
