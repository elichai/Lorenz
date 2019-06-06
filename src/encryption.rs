use crate::Error;
use ring::aead::{self, open_in_place, seal_in_place, Aad, Nonce, OpeningKey, SealingKey, AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use std::str::FromStr;
use structopt::clap::{Error as ClapError, ErrorKind as ClapErrorKind};
use zeroize::Zeroizing;

#[derive(Copy, Clone)]
pub enum Scheme {
    AES256GCM,
    Chacha20Poly1305,
}

pub fn encrypt_data(key: &[u8], mut data: Vec<u8>, scheme: Scheme) -> Result<Vec<u8>, Error> {
    let algorithm = scheme.get_algorithm();
    if key.len() != algorithm.key_len() {
        return Err(Error::BadKeyLength);
    }
    let key = SealingKey::new(algorithm, key)?;
    let (nonce, raw_nonce) = get_random_nonce()?;

    data.extend(vec![0u8; algorithm.tag_len()]);
    let s = seal_in_place(&key, nonce, Aad::empty(), &mut data, algorithm.tag_len())?;

    debug_assert_eq!(s, data.len());

    data.extend(&raw_nonce);

    Ok(data)
}

pub fn decrypt_data(key: &[u8], mut data: Vec<u8>, scheme: Scheme) -> Result<Vec<u8>, Error> {
    let algorithm = scheme.get_algorithm();
    if key.len() != algorithm.key_len() {
        return Err(Error::BadKeyLength);
    }
    let nonce = data.split_off(data.len() - NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(&nonce).unwrap(); // Can never fail.

    let key = OpeningKey::new(algorithm, key)?;
    let mut result = Zeroizing::new(data);

    let plaintext = open_in_place(&key, nonce, Aad::empty(), 0, &mut result)?;

    Ok(plaintext.to_vec())
}

fn get_random_nonce() -> Result<(Nonce, [u8; 12]), Error> {
    let rand_gen = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rand_gen.fill(&mut nonce)?;
    Ok((Nonce::assume_unique_for_key(nonce), nonce))
}

impl Scheme {
    pub fn get_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Scheme::AES256GCM => &AES_256_GCM,
            Scheme::Chacha20Poly1305 => &CHACHA20_POLY1305,
        }
    }

    pub fn get_encrypted_key_size(self) -> usize {
        let algorithm = self.get_algorithm();
        algorithm.key_len() + algorithm.tag_len() + algorithm.nonce_len()
    }
}

impl FromStr for Scheme {
    type Err = ClapError;

    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode.to_lowercase().as_str() {
            "aes" | "aes256" => Ok(Scheme::AES256GCM),
            "chacha" | "chacha20" | "chacha20poly1305" => Ok(Scheme::Chacha20Poly1305),
            a => Err(ClapError::with_description(
                &format!("{} Mode isn't supported, please choose one of these: AES/Chacha20", a),
                ClapErrorKind::InvalidValue,
            )),
        }
    }
}
