#![allow(dead_code)]

mod cli;
mod encryption;
mod error;
mod logic;
mod secret;
mod x25519;

use crate::encryption::Scheme;
use crate::x25519::UserSecretKey;
use cli::Options;
pub use error::Error;
pub use secret::Secret;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use structopt::clap::{Error as ClapError, ErrorKind as ClapErrorKind};
use structopt::StructOpt;
use x25519_dalek::PublicKey;

fn main() {
    let opt = Options::from_args();
    if let Err(e) = handle_cli(opt) {
        e.exit();
    }
}

fn handle_cli(opt: Options) -> Result<(), ClapError> {
    match opt {
        Options::GenerateKeys { amount } => {
            for i in 1..=amount {
                let key = UserSecretKey::new()?;
                println!("key {}: \n{}", i, key);
            }
        }
        Options::Encrypt { public_keys, file, mode } => {
            let mut input = File::open(&file)?;
            let mut output = File::create(add_lorenz_extenstion(&file))?;
            let scheme = Scheme::from_str(&mode)?;
            let public_keys = public_keys.into_iter().map(PublicKey::from).collect();
            logic::encrypt_file_with_keys(&mut input, public_keys, &mut output, scheme)?;
        }
        Options::Decrypt { private_key, file, mode } => {
            let mut input = File::open(&file)?;
            let output_path = remove_lorenz_extenstion(file)?;
            let mut output = File::create(&output_path)?;
            let scheme = Scheme::from_str(&mode)?;
            logic::decrypt_file_with_keys(&mut input, private_key, &mut output, scheme)?;
        }
    };

    Ok(())
}

fn add_lorenz_extenstion<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut path = path.as_ref().as_os_str().to_owned();
    path.push(".lorenz");
    path.into()
}

fn remove_lorenz_extenstion<P: AsRef<Path>>(path: P) -> Result<PathBuf, ClapError> {
    let err = ClapError::with_description("Bad File, doesn't end with `lorenz` extension", ClapErrorKind::InvalidValue);
    let path = path.as_ref();
    if let Some(ext) = path.extension() {
        if ext == "lorenz" {
            let mut res = path.to_owned();
            let file_without_path = path.file_stem().ok_or(err)?;
            res.set_file_name(file_without_path);
            return Ok(res);
        }
    }
    Err(err)
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};

    use super::*;
    use crate::encryption::Scheme;
    use crate::x25519::UserSecretKey;
    use tempfile::tempfile;

    #[test]
    fn full_test() {
        let mut input = get_rand_file();
        let mut encrypted = tempfile().unwrap();
        let mut decrypted = tempfile().unwrap();

        let mut keys = encrypt(6, &mut input, &mut encrypted);

        decrypt(keys.remove(4), &mut encrypted, &mut decrypted);

        let mut before = Vec::new();
        let mut after = Vec::new();

        input.read_to_end(&mut before).unwrap();
        decrypted.read_to_end(&mut after).unwrap();
        assert_eq!(before, after);
    }

    pub fn get_rand_file() -> File {
        let mut input = vec![0u8; 1986];
        let mut rng = thread_rng();
        rng.fill_bytes(&mut input);
        let mut f = tempfile().unwrap();
        f.write_all(&input).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f
    }

    fn take<R: Read>(reader: &mut R) -> io::Result<u8> {
        let mut b = [0];
        reader.read_exact(&mut b)?;
        Ok(b[0])
    }

    fn decrypt(key: UserSecretKey, mut encrypted: &mut File, output: &mut File) {
        let mut pubkey = [0u8; 32];
        encrypted.read_exact(&mut pubkey).unwrap();
        let amount = take(&mut encrypted).unwrap();

        let shared = key.derive_secret(&pubkey.into(), 32);
        let (aes_key, left) = find_aes_key(&mut encrypted, shared, amount);
        let aes_key = aes_key.unwrap();
        encrypted.seek(SeekFrom::Current(left as i64 * 60)).unwrap();

        let file_size = encrypted.metadata().unwrap().len() as usize - 32 - 1 - (60 * amount as usize);

        let mut file_data = Vec::with_capacity(file_size);
        encrypted.read_to_end(&mut file_data).unwrap();

        let original = encryption::decrypt_data(aes_key.as_ref(), file_data, Scheme::AES256GCM).unwrap();
        output.write_all(&original).unwrap();

        encrypted.seek(SeekFrom::Start(0)).unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
    }

    fn find_aes_key<R: Read>(f: &mut R, shared: Secret, amount: u8) -> (Option<Secret>, u8) {
        for i in 1..=amount {
            let mut encrypted_key = vec![0u8; 60];
            match f.read_exact(&mut encrypted_key).ok() {
                None => return (None, amount - i),
                Some(()) => (),
            };
            match encryption::decrypt_data(shared.as_ref(), encrypted_key, Scheme::AES256GCM) {
                Err(_) => continue,
                Ok(key) => return (Some(Secret::from_vec(key)), amount - i),
            }
        }
        (None, 0)
    }

    fn encrypt(keys: u8, input_file: &mut File, output: &mut File) -> Vec<UserSecretKey> {
        let mut input = Vec::with_capacity(1987);
        input_file.read_to_end(&mut input).unwrap();
        let aes = Secret::generate32().unwrap();
        let ephemeral = x25519::EphemeralKey::new().unwrap();

        output.write_all(ephemeral.get_public().as_bytes()).unwrap();

        output.write_all(&[keys]).unwrap();

        let keys = generate_random_keys(keys);
        for (_, public) in &keys {
            let shared = ephemeral.derive_secret(public, 32);
            let enc_key = encryption::encrypt_data(shared.as_ref(), aes.clone().into_vec(), Scheme::AES256GCM).unwrap();
            output.write_all(&enc_key).unwrap();
        }

        let enc_file = encryption::encrypt_data(aes.as_ref(), input, Scheme::AES256GCM).unwrap();
        output.write_all(&enc_file).unwrap();
        output.seek(SeekFrom::Start(0)).unwrap();
        input_file.seek(SeekFrom::Start(0)).unwrap();

        keys.into_iter().map(|(key, _)| key).collect()
    }

    pub fn generate_random_keys(amount: u8) -> Vec<(UserSecretKey, PublicKey)> {
        let mut res = Vec::with_capacity(amount as usize);
        for _ in 0..amount {
            let key = UserSecretKey::new().unwrap();
            let public = key.get_public();
            res.push((key, public));
        }
        res
    }
}
