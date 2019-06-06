use crate::x25519::*;
use crate::*;
use encryption::Scheme;
use std::fs::*;
use std::io::{self, Read, Seek, SeekFrom, Write};
use x25519_dalek::PublicKey;

fn file_len(file: &File) -> usize {
    file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0)
}

pub fn encrypt_file_with_keys(input_file: &mut File, keys: Vec<PublicKey>, output: &mut File, scheme: Scheme) -> Result<(), Error> {
    let mut input = Vec::with_capacity(file_len(&input_file));
    input_file.read_to_end(&mut input)?;
    let aes = Secret::generate32()?;
    let ephemeral = x25519::EphemeralKey::new()?;
    output.write_all(ephemeral.get_public().as_bytes())?;
    output.write_all(&[keys.len() as u8])?;

    for key in &keys {
        let shared = ephemeral.derive_secret(&key, 32);
        let enc_key = encryption::encrypt_data(shared.as_ref(), aes.clone().into_vec(), scheme)?;
        output.write_all(&enc_key)?;
    }

    let enc_file = encryption::encrypt_data(aes.as_ref(), input, scheme)?;
    output.write_all(&enc_file)?;
    Ok(())
}

pub fn decrypt_file_with_keys(input_file: &mut File, key: UserSecretKey, output: &mut File, scheme: Scheme) -> Result<(), Error> {
    let mut pubkey = [0u8; 32];
    input_file.read_exact(&mut pubkey)?;
    let amount = take(input_file)?;

    let shared = key.derive_secret(&pubkey.into(), 32);
    let (key, left) = find_encrypted_key(input_file, shared, amount, scheme);
    let key = key.ok_or(Error::BadKey)?;
    input_file.seek(SeekFrom::Current(i64::from(left) * scheme.get_encrypted_key_size() as i64))?;

    let data_size = file_len(input_file) - 32 - 1 - amount as usize * scheme.get_encrypted_key_size();
    let mut data = Vec::with_capacity(data_size);

    input_file.read_to_end(&mut data)?;

    let original = encryption::decrypt_data(key.as_ref(), data, scheme)?;
    output.write_all(&original)?;

    Ok(())
}

fn take<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut b = [0];
    reader.read_exact(&mut b)?;
    Ok(b[0])
}

fn find_encrypted_key<R: Read>(f: &mut R, shared: Secret, amount: u8, scheme: Scheme) -> (Option<Secret>, u8) {
    let key_size = scheme.get_encrypted_key_size();
    for i in 1..=amount {
        let mut encrypted_key = vec![0u8; key_size];
        match f.read_exact(&mut encrypted_key).ok() {
            None => return (None, amount - i),
            Some(()) => (),
        };
        match encryption::decrypt_data(shared.as_ref(), encrypted_key, scheme) {
            Err(_) => continue,
            Ok(key) => return (Some(Secret::from_vec(key)), amount - i),
        }
    }
    (None, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{generate_random_keys, get_rand_file};
    use rand::{seq::SliceRandom, thread_rng, Rng};
    use tempfile::tempfile;

    #[test]
    fn encryption_decryption_test() {
        for _ in 0..15 {
            internal_test(Scheme::AES256GCM);
            internal_test(Scheme::Chacha20Poly1305);
        }
    }

    fn internal_test(scheme: Scheme) {
        let mut rng = thread_rng();
        let mut original = get_rand_file();
        let mut encrypted = tempfile().unwrap();
        let mut decrypted = tempfile().unwrap();
        let keys = generate_random_keys(rng.gen());
        let decrypt_with = keys.choose(&mut rng).unwrap().0.clone();
        let pub_keys = keys.iter().map(|(_, p)| p).cloned().collect();

        encrypt_file_with_keys(&mut original, pub_keys, &mut encrypted, scheme).unwrap();
        encrypted.seek(SeekFrom::Start(0)).unwrap();
        decrypt_file_with_keys(&mut encrypted, decrypt_with, &mut decrypted, scheme).unwrap();

        original.seek(SeekFrom::Start(0)).unwrap();
        decrypted.seek(SeekFrom::Start(0)).unwrap();

        let (mut before, mut after) = (Vec::with_capacity(1986), Vec::with_capacity(1986));
        original.read_to_end(&mut before).unwrap();
        decrypted.read_to_end(&mut after).unwrap();
        assert_eq!(before, after);
    }

}
