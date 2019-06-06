use crate::x25519::UserSecretKey;
use rustc_hex::{FromHex, FromHexError};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "Lorenz", about = "A tool for encrypting/decrypting a file for multiple participants.")]
pub enum Options {
    /// Generate Pairs of keys.
    #[structopt(name = "generate-keys")]
    GenerateKeys {
        #[structopt(default_value = "1")]
        amount: u8,
    },
    /// Encrypt a file
    #[structopt(name = "encrypt")]
    Encrypt {
        #[structopt(parse(try_from_str = "parse_hex32"), raw(required = "true"))]
        public_keys: Vec<[u8; 32]>,
        #[structopt(parse(from_os_str))]
        file: PathBuf,
        #[structopt(long, default_value = "AES")]
        mode: String,
    },
    /// Decrypt a file
    #[structopt(name = "decrypt")]
    Decrypt {
        #[structopt(parse(try_from_str))]
        private_key: UserSecretKey,
        #[structopt(parse(from_os_str))]
        file: PathBuf,
        #[structopt(long, default_value = "AES")]
        mode: String,
    },
}

pub fn parse_hex32(hex: &str) -> Result<[u8; 32], FromHexError> {
    let hex = if "0x" == hex.chars().take(2).collect::<String>().as_str() { hex.chars().skip(2).collect() } else { hex.to_owned() };
    if hex.len() != 64 {
        // TODO: formalize an error
        return Err(FromHexError::InvalidHexLength);
    }
    let hex_vec: Vec<u8> = hex.from_hex()?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&hex_vec);
    Ok(result)
}