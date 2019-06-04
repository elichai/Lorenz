#[derive(Debug)]
pub enum Error {
    IoError,
    EncryptionError,
    DecryptionError,
    BadKeyLength,
}

impl Error {
    pub fn io<E>(_: E) -> Self {
        Error::IoError
    }
    pub fn encryption<E>(_: E) -> Self {
        Error::EncryptionError
    }
    pub fn decryption<E>(_: E) -> Self {
        Error::DecryptionError
    }
    pub fn key_length<E>(_: E) -> Self {
        Error::BadKeyLength
    }
}
