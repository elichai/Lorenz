pub enum Error {
    IoError,
    EncryptionError,
    BadKeyLength,
}

impl Error {
    pub fn io<E>(_: E) -> Self {
        Error::IoError
    }
    pub fn encryption<E>(_: E) -> Self {
        Error::EncryptionError
    }
    pub fn key_length<E>(_: E) -> Self {
        Error::BadKeyLength
    }
}