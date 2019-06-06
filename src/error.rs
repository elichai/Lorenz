use rand_os::rand_core::Error as RandError;
use ring::error::Unspecified as RingError;
use std::error::Error as StdError;
use std::fmt;
use std::io;
use structopt::clap::{Error as ClapError, ErrorKind as ClapErrorKind};

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    RngError(RandError),
    RingError,
    BadKeyLength,
    BadKey,
}

impl Error {
    pub fn key_length<E>(_: E) -> Self {
        Error::BadKeyLength
    }
    pub fn bad_key<E>(_: E) -> Self {
        Error::BadKey
    }
}

impl StdError for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            IoError(e) => writeln!(f, "Lorenz Error IO: {}", e),
            RngError(e) => writeln!(f, "Lorenz Error RNG: {}", e),
            RingError => writeln!(f, "Lorenz Error: Failed Encrypting/Decrypting data"),
            BadKeyLength => writeln!(f, "Lorenz Error: Key isn't the right length"),
            BadKey => writeln!(f, "Lorenz Error: Couldn't find the right key"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IoError(err)
    }
}

impl From<RandError> for Error {
    fn from(err: RandError) -> Self {
        Error::RngError(err)
    }
}

impl From<RingError> for Error {
    fn from(_: RingError) -> Self {
        Error::RingError
    }
}

impl From<Error> for ClapError {
    fn from(err: Error) -> ClapError {
        use Error::*;
        match err {
            IoError(e) => e.into(),
            RngError(e) => ClapError::with_description(e.description(), ClapErrorKind::Io),
            _ => unimplemented!(),
        }
    }
}
