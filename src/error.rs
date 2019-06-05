use std::io;
use rand_os::rand_core;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    RngError(rand_core::Error),
    RingError,
    BadKeyLength,
    BadKey,
}

impl Error {
    pub fn key_length<E>(_: E) -> Self {
        Error::BadKeyLength
    }
}



impl From<io::Error> for Error{
    fn from(err: io::Error) -> Self {
        Error::IoError(err)
    }
}

impl From<rand_core::Error> for Error{
    fn from(err: rand_core::Error) -> Self {
        Error::RngError(err)
    }
}

impl From<ring::error::Unspecified> for Error{
    fn from(_: ring::error::Unspecified) -> Self {
        Error::RingError
    }
}