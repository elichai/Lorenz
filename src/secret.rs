use crate::Error;
use rand_os::rand_core::RngCore;
use rand_os::OsRng;
use std::boxed::Box;
use std::pin::Pin;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Secret(Pin<Box<[u8]>>);

impl Secret {
    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self(vec.into_boxed_slice().into())
    }

    pub fn generate32() -> Result<Self, Error> {
        let mut rng = OsRng::new()?;
        let mut vec = vec![0u8; 32];
        rng.fill_bytes(&mut vec);
        Ok(Self::from_vec(vec))
    }

    pub fn into_vec(self) -> Vec<u8> {
        (*self.0).into()
    }
}

impl AsRef<[u8]> for Secret {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
