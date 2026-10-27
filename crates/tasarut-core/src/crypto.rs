//! Fixed, versioned suites. No cipher or Argon2 parameters supplied by the volume.

use crate::{CipherAlgorithm, EncryptOptions, Error, Result};
use blake2::{digest::Mac, Blake2bMac512};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherError},
    XChaCha20,
};
use hmac::Hmac;
use serpent::{
    cipher::{InnerIvInit, KeyInit, StreamCipher as SerpentStreamCipher},
    Serpent,
};
use sha3::Sha3_512;
use threefish::Threefish1024;
use zeroize::Zeroizing;

type SerpentCtr = ctr::Ctr128BE<Serpent>;
type SerpentCtrCore = ctr::CtrCore<Serpent, ctr::flavors::Ctr128BE>;
type Sha3Mac = Hmac<Sha3_512>;
type ThreefishCtr = ctr::Ctr128BE<Threefish1024>;
type ThreefishCtrCore = ctr::CtrCore<Threefish1024, ctr::flavors::Ctr128BE>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    Standard,
    Paranoid,
    Threefish,
}

impl Suite {
    pub fn from_options(options: &EncryptOptions) -> Result<Self> {
        match (options.algorithm, options.paranoid) {
            (CipherAlgorithm::XChaCha20, false) => Ok(Self::Standard),
            (CipherAlgorithm::XChaCha20, true) => Ok(Self::Paranoid),
            (CipherAlgorithm::Threefish1024, false) => Ok(Self::Threefish),
            (CipherAlgorithm::Threefish1024, true) => Err(Error::CipherOptions),
        }
    }

    pub fn algorithm(self) -> CipherAlgorithm {
        match self {
            Self::Threefish => CipherAlgorithm::Threefish1024,
            Self::Standard | Self::Paranoid => CipherAlgorithm::XChaCha20,
        }
    }

    pub fn id(self) -> u8 {
        match self {
            Self::Standard => 1,
            Self::Paranoid => 2,
            Self::Threefish => 3,
        }
    }

    pub fn version(self) -> u8 {
        match self {
            Self::Standard => 1,
            Self::Paranoid => 2,
            Self::Threefish => 5,
        }
    }

    pub fn profile(self) -> (u32, u32, usize) {
        match self {
            Self::Standard => (65_536, 3, 64),
            Self::Paranoid => (262_144, 6, 128),
            Self::Threefish => (262_144, 6, 192),
        }
    }

    pub fn password_domain(self) -> &'static [u8] {
        match self {
            Self::Standard => b"Tasarut/v1/password+keyfiles",
            Self::Paranoid => b"Tasarut/v2/paranoid/password+keyfiles",
            Self::Threefish => b"Tasarut/v5/threefish1024/password+keyfiles",
        }
    }
}

pub(crate) struct Keys {
    pub suite: Suite,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl Keys {
    pub fn mac(&self, header: &[u8]) -> Result<Authenticator> {
        let mut mac = match self.suite {
            Suite::Standard => Authenticator::Blake2(
                <Blake2bMac512 as Mac>::new_from_slice(&self.bytes[32..64])
                    .map_err(|_| Error::Kdf)?,
            ),
            Suite::Paranoid => Authenticator::Sha3(Box::new(
                <Sha3Mac as Mac>::new_from_slice(&self.bytes[64..128]).map_err(|_| Error::Kdf)?,
            )),
            Suite::Threefish => Authenticator::Sha3(Box::new(
                <Sha3Mac as Mac>::new_from_slice(&self.bytes[128..192]).map_err(|_| Error::Kdf)?,
            )),
        };
        mac.update(header);
        Ok(mac)
    }

    pub fn cipher(&self, nonce: &[u8; 24], block_parameter: Option<&[u8; 16]>) -> Result<Cascade> {
        if self.suite == Suite::Threefish {
            let tweak = block_parameter.ok_or(Error::InvalidVolume)?;
            let key = self.bytes[..128].try_into().map_err(|_| Error::Kdf)?;
            let block = Threefish1024::new_with_tweak(key, tweak);
            // Threefish consumes the whole 128-byte block. Keep the public
            // 192-bit prefix, 88 fixed zero bytes and a zero 128-bit BE counter.
            let mut iv = [0; 128];
            iv[..24].copy_from_slice(nonce);
            let cipher =
                ThreefishCtrCore::inner_iv_slice_init(block, &iv).map_err(|_| Error::Kdf)?;
            return Ok(Cascade::Threefish(Box::new(ThreefishCtr::from_core(
                cipher,
            ))));
        }
        let xchacha =
            XChaCha20::new_from_slices(&self.bytes[..32], nonce).map_err(|_| Error::Kdf)?;
        let serpent = match (self.suite, block_parameter) {
            (Suite::Standard, None) => None,
            (Suite::Paranoid, Some(iv)) => {
                // Serpent's default KeySize is 128 bits; explicitly initialize its 256-bit key
                // before wrapping it in CTR, rather than truncating it to fit that default.
                let block = Serpent::new_from_slice(&self.bytes[32..64]).map_err(|_| Error::Kdf)?;
                Some(Box::new(SerpentCtr::from_core(
                    SerpentCtrCore::inner_iv_slice_init(block, iv).map_err(|_| Error::Kdf)?,
                )))
            }
            _ => return Err(Error::InvalidVolume),
        };
        Ok(Cascade::ChaCha { xchacha, serpent })
    }
}

pub(crate) enum Cascade {
    ChaCha {
        xchacha: XChaCha20,
        serpent: Option<Box<SerpentCtr>>,
    },
    Threefish(Box<ThreefishCtr>),
}

impl Cascade {
    pub fn encrypt(&mut self, bytes: &mut [u8]) -> std::result::Result<(), StreamCipherError> {
        let Self::ChaCha { xchacha, serpent } = self else {
            let Self::Threefish(cipher) = self else {
                unreachable!()
            };
            return cipher
                .try_apply_keystream(bytes)
                .map_err(|_| StreamCipherError);
        };
        xchacha.try_apply_keystream(bytes)?;
        if let Some(serpent) = serpent {
            serpent
                .try_apply_keystream(bytes)
                .map_err(|_| StreamCipherError)?;
        }
        Ok(())
    }

    pub fn decrypt(&mut self, bytes: &mut [u8]) -> std::result::Result<(), StreamCipherError> {
        let Self::ChaCha { xchacha, serpent } = self else {
            return self.encrypt(bytes);
        };
        if let Some(serpent) = serpent {
            serpent
                .try_apply_keystream(bytes)
                .map_err(|_| StreamCipherError)?;
        }
        xchacha.try_apply_keystream(bytes)
    }
}

pub(crate) enum Authenticator {
    Blake2(Blake2bMac512),
    Sha3(Box<Sha3Mac>),
}

impl Authenticator {
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Blake2(mac) => Mac::update(mac, bytes),
            Self::Sha3(mac) => Mac::update(mac.as_mut(), bytes),
        }
    }

    pub fn finalize(self) -> [u8; 64] {
        match self {
            Self::Blake2(mac) => mac.finalize().into_bytes().into(),
            Self::Sha3(mac) => (*mac).finalize().into_bytes().into(),
        }
    }

    pub fn verify(self, tag: &[u8]) -> Result<()> {
        match self {
            Self::Blake2(mac) => mac.verify_slice(tag),
            Self::Sha3(mac) => (*mac).verify_slice(tag),
        }
        .map_err(|_| Error::Authentication)
    }
}
