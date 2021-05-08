use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_, box_::PublicKey, box_::SecretKey, secretbox, secretbox::Key as SodiumOxideKey,
};
use std::{
    convert::{TryFrom, TryInto},
    vec::Vec,
};

pub struct ValueKeySource {
    value: Vec<u8>,
}
pub struct FsKeySource {
    path: String,
}

impl TryFrom<FsKeySource> for ValueKeySource {
    type Error = std::io::Error;

    fn try_from(ks: FsKeySource) -> Result<Self, Self::Error> {
        std::fs::read(ks.path)
    }
}

impl TryFrom<KeySources> for ValueKeySource {
    type Error = &'static str;

    fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Value(vks) => Ok(vks),
            KeySources::Fs(fsks) => Ok(fsks.try_into()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum KeySources {
    Value(ValueKeySource),
    Fs(FsKeySource),
}

pub trait SymmetricKeyExecutor {
    fn try_encrypt(ks: KeySources) -> String;
}

pub struct SodiumOxideSymmetricKeyExecutor {}

impl SymmetricKeyExecutor for SodiumOxideSymmetricKeyExecutor {
    fn try_encrypt<T: TryInto<ValueKeySource>>(ks: T) -> String {
        let vks = ks.try_into::<ValueKeySource>().unwrap();
        "hello".to_owned()
    }
}

pub trait AsymmetricKeyExecutor {
    fn try_encrypt(ks: KeySources) -> String;
}

pub struct SodiumOxideAsymmetricKeyExecutor {}

impl AsymmetricKeyExecutor for SodiumOxideAsymmetricKeyExecutor {
    fn try_encrypt<T: TryInto<ValueKeySource>>(ks: T) -> String {
        let vks = ks.try_into::<ValueKeySource>().unwrap();
        "hello".to_owned()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SymmetricKeyExecutors {
    SodiumOxide(SodiumOxideSymmetricKeyExecutor),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AsymmetricKeyExecutors {
    SodiumOxide(SodiumOxideAsymmetricKeyExecutor),
}

pub enum Keys {
    Symmetric(SymmetricKey),
    Asymmetric(AsymmetricKey),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SymmetricKey {
    pub source: KeySources,
    pub executor: SymmetricKeyExecutors,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl SymmetricKey {
    fn encrypt(&self) -> String {
        match self.executor {
            SymmetricKeyExecutors::SodiumOxide(so) => so.try_encrypt(self.source),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AsymmetricKey {
    pub source: KeySources,
    pub executor: AsymmetricKeyExecutors,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl AsymmetricKey {
    fn encrypt(&self) -> String {
        // match self.executor {
        //     KeyExecutors::SodiumOxide(so) => so
        // };
        "hello".to_owned()
    }
}

// pub trait SymmetricKeyEncryptDecryptor {}
// pub trait AsymmetricKeyEncryptDecryptor {
//     fn new() -> Self;
// }

// pub struct SodiumOxideSymmetricKeyEncryptDecryptor {
//     key: Key,
// }

// pub struct SodiumOxideAsymmetricKeyEncryptDecryptor {
//     pk: PublicKey,
//     sk: SecretKey,
// }

// impl TryFrom<KeyMetadata> for SodiumOxideSymmetricKeyEncryptDecryptor {
//     type Error = &'static str;

//     fn try_from(km: KeyMetadata<FsKeyInfo>) -> Result<Self, Self::Error> {
//         Self::try_from(Path::new(&km.key_info.path))
//     }
// }

// impl TryFrom<KeyMetadata<ValueKeyInfo>> for SodiumOxideSymmetricKeyEncryptDecryptor {
//     type Error = &'static str;

//     fn try_from(km: KeyMetadata<ValueKeyInfo>) -> Result<Self, Self::Error> {
//         Self::try_from(km.key_info.value.as_slice())
//     }
// }

// impl TryFrom<&Path> for SodiumOxideSymmetricKeyEncryptDecryptor {
//     type Error = &'static str;

//     fn try_from(path: &Path) -> Result<Self, Self::Error> {
//         let key_file = File::open(path).map_err(|e| "io error")?;
//         let mut key_str = String::new();
//         key_file.read_to_string(&mut key_str);

//         Self::try_from(key_str.as_bytes())
//     }
// }

// impl TryFrom<&[u8]> for SodiumOxideSymmetricKeyEncryptDecryptor {
//     type Error = &'static str;

//     fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
//         let key = Key::from_slice(key).ok_or("key creation error")?;
//         Ok(SodiumOxideSymmetricKeyEncryptDecryptor { key })
//     }
// }

// impl SymmetricKeyEncryptDecryptor for SodiumOxideSymmetricKeyEncryptDecryptor {
//     fn new() -> Self {
//         SodiumOxideSymmetricKeyEncryptDecryptor {
//             key: secretbox::gen_key(),
//         }
//     }
// }

// impl AsymmetricKeyEncryptDecryptor for SodiumOxideAsymmetricKeyEncryptDecryptor {
//     fn new() -> Self {
//         let (pk, sk) = box_::gen_keypair();
//         SodiumOxideAsymmetricKeyEncryptDecryptor { pk, sk }
//     }
// }

/// Specifies an interface for performing cryptographic
/// functions
pub trait CryptoProvider {
    fn create_asymmetric_key<T: AsymmetricKeyEncryptDecryptor>() -> T;
    fn create_symmetric_key<T: SymmetricKeyEncryptDecryptor>() -> T;
}

/// Implements the KeypairGenerator trait using the
/// sodiumoxide trait to provide the backing crypto
/// Sodiumoxide is simply an FFI into the well-known
/// libsodium library.
/// The keys generated by libsodium are ECDSA keys
/// using a combination of Curve25519, Salsa20, and
/// Poly1305.
/// For more information on the crypto, see:
/// http://nacl.cr.yp.to/valid.html
pub struct SodiumOxideCryptoProvider {}

impl SodiumOxideCryptoProvider {
    /// Calls sodiumoxide's init function.
    /// According to libsodium's documentation, it's safe to call this
    /// function multiple times:
    /// https://libsodium.gitbook.io/doc/usage
    pub fn init() -> Result<(), ()> {
        sodiumoxide::init()
    }
}

impl CryptoProvider for SodiumOxideCryptoProvider {
    /// Generates an ECDSA keypair using a combination of Curve25519, Salsa20,
    /// and Poly1305.
    fn create_asymmetric_key() -> ([u8; 32], [u8; 32]) {
        let (pk, sk) = box_::gen_keypair();
        // Discussion about iter->fized-size array conversion here:
        // https://github.com/rust-lang/rust/issues/81615
        // let pk_arr: [u8; 32] = pk
        //     .as_ref()
        //     .iter()
        //     .copied()
        //     .collect::<Vec<u8>>()
        //     .try_into()
        //     .unwrap();
        // let sk_arr: [u8; 32] = sk
        //     .as_ref()
        //     .iter()
        //     .copied()
        //     .collect::<Vec<u8>>()
        //     .try_into()
        //     .unwrap();
        (pk, sk)
    }

    fn create_symmetric_key() -> [u8; 32] {
        secretbox::gen_key()
            .as_ref()
            .iter()
            .copied()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }
}
