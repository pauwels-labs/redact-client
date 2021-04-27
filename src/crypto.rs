use sodiumoxide::crypto;
use std::{convert::TryInto, vec::Vec};

pub trait KeypairGenerator {
    fn create() -> Result<([u8; 64], [u8; 64]), serde_json::Error>;
}

pub struct SodiumOxideKeypairGenerator {}

impl SodiumOxideKeypairGenerator {
    pub fn new() -> Result<SodiumOxideKeypairGenerator, ()> {
        // sodiumoxide::init is a wrapper around an ffi call to libsodium's
        // sodium_init. According to libsodium's documentation, it's safe to
        // call this function multiple times:
        // https://libsodium.gitbook.io/doc/usage
        sodiumoxide::init()?;
        Ok(SodiumOxideKeypairGenerator {})
    }
}

impl KeypairGenerator for SodiumOxideKeypairGenerator {
    fn create() -> Result<([u8; 64], [u8; 64]), serde_json::Error> {
        let (pk, sk) = crypto::box_::gen_keypair();
        // Discussion about iter->fized-size array conversion here:
        // https://github.com/rust-lang/rust/issues/81615
        let pk_arr: [u8; 64] = pk
            .as_ref()
            .iter()
            .map(|x| *x)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let sk_arr: [u8; 64] = sk
            .as_ref()
            .iter()
            .map(|x| *x)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        Ok((pk_arr, sk_arr))
    }
}
