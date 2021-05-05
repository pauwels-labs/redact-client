use serde_json::Value;
use sodiumoxide::crypto;

pub trait KeypairGenerator {
    fn create() -> Result<(Value, Value), serde_json::Error>;
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
    fn create() -> Result<(Value, Value), serde_json::Error> {
        let (pk, sk) = crypto::box_::gen_keypair();
        let pk_val = serde_json::to_value(&pk)?;
        let sk_val = serde_json::to_value(&sk)?;
        Ok((pk_val, sk_val))
    }
}
