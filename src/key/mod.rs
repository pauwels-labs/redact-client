use super::error::Error;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key as NaKey, Nonce as NaNonce};
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::io::ErrorKind;

#[derive(Debug)]
pub struct Key {
    pub key: NaKey,
    pub nonce: NaNonce,
}

impl<'a> TryFrom<&'a [u8]> for Key {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 56 {
            return Err(Error::new(
                format!(
                    "key byte slice should be 56 bytes long, was {} bytes long",
                    bytes.len()
                ),
                vec![],
            ));
        }

        let mut byte_arr = [0u8; 56];
        for i in 0..56 {
            byte_arr[i] = bytes[i];
        }

        Ok(Key::from(byte_arr))
    }
}

impl From<[u8; 56]> for Key {
    fn from(bytes: [u8; 56]) -> Self {
        let na_key = NaKey::from_slice(&bytes[0..32])
            .ok_or(Error::new(
                "could not extract key from file".to_owned(),
                vec![],
            ))
            .unwrap();

        let na_nonce = NaNonce::from_slice(&bytes[32..56])
            .ok_or(Error::new(
                "could not extract none from file".to_owned(),
                vec![],
            ))
            .unwrap();

        Key {
            key: na_key,
            nonce: na_nonce,
        }
    }
}

impl Key {
    pub fn new(path: &str) -> Result<Key, Error> {
        fs::read(path).map_or_else(
            |e| match e.kind() {
                ErrorKind::NotFound => Key::write_key(path),
                _ => Err(Error::new(
                    format!("could not read key at {}: {}", path, e),
                    vec![],
                )),
            },
            |encoded_bytes| {
                let decoded_bytes = base64::decode(encoded_bytes).unwrap();
                decoded_bytes.as_slice().try_into()
            },
        )
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        secretbox::open(data, &self.nonce, &self.key)
            .map_err(|()| Error::new(format!("could not decrypt decoded data"), vec![]))
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        secretbox::seal(data, &self.nonce, &self.key)
    }

    fn write_key(path: &str) -> Result<Key, Error> {
        let key = xsalsa20poly1305::gen_key();
        let nonce = xsalsa20poly1305::gen_nonce();

        if key.0.len() != 32 {
            return Err(Error::new(
                format!(
                    "expected generated key to be 32 bytes long, was {} bytes long",
                    key.0.len()
                ),
                vec![],
            ));
        }
        if nonce.0.len() != 24 {
            return Err(Error::new(
                format!(
                    "expected generated nonce to be 24 bytes long, was {} bytes long",
                    nonce.0.len()
                ),
                vec![],
            ));
        }

        let all_bytes: Vec<u8> = key
            .0
            .iter()
            .chain(nonce.0.iter())
            .map(|b| b.to_owned())
            .collect();
        fs::write(path, base64::encode(&all_bytes))
            .map_err(|e| {
                Error::new(
                    format!("could not write new key file to {}: {}", path, e),
                    vec![],
                )
            })
            .and_then(|()| all_bytes.as_slice().try_into())
    }
}
