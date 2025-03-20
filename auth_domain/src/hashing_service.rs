use hex;
use rand::{thread_rng, RngCore};
use ring::digest::{Context, SHA256};
use auth_data::entities::SaltedHash;

pub trait HashingService: Send + Sync {
    fn hash_password(&self, value: &str) -> SaltedHash;
    fn verify(&self, value: &str, salted_hash: &SaltedHash) -> bool;
    fn hash_with_salt(&self, value: &str, salt: &str) -> String;
}

#[derive(Clone)]
pub struct SHA256HashingService {
    salt_length: usize,
}

impl SHA256HashingService {
    pub fn new(salt_length: usize) -> Self {
        SHA256HashingService { salt_length }
    }
}

impl Default for SHA256HashingService {
    fn default() -> Self {
        SHA256HashingService { salt_length: 32 }
    }
}

impl HashingService for SHA256HashingService {
    fn hash_password(&self, value: &str) -> SaltedHash {
        let mut salt = vec![0u8; self.salt_length];
        thread_rng().fill_bytes(&mut salt);
        let salt_hex = hex::encode(salt.clone());

        let mut context = Context::new(&SHA256);
        context.update(salt.as_slice());
        context.update(value.as_bytes());
        let hash = context.finish();

        SaltedHash {
            hash: hex::encode(hash.as_ref()),
            salt: salt_hex,
        }
    }

    fn verify(&self, value: &str, salted_hash: &SaltedHash) -> bool {
        let mut context = Context::new(&SHA256);
        context.update(hex::decode(&salted_hash.salt).unwrap().as_slice());
        context.update(value.as_bytes());
        let hash = context.finish();

        hex::encode(hash.as_ref()) == salted_hash.hash
    }

    fn hash_with_salt(&self, value: &str, salt: &str) -> String {
        let mut context = Context::new(&SHA256);
        context.update(hex::decode(salt).unwrap().as_slice());
        context.update(value.as_bytes());
        hex::encode(context.finish().as_ref())
    }
}
