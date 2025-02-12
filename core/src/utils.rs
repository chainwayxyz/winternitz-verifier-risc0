use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn hash160(input: &[u8]) -> [u8; 20] {
    let hash = Sha256::digest(input);
    let hash = Ripemd160::digest(hash);
    hash.into()
}