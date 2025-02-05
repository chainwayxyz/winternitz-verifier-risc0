use serde::{Deserialize, Serialize};
mod utils;
type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;
use crate::utils::*;
use bitcoin::{
    hashes::{Hash, hash160},
    Witness,
};

use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Parameters {
    n0: u32,
    log_d: u32,
    n1: u32,
    d: u32,
    n: u32,
}

pub struct DigitSignature {
    pub hash_bytes: Vec<u8>,
}

impl Parameters {
    pub fn new(n0: u32, log_d: u32) -> Self {
        assert!(
            4 <= log_d && log_d <= 8,
            "You can only choose block lengths in the range [4, 8]"
        );
        let d: u32 = (1 << log_d) - 1;
        let n1: u32 = log_base_ceil(d * n0, d + 1) + 1;
        let n: u32 = n0 + n1;
        Parameters {
            n0,
            log_d,
            n1,
            d,
            n,
        }
    }
}

fn public_key_for_digit(ps: &Parameters, secret_key: &SecretKey, digit_index: u32) -> HashOut {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..ps.d {
        hash = hash160::Hash::hash(&hash[..]);
    }

    *hash.as_byte_array() 
}

pub fn digit_signature(
    secret_key: &SecretKey,
    digit_index: u32,
    message_digit: u32,
) -> DigitSignature {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);
    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }
    let hash_bytes = hash.as_byte_array().to_vec();
    DigitSignature {
        hash_bytes,
    }
}

pub fn generate_public_key(ps: &Parameters, secret_key: &SecretKey) -> PublicKey {
    let mut public_key = PublicKey::with_capacity(ps.n as usize);
    for i in 0..ps.n {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

fn checksum(ps: &Parameters, digits: Vec<u32>) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit;
    }
    ps.d * ps.n0 - sum
}

fn add_message_checksum(ps: &Parameters, mut digits: Vec<u32>) -> Vec<u32> {
    let mut checksum_digits = to_digits(checksum(ps, digits.clone()), ps.d + 1, ps.n1 as i32);
    checksum_digits.append(&mut digits);
    checksum_digits.reverse();
    checksum_digits
}

pub fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: Vec<u32>) -> Witness {
    let digits = add_message_checksum(ps, digits);
    let mut result = Witness::new();
    for i in 0..ps.n {
        let sig = digit_signature(secret_key, i, digits[i as usize]);
        result.push(sig.hash_bytes);
        result.push(u32_to_le_bytes_minimal(digits[i as usize]));
    }
    result
}


// Takes signature as Witness for ease of use since sign method produces result in Witness.
// TODO: Change the signature type to u8 array
pub fn verify_signature(public_key: &PublicKey, signature: &Witness, ps: &Parameters) -> Result<bool, String>  {
    
    for i in 0..public_key.len() {
        let digit = signature.nth(i*2 + 1).ok_or("Signature is not complete")?;
        let mut digit2 = [0u8;4];
        for i in 0..digit.len() {
            digit2[i] = digit[i];
        }
        
        let digit = if digit.len() > 0 {u32::from_le_bytes(digit2)} else {0};
        let hash = signature.nth(i*2).ok_or("Signature is not complete")?;
        let hash_bytes = (0..(ps.d - digit - 1)).into_iter().fold(hash160(hash), |hash, _| hash160(&hash));

        if hash_bytes != public_key[i] {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn hash160(input: &[u8]) -> HashOut {
    let hash = Sha256::digest(&input);
    let hash = Ripemd160::digest(&hash);
    return hash.into();
}