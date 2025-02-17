use serde::{Deserialize, Serialize};
pub type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;
use crate::utils::hash160;
use bitcoin::hashes::{self, Hash};

pub fn verify_signature(
    public_key: &PublicKey,
    signature: &[Vec<u8>],
    message: &[u8],
    ps: &Parameters,
) -> bool {
    if public_key.len() != ps.n as usize || signature.len() != ps.n as usize || message.len() != ps.n0 as usize {
        return false;
    }
    let checksum = get_message_checksum(ps, message);

    for (i, &digit) in message.iter().enumerate() {
        let signature_byte_arr: [u8; 20] = signature[i].as_slice().try_into().unwrap();

        let hash_bytes =
            (0..(ps.d - digit as u32)).fold(signature_byte_arr, |hash, _| hash160(&hash));

        if hash_bytes != public_key[i] {
            println!("{:?}, {:?}", hash_bytes, public_key[i]);
            return false;
        }
    }

    for ((&checksum, sig), &pubkey) in checksum
        .iter()
        .zip(&signature[message.len()..])
        .zip(&public_key[message.len()..])
    {
        let signature_byte_arr: [u8; 20] = sig.as_slice().try_into().unwrap();
        let hash_bytes =
            (0..(ps.d - checksum as u32)).fold(signature_byte_arr, |hash, _| hash160(&hash));

        if hash_bytes != pubkey {
            println!("{:?}, {:?}", hash_bytes, pubkey);
            return false;
        }
    }

    true
}

pub fn get_message_checksum(ps: &Parameters, digits: &[u8]) -> Vec<u8> {
    to_digits(checksum(ps, digits), ps.d + 1, ps.n1 as i32)
}

pub fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: &[u8]) -> Vec<Vec<u8>> {
    let cheksum1 = get_message_checksum(ps, digits);
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(ps.n as usize);
    for i in 0..ps.n0 {
        let sig = digit_signature(secret_key, i, digits[i as usize]);
        result.push(sig.hash_bytes);
    }
    for i in 0..ps.n1 {
        let sig = digit_signature(secret_key, i + digits.len() as u32, cheksum1[i as usize]);
        result.push(sig.hash_bytes);
    }
    result
}

pub fn generate_public_key(ps: &Parameters, secret_key: &SecretKey) -> PublicKey {
    let mut public_key = PublicKey::with_capacity(ps.n as usize);
    for i in 0..ps.n {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

fn checksum(ps: &Parameters, digits: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for &digit in digits {
        sum += digit as u32;
    }
    ps.d * ps.n0 - sum
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Parameters {
    n0: u32,
    log_d: u32,
    n1: u32,
    d: u32,
    n: u32,
}

#[derive(Debug, Clone)]
pub struct DigitSignature {
    pub hash_bytes: Vec<u8>,
}

impl Parameters {
    pub fn new(n0: u32, log_d: u32) -> Self {
        assert!(
            (4..=8).contains(&log_d),
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
    let mut hash = hashes::hash160::Hash::hash(&secret_i);

    for _ in 0..ps.d {
        hash = hashes::hash160::Hash::hash(&hash[..]);
    }

    *hash.as_byte_array()
}

pub fn digit_signature(
    secret_key: &SecretKey,
    digit_index: u32,
    message_digit: u8,
) -> DigitSignature {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hashes::hash160::Hash::hash(&secret_i);
    for _ in 0..message_digit {
        hash = hashes::hash160::Hash::hash(&hash[..]);
    }
    let hash_bytes = hash.as_byte_array().to_vec();
    DigitSignature { hash_bytes }
}

pub fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u8> {
    let mut digits = Vec::new();
    if digit_count == -1 {
        while number > 0 {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    } else {
        digits.reserve(digit_count as usize);
        for _ in 0..digit_count {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    }
    let mut digits_u8: Vec<u8> = vec![0; digits.len()];
    for (i, num) in digits.iter().enumerate() {
        let bytes = num.to_le_bytes(); // Convert u32 to 4 bytes (little-endian)
        digits_u8[i] = bytes[0];
    }
    digits_u8
}

pub fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}
