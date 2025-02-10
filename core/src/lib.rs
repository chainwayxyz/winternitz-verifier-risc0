use serde::{Deserialize, Serialize};
mod utils;
type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;
use crate::utils::*;
use bitcoin::{
    bech32::primitives::checksum, hashes::{hash160, Hash}, p2p::message, params, Witness
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
    message_digit: u8,
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

fn checksum(ps: &Parameters, digits: Vec<u8>) -> u32 {
    let mut sum: u32 = 0;
    for digit in digits {
        sum += digit as u32;
    }
    ps.d * ps.n0 - sum
}

fn add_message_checksum(ps: &Parameters, digits: &Vec<u8>) -> Vec<u8> {
    let checksum_digits = to_digits(checksum(ps, digits.clone()), ps.d + 1, ps.n1 as i32);
    checksum_digits
}

pub fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: &Vec<u8>) -> Vec<Vec<u8>> {
    let cheksum1 = add_message_checksum(ps, digits);
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(ps.n as usize);
    for i in 0..ps.n0 {
        let sig = digit_signature(secret_key, i, digits[i as usize]);
        result.push(sig.hash_bytes);
    }
    for i in 0..ps.n1{
        let sig = digit_signature(secret_key, i + digits.len() as u32 , cheksum1[i as usize]);
        result.push(sig.hash_bytes);
    }
    result
}


// Takes signature as Witness for ease of use since sign method produces result in Witness.
// TODO: Change the signature type to u8 array
pub fn verify_signature(public_key: &PublicKey, signature: &Vec<Vec<u8>>, message: Vec<u8>, ps: &Parameters) -> Result<bool, String>  {
    let checksum = add_message_checksum(ps, &message);
    for i in 0..message.len() {
        let digit = message[i];
        if digit == 255{ 
            if signature[i] != public_key[i] {
                return Ok(false);
            };
         
            continue; 
        }
        let hash_bytes = (0..(ps.d - digit as u32 - 1)).into_iter().fold(hash160(&signature[i]), |hash, _| hash160(&hash));

        if hash_bytes != public_key[i] {
            println!("{:?}, {:?}", hash_bytes, public_key[i as usize]);
            return Ok(false);
        }
    }

    for i in 0..ps.n1{
        let digit = checksum[i as usize];
        let ind = message.len() + i as usize;
        if digit == 255{ 
            if signature[ind] != public_key[ind] {
                return Ok(false);
            };
            continue; 
        }

        let hash_bytes = (0..(ps.d - digit as u32 - 1)).into_iter().fold(hash160(&signature[ind]), |hash, _| hash160(&hash));
        
        if hash_bytes != public_key[ind] {
            println!("{:?}, {:?}", hash_bytes, public_key[ind]);
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


pub fn verify_winternitz_and_groth16(pub_key: &Vec<[u8; 20]> , signature: &Vec<Vec<u8>>, message: &Vec<u8>, params: &Parameters){
    if !verify_signature(&pub_key, &signature, message.clone(), &params).unwrap() {
        panic!("Verification failed");
    }

    let a: [u8; 32] = message[0..32].try_into().unwrap();
    let b: [u8; 64] = message[32..96].try_into().unwrap();
    let c: [u8; 32] = message[96..128].try_into().unwrap();
    let total_work: [u8; 16] = message[128..144].try_into().unwrap();
    println!("{:?}", total_work);

}