use ark_bn254::{g1, Bn254, G1Affine};
use ark_ff::PrimeField;
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

use ark_std::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{Zero, One};    
use std::convert::TryInto;
use risc0_groth16::{verifying_key, Seal};
use ark_bn254;
use ark_groth16::{Proof};


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

    let risc0_groth16_verifying_key = verifying_key();

    let a_decompressed = g1_decompress(&a).unwrap();
    let b_decompressed = g2_decompress(&b).unwrap();
    let c_decompressed = g1_decompress(&c).unwrap();

    let a0_serialized = a_decompressed[0].to_bytes_be();
    let a1_serialized = a_decompressed[1].to_bytes_be();
    let b00_serialized = b_decompressed[0].to_bytes_be();
    let b01_serialized = b_decompressed[1].to_bytes_be();
    let b10_serialized = b_decompressed[2].to_bytes_be();
    let b11_serialized = b_decompressed[3].to_bytes_be();
    let c0_serialized = c_decompressed[0].to_bytes_be();
    let c1_serialized = c_decompressed[1].to_bytes_be();

    let ark_bn254_a = 
    ark_bn254::G1Affine::new(ark_bn254::Fq::from_be_bytes_mod_order(&a0_serialized), ark_bn254::Fq::from_be_bytes_mod_order(&a1_serialized));

    let ark_bn254_c = 
    ark_bn254::G1Affine::new(ark_bn254::Fq::from_be_bytes_mod_order(&c0_serialized), ark_bn254::Fq::from_be_bytes_mod_order(&c1_serialized));

    let ark_bn254_b = 
    ark_bn254::G2Affine::new(
                ark_bn254::Fq2::new(ark_bn254::Fq::from_be_bytes_mod_order(&b00_serialized), ark_bn254::Fq::from_be_bytes_mod_order(&b01_serialized)),
                ark_bn254::Fq2::new(ark_bn254::Fq::from_be_bytes_mod_order(&b10_serialized), ark_bn254::Fq::from_be_bytes_mod_order(&b11_serialized)));

    let ark_proof = Proof::<Bn254> {
        a: ark_bn254_a.into(),
        b: ark_bn254_b.into(),
        c: ark_bn254_c.into(),
    };
    
    println!("{:?}", total_work);

}


fn get_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10
    ).unwrap()
}

fn get_exp_sqrt() -> BigUint{
    BigUint::parse_bytes(
        b"5472060717959818805561601436314318772174077789324455915672259473661306552146", 10
    ).unwrap()
}

fn get_const_1_2() -> BigUint{
    BigUint::parse_bytes(
        b"10944121435919637611123202872628637544348155578648911831344518947322613104292", 10
    ).unwrap()
}

fn get_const_27_82() -> BigUint{
    BigUint::parse_bytes(
        b"19485874751759354771024239261021720505790618469301721065564631296452457478373", 10
    ).unwrap()
}

fn get_const_3_82() -> BigUint{
    BigUint::parse_bytes(
        b"21621313080719284060999498358119991246151234191964923374119659383734918571893", 10
    ).unwrap()
}

pub fn g2_compress(point: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
    let x_real = BigUint::from_bytes_be(&point[0][1]);
    let x_imaginary = BigUint::from_bytes_be(&point[0][0]);
    let y_real = BigUint::from_bytes_be(&point[1][1]);
    let y_img = BigUint::from_bytes_be(&point[1][0]);

    println!("x_real: {:?}, x_imaginary: {:?}, y_real: {:?}, y_img: {:?}", x_real, x_imaginary, y_real, y_img);
    let modulus = get_modulus();

    let y_neg = negate_bigint(&y_real, &modulus);
    
    let sign: u8 = if y_real < y_neg { 0x1 } else { 0x0 };

    let const_27_82 = get_const_27_82();
    let const_3_82 = get_const_3_82();
    
    let n3ab = (&x_real * &x_imaginary * (&modulus - BigUint::from(3u8))) % &modulus;
    let a_3 = (&x_real * &x_real * &x_real) % &modulus;
    let b_3 = (&x_imaginary * &x_imaginary * &x_imaginary) % &modulus;

    let m = (&const_27_82 + &a_3 + ((&n3ab * &x_imaginary) % &modulus)) % &modulus;
    let n = negate_bigint(&((&const_3_82 + &b_3 + (&n3ab * &x_real)) % &modulus), &modulus);

    let d = sqrt_fp(&((m.pow(2) + n.pow(2)) % &modulus), &modulus);

    let d_check = (y_real.pow(2) + y_img.pow(2)) % modulus;

    let hint = if d == d_check { 0x0 } else { 0x2 };
    
    let flag = sign | hint;

    let compressed_x0 = (&x_real << 2) | BigUint::from(flag);
    let compressed_x1 = x_imaginary;

    let mut compressed = Vec::new();
    compressed.extend_from_slice(&bigint_to_bytes(&compressed_x0));
    compressed.extend_from_slice(&bigint_to_bytes(&compressed_x1));
    compressed
}

fn sqrt_f2(a0: BigUint, a1: BigUint, hint: bool, modulus: &BigUint) -> (BigUint, BigUint) {
    let const_1_2 = get_const_1_2();
    let d = sqrt_fp(&((a0.pow(2) + &a1.pow(2)) % modulus), modulus);
    let d = if hint { negate_bigint(&d, modulus) } else { d };
    let x0 = sqrt_fp(&((((&a0 + &d) % modulus ) * const_1_2) % modulus), modulus);
    let x1 = (&a1 * mod_inverse(&(&BigUint::from(2u8) * (&x0)), modulus)) % modulus;
    
    assert_eq!(a0, (x0.clone().pow(2) + negate_bigint(&(x1.clone().pow(2)), modulus)) % modulus);
    assert_eq!(a1, (BigUint::from(2u8) * x0.clone() * x1.clone()) % modulus);
    
    (x0, x1)
}

pub fn g2_decompress(compressed: &[u8]) -> Option<[BigUint; 4]> {
    if compressed.len() != 64 { return None; }
    let modulus = get_modulus();
    
    let compressed_x0 = bytes_to_bigint(&compressed[0..32].try_into().unwrap());
    let compressed_x1 = bytes_to_bigint(&compressed[32..64].try_into().unwrap());
    
    let negate_point = (&compressed_x0 & BigUint::one()) == BigUint::one();
    let hint = (&compressed_x0 & BigUint::from(2u8)) == BigUint::from(2u8);
    let x0: BigUint = &compressed_x0 >> 2;
    let x1 = compressed_x1;
    
    let n3ab = (&x0 * &x1 * (&modulus - BigUint::from(3u8))) % &modulus;
    let a_3 = (&x0 * &x0 * &x0) % &modulus;
    let b_3 = (&x1 * &x1 * &x1) % &modulus;
    
    let const_27_82 = get_const_27_82();
    let const_3_82 = get_const_3_82();
    let y0 = (&const_27_82 + &a_3 + ((&n3ab * &x1) % &modulus)) % &modulus;
    let y1 = negate_bigint(&((&const_3_82 + &b_3 + (&n3ab * &x0)) % &modulus), &modulus);
    let (y0, y1) = sqrt_f2(y0, y1, hint, &modulus);
    
    if negate_point {
        let y1 = negate_bigint(&y1, &modulus);
        let y0 = negate_bigint(&y0, &modulus);
        return Some([x0, x1, y0, y1])
    }
    
    Some([x0, x1, y0, y1])
}

pub fn g1_compress(point: Vec<Vec<u8>>) -> Vec<u8> {
    let modulus = get_modulus();
    
    let x = BigUint::from_bytes_be(&point[0]);
    let y = BigUint::from_bytes_be(&point[1]);


    println!("x: {:?}, y: {:?}", x, y);

    let y_neg = negate_bigint(&y, &modulus);
    let sign: u8 = if y < y_neg { 0x1 } else { 0x0 };

    let compressed = (&x << 1) | BigUint::from(sign);

    bigint_to_bytes(&compressed).to_vec()
}

/// Decompress a G1 point from a byte vector
pub fn g1_decompress(compressed: &[u8]) -> Option<[BigUint; 2]> {
    if compressed.len() != 32 { return None; }

    let modulus = get_modulus();
    
    let compressed_x = bytes_to_bigint(&compressed.try_into().unwrap());
    let negate_point = (&compressed_x & BigUint::one()) == BigUint::one();
    let x = &compressed_x >> 1;
    
    let y = sqrt_fp(&((&x * &x * &x + BigUint::from(3u8)) % &modulus), &modulus);
    let y = if negate_point { negate_bigint(&y, &modulus) } else { y };
    Some([x, y])
}

pub(crate) fn negate_bigint(value: &BigUint, modulus: &BigUint) -> BigUint {
    if value.is_zero() {
        BigUint::zero()
    } else {
        modulus - (value % modulus)
    }
}

fn mod_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    value.modpow(&(modulus - BigUint::from(2u8)), modulus)
}


fn bytes_to_bigint(bytes: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn sqrt_fp(value: &BigUint, modulus: &BigUint) -> BigUint {

    let exp_sqrt = get_exp_sqrt();
    let result = value.modpow(&exp_sqrt, modulus);
    let neg_result = negate_bigint(&result, modulus);
    let result = if neg_result > result { neg_result } else { result };
    assert_eq!((&result * &result) % modulus, *value, "Square root verification failed");
    result
}

fn bigint_to_bytes(value: &BigUint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let value_bytes = value.to_bytes_be();
    let len = value_bytes.len();
    bytes[32 - len..].copy_from_slice(&value_bytes);
    bytes
}