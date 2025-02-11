use num_bigint::BigUint;
use num_traits::Zero;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::constants::*;

pub type HashOut = [u8; 20];

pub fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
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

pub fn hash160(input: &[u8]) -> HashOut {
    let hash = Sha256::digest(&input);
    let hash = Ripemd160::digest(&hash);
    return hash.into();
}

pub(crate) fn mod_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    value.modpow(&(modulus - BigUint::from(2u8)), modulus)
}

pub(crate) fn bytes_to_bigint(bytes: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

pub fn sqrt_fp(value: &BigUint, modulus: &BigUint) -> BigUint {
    let exp_sqrt = BigUint::parse_bytes(EXP_SQRT, 10).unwrap();
    let result = value.modpow(&exp_sqrt, modulus);
    let neg_result = negate_bigint(&result, modulus);
    let result = if neg_result > result {
        neg_result
    } else {
        result
    };
    assert_eq!(
        (&result * &result) % modulus,
        *value,
        "Square root verification failed"
    );
    result
}

pub(crate) fn bigint_to_bytes(value: &BigUint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let value_bytes = value.to_bytes_be();
    let len = value_bytes.len();
    bytes[32 - len..].copy_from_slice(&value_bytes);
    bytes
}

pub(crate) fn negate_bigint(value: &BigUint, modulus: &BigUint) -> BigUint {
    if value.is_zero() {
        BigUint::zero()
    } else {
        modulus - (value % modulus)
    }
}

pub(crate) fn sqrt_f2(
    a0: BigUint,
    a1: BigUint,
    hint: bool,
    modulus: &BigUint,
) -> (BigUint, BigUint) {
    let const_1_2 = BigUint::parse_bytes(CONST_1_2, 10).unwrap();
    let d = sqrt_fp(&((a0.pow(2) + &a1.pow(2)) % modulus), modulus);
    let d = if hint { negate_bigint(&d, modulus) } else { d };
    let x0 = sqrt_fp(&((((&a0 + &d) % modulus) * const_1_2) % modulus), modulus);
    let x1 = (&a1 * mod_inverse(&(&BigUint::from(2u8) * (&x0)), modulus)) % modulus;

    assert_eq!(
        a0,
        (x0.clone().pow(2) + negate_bigint(&(x1.clone().pow(2)), modulus)) % modulus
    );
    assert_eq!(a1, (BigUint::from(2u8) * x0.clone() * x1.clone()) % modulus);

    (x0, x1)
}
