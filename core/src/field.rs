use num_bigint::BigUint;
use num_traits::Zero;

use crate::constants::{CONST_1_2, EXP_SQRT};

pub(crate) fn mod_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    value.modpow(&(modulus - BigUint::from(2u8)), modulus)
}

pub fn bytes_to_bigint(bytes: &[u8; 32]) -> BigUint {
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