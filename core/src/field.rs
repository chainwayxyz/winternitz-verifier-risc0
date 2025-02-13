use num_bigint::BigUint;
use num_traits::Zero;

use crate::{
    constants::{CONST_1_2, EXP_SQRT, MODULUS},
    error::FieldError,
};

pub(crate) fn mod_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    value.modpow(&(modulus - BigUint::from(2u8)), modulus)
}

pub fn bytes_to_bigint(bytes: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

pub fn sqrt_fp(value: &BigUint) -> Result<BigUint, FieldError> {
    let modulus = &BigUint::parse_bytes(MODULUS, 10).unwrap();
    let exp_sqrt = BigUint::parse_bytes(EXP_SQRT, 10).unwrap();
    let result = value.modpow(&exp_sqrt, modulus);
    let neg_result = negate_bigint(&result, modulus);
    let result = if neg_result > result {
        neg_result
    } else {
        result
    };

    if (&result * &result) % modulus != value % modulus {
        return Err(FieldError::F1SquareRootError);
    }
    Ok(result)
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
) -> Result<(BigUint, BigUint), FieldError> {
    let modulus = &BigUint::parse_bytes(MODULUS, 10).unwrap();
    let const_1_2 = BigUint::parse_bytes(CONST_1_2, 10).unwrap();
    let d = sqrt_fp(&((a0.pow(2) + &a1.pow(2)) % modulus))?;
    let d = if hint { negate_bigint(&d, modulus) } else { d };
    let x0 = sqrt_fp(&((((&a0 + &d) % modulus) * const_1_2) % modulus))?;
    let x1 = (&a1 * mod_inverse(&(&BigUint::from(2u8) * (&x0)), modulus)) % modulus;

    if a0 % modulus != (x0.clone().pow(2) + negate_bigint(&(x1.clone().pow(2)), modulus)) % modulus
        || a1 != (BigUint::from(2u8) * x0.clone() * x1.clone()) % modulus
    {
        return Err(FieldError::F2SquareRootError);
    }

    Ok((x0, x1))
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_mod_inverse() {
        let value = BigUint::from(5u8);
        let modulus = BigUint::from(7u8);
        let result = mod_inverse(&value, &modulus);
        assert_eq!(result, BigUint::from(3u8));
    }

    #[test]
    fn test_sqrt_fp() {
        let nums_with_squares: [u8; 137] = [
            1, 2, 4, 7, 8, 9, 11, 13, 14, 15, 16, 17, 18, 19, 22, 23, 25, 26, 28, 29, 30, 32, 34,
            36, 37, 38, 44, 46, 49, 50, 52, 53, 56, 58, 60, 63, 64, 68, 71, 72, 74, 76, 77, 79, 81,
            83, 88, 91, 92, 93, 98, 99, 100, 104, 105, 106, 107, 112, 113, 116, 117, 119, 120, 121,
            123, 126, 128, 129, 133, 135, 136, 141, 142, 143, 144, 148, 149, 151, 152, 153, 154,
            155, 157, 158, 161, 162, 163, 165, 166, 169, 171, 173, 175, 176, 177, 181, 182, 183,
            184, 186, 187, 191, 193, 195, 196, 197, 198, 199, 200, 201, 203, 205, 207, 208, 209,
            210, 212, 214, 215, 219, 221, 224, 225, 226, 229, 232, 233, 234, 235, 238, 240, 241,
            242, 246, 247, 252, 253,
        ];
        for &value in nums_with_squares.iter() {
            let value = BigUint::from(value);
            let modulus = &BigUint::parse_bytes(MODULUS, 10).unwrap();
            let result = sqrt_fp(&value).unwrap();

            assert_eq!((result.clone() * result.clone()) % modulus, value % modulus);
        }
    }
}
