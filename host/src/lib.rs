use ark_std::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{Zero, One};    
use std::convert::TryInto;

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct G16Proof{
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64]
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

    let y_neg = negate_bigint(&y_real, &(BigUint::one() << 256));
    
    let sign: u8 = if y_real < y_neg { 0x1 } else { 0x0 };

    let const_27_82 = get_const_27_82();
    let const_3_82 = get_const_3_82();
    let modulus = get_modulus();
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


