mod utils;
mod constants;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use risc0_zkvm::Groth16ReceiptVerifierParameters;
use serde::{Deserialize, Serialize};

type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;
use crate::utils::*;
use bitcoin::hashes::{hash160, Hash};
use ark_bn254;
use ark_groth16::{Proof, prepare_verifying_key};
use ark_std::vec::Vec;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::str::FromStr;
use hex::ToHex;
use num_traits::Num;
use constants::*;


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
    DigitSignature { hash_bytes }
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
    for i in 0..ps.n1 {
        let sig = digit_signature(secret_key, i + digits.len() as u32, cheksum1[i as usize]);
        result.push(sig.hash_bytes);
    }
    result
}

// Takes signature as Witness for ease of use since sign method produces result in Witness.
// TODO: Change the signature type to u8 array
pub fn verify_signature(
    public_key: &PublicKey,
    signature: &Vec<Vec<u8>>,
    message: Vec<u8>,
    ps: &Parameters,
) -> Result<bool, String> {
    let checksum = add_message_checksum(ps, &message);
    for i in 0..message.len() {
        let digit = message[i];
        if digit == 255 {
            if signature[i] != public_key[i] {
                return Ok(false);
            };

            continue;
        }
        let hash_bytes = (0..(ps.d - digit as u32 - 1))
            .into_iter()
            .fold(hash160(&signature[i]), |hash, _| hash160(&hash));

        if hash_bytes != public_key[i] {
            println!("{:?}, {:?}", hash_bytes, public_key[i as usize]);
            return Ok(false);
        }
    }

    for i in 0..ps.n1 {
        let digit = checksum[i as usize];
        let ind = message.len() + i as usize;
        if digit == 255 {
            if signature[ind] != public_key[ind] {
                return Ok(false);
            };
            continue;
        }

        let hash_bytes = (0..(ps.d - digit as u32 - 1))
            .into_iter()
            .fold(hash160(&signature[ind]), |hash, _| hash160(&hash));

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

pub fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}

pub fn verify_winternitz_and_groth16(
    pub_key: &Vec<[u8; 20]>,
    signature: &Vec<Vec<u8>>,
    message: &Vec<u8>,
    params: &Parameters,
) {
    if !verify_signature(&pub_key, &signature, message.clone(), &params).unwrap() {
        panic!("Verification failed");
    }

    let a: [u8; 32] = message[0..32].try_into().unwrap();
    let b: [u8; 64] = message[32..96].try_into().unwrap();
    let c: [u8; 32] = message[96..128].try_into().unwrap();
    let total_work: [u8; 16] = message[128..144].try_into().unwrap();

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

    let ark_bn254_a = ark_bn254::G1Affine::new(
        ark_bn254::Fq::from_be_bytes_mod_order(&a0_serialized),
        ark_bn254::Fq::from_be_bytes_mod_order(&a1_serialized),
    );

    let ark_bn254_c = ark_bn254::G1Affine::new(
        ark_bn254::Fq::from_be_bytes_mod_order(&c0_serialized),
        ark_bn254::Fq::from_be_bytes_mod_order(&c1_serialized),
    );

    let ark_bn254_b = ark_bn254::G2Affine::new(
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_be_bytes_mod_order(&b00_serialized),
            ark_bn254::Fq::from_be_bytes_mod_order(&b01_serialized),
        ),
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_be_bytes_mod_order(&b10_serialized),
            ark_bn254::Fq::from_be_bytes_mod_order(&b11_serialized),
        ),
    );

    let ark_proof = Proof::<Bn254> {
        a: ark_bn254_a.into(),
        b: ark_bn254_b.into(),
        c: ark_bn254_c.into(),
    };

    println!("Proof: {:?}", ark_proof);

    println!("Proof created");

    let vk: ark_groth16::VerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> = create_verifying_key();
    let prepared_vk:ark_groth16::PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> = prepare_verifying_key(&vk);
    println!("Verifying key created");

    let output_tag: [u8; 32] = hex::decode(OUTPUT_TAG).unwrap().try_into().unwrap();
    let total_work_digest: [u8; 32] = Sha256::digest(&total_work).try_into().unwrap();
    let assumptions_bytes: [u8; 32] = hex::decode(ASSUMPTIONS_HEX).unwrap().try_into().unwrap();
    let len_output: [u8; 2] = hex::decode("0200").unwrap().try_into().unwrap();
    let mut output_pre_digest: [u8; 98] = [0; 98];

    output_pre_digest[0..32].copy_from_slice(&output_tag);
    output_pre_digest[32..64].copy_from_slice(&total_work_digest);
    output_pre_digest[64..96].copy_from_slice(&assumptions_bytes);
    output_pre_digest[96..98].copy_from_slice(&len_output);
    
    let output_digest = Sha256::digest(output_pre_digest);

    let pre_state_bytes: [u8; 32] = hex::decode(PRE_STATE_HEX).unwrap().try_into().unwrap();
    let post_state_bytes: [u8; 32] = hex::decode(POST_STATE_HEX).unwrap().try_into().unwrap();
    let input_bytes: [u8; 32] = hex::decode(INPUT_HEX).unwrap().try_into().unwrap();
    let claim_tag: [u8; 32] = hex::decode(CLAIM_TAG).unwrap().try_into().unwrap();

    let mut claim_pre_digest: [u8; 170] = [0; 170];

    let data: [u8; 8] = [0; 8];

    let claim_len: [u8; 2] = [4, 0];

    claim_pre_digest[0..32].copy_from_slice(&claim_tag);
    claim_pre_digest[32..64].copy_from_slice(&input_bytes);
    claim_pre_digest[64..96].copy_from_slice(&pre_state_bytes);
    claim_pre_digest[96..128].copy_from_slice(&post_state_bytes);
    claim_pre_digest[128..160].copy_from_slice(&output_digest);
    claim_pre_digest[160..168].copy_from_slice(&data);
    claim_pre_digest[168..170].copy_from_slice(&claim_len);

    let mut claim_digest = Sha256::digest(&claim_pre_digest);
    claim_digest.reverse();

    let claim_digest_hex: String = claim_digest.encode_hex();
    let c0_str = claim_digest_hex[0..32].to_string();
    let c1_str = claim_digest_hex[32..64].to_string();

    let c0_dec = to_decimal(&c0_str).unwrap();
    let c1_dec = to_decimal(&c1_str).unwrap();

    let groth16_receipt_verifier_params = Groth16ReceiptVerifierParameters::default();

    let groth16_control_root = groth16_receipt_verifier_params.control_root;
    let mut groth16_control_root_bytes: [u8; 32] = groth16_control_root.as_bytes().try_into().unwrap();
    groth16_control_root_bytes.reverse();

    // convert to be bytes 

    let groth16_control_root_bytes: String = groth16_control_root_bytes.encode_hex();
    let a1_str = groth16_control_root_bytes[0..32].to_string();
    let a0_str = groth16_control_root_bytes[32..64].to_string();

    let a1_dec = to_decimal(&a1_str).unwrap();
    let a0_dec = to_decimal(&a0_str).unwrap();

    let mut bn254_control_id_bytes: [u8; 32] = hex::decode(BN254_CONTROL_ID_HEX).unwrap().try_into().unwrap();
    bn254_control_id_bytes.reverse();

    let bn254_control_id_bytes: String = bn254_control_id_bytes.encode_hex();


    let bn254_control_id_dec = to_decimal(&bn254_control_id_bytes).unwrap();

    let mut public_inputs = Vec::new();

    public_inputs.push(Fr::from_str(&a0_dec).unwrap());
    public_inputs.push(Fr::from_str(&a1_dec).unwrap());
    public_inputs.push(Fr::from_str(&c1_dec).unwrap());
    public_inputs.push(Fr::from_str(&c0_dec).unwrap());
    public_inputs.push(Fr::from_str(&bn254_control_id_dec).unwrap());

    println!("Public inputs: {:?}", public_inputs);

    println!("{}", ark_groth16::Groth16::<Bn254>::verify_proof(&prepared_vk, &ark_proof, &public_inputs).unwrap());

}

pub fn g2_compress(point: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
    let x_real = BigUint::from_bytes_be(&point[0][1]);
    let x_imaginary = BigUint::from_bytes_be(&point[0][0]);
    let y_real = BigUint::from_bytes_be(&point[1][1]);
    let y_img = BigUint::from_bytes_be(&point[1][0]);

    println!(
        "x_real: {:?}, x_imaginary: {:?}, y_real: {:?}, y_img: {:?}",
        x_real, x_imaginary, y_real, y_img
    );
    let modulus = BigUint::parse_bytes(MODULUS, 10).unwrap();

    let y_neg = negate_bigint(&y_real, &modulus);

    let sign: u8 = if y_real < y_neg { 0x1 } else { 0x0 };

    let const_27_82 = BigUint::parse_bytes(CONST_27_82, 10).unwrap();
    let const_3_82 = BigUint::parse_bytes(CONST_3_82, 10).unwrap();

    let n3ab = (&x_real * &x_imaginary * (&modulus - BigUint::from(3u8))) % &modulus;
    let a_3 = (&x_real * &x_real * &x_real) % &modulus;
    let b_3 = (&x_imaginary * &x_imaginary * &x_imaginary) % &modulus;

    let m = (&const_27_82 + &a_3 + ((&n3ab * &x_imaginary) % &modulus)) % &modulus;
    let n = negate_bigint(
        &((&const_3_82 + &b_3 + (&n3ab * &x_real)) % &modulus),
        &modulus,
    );

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

pub fn g2_decompress(compressed: &[u8]) -> Option<[BigUint; 4]> {
    if compressed.len() != 64 {
        return None;
    }
    let modulus = BigUint::parse_bytes(MODULUS, 10).unwrap();
    let compressed_x0 = bytes_to_bigint(&compressed[0..32].try_into().unwrap());
    let compressed_x1 = bytes_to_bigint(&compressed[32..64].try_into().unwrap());

    let negate_point = (&compressed_x0 & BigUint::one()) == BigUint::one();
    let hint = (&compressed_x0 & BigUint::from(2u8)) == BigUint::from(2u8);
    let x0: BigUint = &compressed_x0 >> 2;
    let x1 = compressed_x1;

    let n3ab = (&x0 * &x1 * (&modulus - BigUint::from(3u8))) % &modulus;
    let a_3 = (&x0 * &x0 * &x0) % &modulus;
    let b_3 = (&x1 * &x1 * &x1) % &modulus;

    let const_27_82 = BigUint::parse_bytes(CONST_27_82, 10).unwrap();
    let const_3_82 = BigUint::parse_bytes(CONST_3_82, 10).unwrap();
    let y0 = (&const_27_82 + &a_3 + ((&n3ab * &x1) % &modulus)) % &modulus;
    let y1 = negate_bigint(&((&const_3_82 + &b_3 + (&n3ab * &x0)) % &modulus), &modulus);
    let (y0, y1) = sqrt_f2(y0, y1, hint, &modulus);

    if negate_point {
        let y1 = negate_bigint(&y1, &modulus);
        let y0 = negate_bigint(&y0, &modulus);
        return Some([x0, x1, y0, y1]);
    }

    Some([x0, x1, y0, y1])
}

pub fn g1_compress(point: Vec<Vec<u8>>) -> Vec<u8> {
    let modulus = BigUint::parse_bytes(MODULUS, 10).unwrap();

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
    if compressed.len() != 32 {
        return None;
    }

    let modulus = BigUint::parse_bytes(MODULUS, 10).unwrap();

    let compressed_x = bytes_to_bigint(&compressed.try_into().unwrap());
    let negate_point = (&compressed_x & BigUint::one()) == BigUint::one();
    let x = &compressed_x >> 1;

    let y = sqrt_fp(&((&x * &x * &x + BigUint::from(3u8)) % &modulus), &modulus);
    let y = if negate_point {
        negate_bigint(&y, &modulus)
    } else {
        y
    };
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

fn bigint_to_bytes(value: &BigUint) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let value_bytes = value.to_bytes_be();
    let len = value_bytes.len();
    bytes[32 - len..].copy_from_slice(&value_bytes);
    bytes
}
