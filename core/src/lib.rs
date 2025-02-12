mod constants;
pub mod groth16;
pub mod utils;
use ark_bn254;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Proof};
use ark_std::vec::Vec;
use bitcoin::hashes::{self, Hash};
use constants::*;
use groth16::Groth16Seal;
use hex::ToHex;
use num_bigint::BigUint;
use num_traits::Num;
use risc0_zkvm::Groth16ReceiptVerifierParameters;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::str::FromStr;
use utils::*;
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;
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

fn get_message_checksum(ps: &Parameters, digits: &Vec<u8>) -> Vec<u8> {
    let checksum_digits = to_digits(checksum(ps, digits.clone()), ps.d + 1, ps.n1 as i32);
    checksum_digits
}

pub fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: &Vec<u8>) -> Vec<Vec<u8>> {
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

// Takes signature as Witness for ease of use since sign method produces result in Witness.
// TODO: Change the signature type to u8 array
pub fn verify_signature(
    public_key: &PublicKey,
    signature: &Vec<Vec<u8>>,
    message: Vec<u8>,
    ps: &Parameters,
) -> Result<bool, String> {
    let checksum = get_message_checksum(ps, &message);
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

    let compressed_seal: [u8; 128] = message[0..128].try_into().unwrap();
    let total_work: [u8; 16] = message[128..144].try_into().unwrap();

    let seal = groth16::Groth16Seal::from_compressed(&compressed_seal).unwrap();

    let ark_proof = create_ark_proof(seal);

    let vk: ark_groth16::VerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> = create_verifying_key();
    let prepared_vk: ark_groth16::PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> =
        prepare_verifying_key(&vk);

    let output_tag: [u8; 32] = hex::decode(OUTPUT_TAG).unwrap().try_into().unwrap();
    let total_work_digest: [u8; 32] = Sha256::digest(&total_work).try_into().unwrap();
    let assumptions_bytes: [u8; 32] = hex::decode(ASSUMPTIONS_HEX).unwrap().try_into().unwrap();
    let len_output: [u8; 2] = hex::decode("0200").unwrap().try_into().unwrap();
    let mut output_pre_digest: [u8; 98] = [0; 98];

    let concantenated_output = [
        &output_tag[..],
        &total_work_digest[..],
        &assumptions_bytes[..],
        &len_output[..],
    ]
    .concat();

    output_pre_digest.copy_from_slice(&concantenated_output);

    let output_digest = Sha256::digest(output_pre_digest);

    let pre_state_bytes: [u8; 32] = hex::decode(PRE_STATE_HEX).unwrap().try_into().unwrap();
    let post_state_bytes: [u8; 32] = hex::decode(POST_STATE_HEX).unwrap().try_into().unwrap();
    let input_bytes: [u8; 32] = hex::decode(INPUT_HEX).unwrap().try_into().unwrap();
    let claim_tag: [u8; 32] = hex::decode(CLAIM_TAG).unwrap().try_into().unwrap();

    let mut claim_pre_digest: [u8; 170] = [0; 170];

    let data: [u8; 8] = [0; 8];

    let claim_len: [u8; 2] = [4, 0];

    let concatenated = [
        &claim_tag[..],
        &input_bytes[..],
        &pre_state_bytes[..],
        &post_state_bytes[..],
        &output_digest[..],
        &data[..],
        &claim_len[..],
    ]
    .concat();

    claim_pre_digest.copy_from_slice(&concatenated);

    let mut claim_digest = Sha256::digest(&claim_pre_digest);
    claim_digest.reverse();

    let claim_digest_hex: String = claim_digest.encode_hex();
    let c0_str = claim_digest_hex[0..32].to_string();
    let c1_str = claim_digest_hex[32..64].to_string();

    let c0_dec = to_decimal(&c0_str).unwrap();
    let c1_dec = to_decimal(&c1_str).unwrap();

    let groth16_receipt_verifier_params = Groth16ReceiptVerifierParameters::default();

    let groth16_control_root = groth16_receipt_verifier_params.control_root;
    let mut groth16_control_root_bytes: [u8; 32] =
        groth16_control_root.as_bytes().try_into().unwrap();
    groth16_control_root_bytes.reverse();

    let groth16_control_root_bytes: String = groth16_control_root_bytes.encode_hex();
    let a1_str = groth16_control_root_bytes[0..32].to_string();
    let a0_str = groth16_control_root_bytes[32..64].to_string();

    let a1_dec = to_decimal(&a1_str).unwrap();
    let a0_dec = to_decimal(&a0_str).unwrap();

    let mut bn254_control_id_bytes: [u8; 32] = hex::decode(BN254_CONTROL_ID_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    bn254_control_id_bytes.reverse();

    let bn254_control_id_bytes: String = bn254_control_id_bytes.encode_hex();

    let bn254_control_id_dec = to_decimal(&bn254_control_id_bytes).unwrap();

    let mut public_inputs = Vec::new();

    let values = [&a0_dec, &a1_dec, &c1_dec, &c0_dec, &bn254_control_id_dec];

    public_inputs.extend(values.iter().map(|&v| Fr::from_str(v).unwrap()));

    println!(
        "{}",
        ark_groth16::Groth16::<Bn254>::verify_proof(&prepared_vk, &ark_proof, &public_inputs)
            .unwrap()
    );
}

fn create_ark_proof(g16_seal: Groth16Seal) -> Proof<Bn254> {
    let ark_bn254_a = ark_bn254::G1Affine::new(
        ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.a().x()),
        ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.a().y()),
    );

    let ark_bn254_c = ark_bn254::G1Affine::new(
        ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.c().x()),
        ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.c().y()),
    );

    let ark_bn254_b = ark_bn254::G2Affine::new(
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.b().x0()),
            ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.b().x1()),
        ),
        ark_bn254::Fq2::new(
            ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.b().y0()),
            ark_bn254::Fq::from_be_bytes_mod_order(g16_seal.b().y1()),
        ),
    );

    Proof::<Bn254> {
        a: ark_bn254_a.into(),
        b: ark_bn254_b.into(),
        c: ark_bn254_c.into(),
    }
}
