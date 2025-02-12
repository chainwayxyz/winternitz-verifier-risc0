mod constants;
pub mod groth16;
pub mod utils;
pub mod winternitz;
pub mod field;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Proof};
use ark_std::vec::Vec;
use constants::*;
use groth16::Groth16Seal;
use hex::ToHex;
use num_bigint::BigUint;
use num_traits::Num;
use risc0_zkvm::Groth16ReceiptVerifierParameters;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::str::FromStr;
use winternitz::{Parameters, verify_signature};

/// Verifies a total work proof using
///
/// # Parameters
/// - ...
pub fn verify_winternitz_and_groth16(
    pub_key: &Vec<[u8; 20]>,
    signature: &[Vec<u8>],
    message: &[u8],
    params: &Parameters,
) {
    assert_eq!(message.len(), 144, "Message length mismatch");

    // winternitz verification
    if !verify_signature(pub_key, signature, message, params).unwrap() {
        panic!("Verification failed");
    }

    let compressed_seal: [u8; 128] = message[0..128].try_into().unwrap();
    let total_work: [u8; 16] = message[128..144].try_into().unwrap();

    let seal = groth16::Groth16Seal::from_compressed(&compressed_seal).unwrap();

    let ark_proof = seal.into();

    let vk: ark_groth16::VerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> = create_verifying_key();
    let prepared_vk: ark_groth16::PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> =
        prepare_verifying_key(&vk);

    let total_work_digest: [u8; 32] = Sha256::digest(total_work).into();
    let len_output: [u8; 2] = hex::decode("0200").unwrap().try_into().unwrap();
    let mut output_pre_digest: [u8; 98] = [0; 98];

    let concatenated_output = [
        &OUTPUT_TAG,
        &total_work_digest[..],
        &ASSUMPTIONS[..],
        &len_output[..],
    ]
    .concat();

    output_pre_digest.copy_from_slice(&concatenated_output);

    let output_digest = Sha256::digest(output_pre_digest);

    let mut claim_pre_digest: [u8; 170] = [0; 170];

    let data: [u8; 8] = [0; 8];

    let claim_len: [u8; 2] = [4, 0];

    let concatenated = [
        &CLAIM_TAG[..],
        &INPUT[..],
        &PRE_STATE[..],
        &POST_STATE[..],
        &output_digest[..],
        &data[..],
        &claim_len[..],
    ]
    .concat();

    claim_pre_digest.copy_from_slice(&concatenated);

    let mut claim_digest = Sha256::digest(claim_pre_digest);
    claim_digest.reverse();

    let claim_digest_hex: String = claim_digest.encode_hex();
    let c0_str = &claim_digest_hex[0..32];
    let c1_str = &claim_digest_hex[32..64];

    let c0_dec = to_decimal(c0_str).unwrap();
    let c1_dec = to_decimal(c1_str).unwrap();

    let groth16_receipt_verifier_params = Groth16ReceiptVerifierParameters::default();

    let groth16_control_root = groth16_receipt_verifier_params.control_root;
    let mut groth16_control_root_bytes: [u8; 32] =
        groth16_control_root.as_bytes().try_into().unwrap();
    groth16_control_root_bytes.reverse();

    let groth16_control_root_bytes: String = groth16_control_root_bytes.encode_hex();
    let a1_str = &groth16_control_root_bytes[0..32];
    let a0_str = &groth16_control_root_bytes[32..64];

    let a1_dec = to_decimal(a1_str).unwrap();
    let a0_dec = to_decimal(a0_str).unwrap();

    let mut bn254_control_id_bytes: [u8; 32] = BN254_CONTROL_ID;
    bn254_control_id_bytes.reverse();

    let bn254_control_id_hex: String = bn254_control_id_bytes.encode_hex();

    let bn254_control_id_dec = to_decimal(&bn254_control_id_hex).unwrap();

    let values = [&a0_dec, &a1_dec, &c1_dec, &c0_dec, &bn254_control_id_dec];

    let public_inputs = values
        .iter()
        .map(|&v| Fr::from_str(v).unwrap())
        .collect::<Vec<_>>();

    println!(
        "{}",
        ark_groth16::Groth16::<Bn254>::verify_proof(&prepared_vk, &ark_proof, &public_inputs)
            .unwrap()
    );
}

impl From<Groth16Seal> for Proof<Bn254> {
    fn from(g16_seal: Groth16Seal) -> Self {
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
            a: ark_bn254_a,
            b: ark_bn254_b,
            c: ark_bn254_c,
        }
    }
}

fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}