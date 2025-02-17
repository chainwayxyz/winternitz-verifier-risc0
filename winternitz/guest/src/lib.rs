use ark_bn254::{Bn254, Fr};
use ark_ff::BigInt;
use ark_groth16::PreparedVerifyingKey;
use ark_serialize::CanonicalDeserialize;
use hex::ToHex;
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use winternitz_core::winternitz::verify_signature;
use winternitz_core::{
    constants::PREPARED_VK, groth16::Groth16Seal, utils::to_decimal, winternitz::Parameters,
};

// GROTH16 RELATED CONSTANTS
pub static PRE_STATE: [u8; 32] =
    hex_literal::hex!("38e22506dd96d82b369d0dd3ec457089ba2f80c88c0ac37766bd336f172d3dd1");
pub static POST_STATE: [u8; 32] =
    hex_literal::hex!("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2");
pub static INPUT: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static ASSUMPTIONS: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static BN254_CONTROL_ID: [u8; 32] =
    hex_literal::hex!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");
pub static CLAIM_TAG: [u8; 32] =
    hex_literal::hex!("cb1fefcd1f2d9a64975cbbbf6e161e2914434b0cbb9960b84df5d717e86b48af"); // hash of "risc0.ReceiptClaim"
pub static OUTPUT_TAG: [u8; 32] =
    hex_literal::hex!("77eafeb366a78b47747de0d7bb176284085ff5564887009a5be63da32d3559d4"); // hash of "risc0.Output"

pub const A0_BIGINT: BigInt<4> = BigInt::new([3584412468423285388, 5573840904707615506, 0, 0]);
pub const A0_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> = Fr::new(A0_BIGINT);

pub const A1_BIGINT: BigInt<4> = BigInt::new([3118573868620133879, 7567222285189782870, 0, 0]);
pub const A1_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> = Fr::new(A1_BIGINT);

pub const BN_254_CONTROL_ID_BIGINT: BigInt<4> = BigInt::new([
    10066737433256753856,
    15970898588890169697,
    12996428817291790227,
    307492062473808767,
]);
pub const BN_254_CONTROL_ID_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> =
    Fr::new(BN_254_CONTROL_ID_BIGINT);

pub fn create_output_digest(total_work: &[u8; 16]) -> [u8; 32] {
    let total_work_digest: [u8; 32] = Sha256::digest(total_work).into();
    let len_output: [u8; 2] = hex::decode("0200").unwrap().try_into().unwrap();

    let output_pre_digest: [u8; 98] = [
        &OUTPUT_TAG,
        &total_work_digest[..],
        &ASSUMPTIONS[..],
        &len_output[..],
    ]
    .concat()
    .try_into()
    .expect("slice has correct length");

    Sha256::digest(output_pre_digest).into()
}

pub fn create_claim_digest(output_digest: &[u8; 32]) -> [u8; 32] {
    let data: [u8; 8] = [0; 8];

    let claim_len: [u8; 2] = [4, 0];

    let concatenated = [
        &CLAIM_TAG,
        &INPUT,
        &PRE_STATE,
        &POST_STATE,
        output_digest,
        &data[..],
        &claim_len,
    ]
    .concat();

    let mut claim_digest = Sha256::digest(concatenated);
    claim_digest.reverse();

    claim_digest.into()
}
pub struct Groth16 {
    groth16_seal: Groth16Seal,
    total_work: [u8; 16],
}

impl Groth16 {
    pub fn new(groth16_seal: Groth16Seal, total_work: [u8; 16]) -> Groth16 {
        Groth16 {
            groth16_seal,
            total_work,
        }
    }

    pub fn verify(&self) -> bool {
        let ark_proof = self.groth16_seal.into();
        let start = env::cycle_count();
        let prepared_vk: PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> =
            CanonicalDeserialize::deserialize_uncompressed(PREPARED_VK).unwrap();
        let end = env::cycle_count();
        println!("PVK: {}", end - start);
        let start = env::cycle_count();

        let output_digest = create_output_digest(&self.total_work);

        let claim_digest: [u8; 32] = create_claim_digest(&output_digest);

        let claim_digest_hex: String = claim_digest.encode_hex();
        let c0_str = &claim_digest_hex[32..64];
        let c1_str = &claim_digest_hex[0..32];

        let c0_dec = to_decimal(c0_str).unwrap();
        let c1_dec = to_decimal(c1_str).unwrap();

        let c0 = Fr::from_str(&c0_dec).unwrap();
        let c1 = Fr::from_str(&c1_dec).unwrap();

        let public_inputs = vec![A0_ARK, A1_ARK, c0, c1, BN_254_CONTROL_ID_ARK];

        let end = env::cycle_count();
        println!("PPI: {}", end - start);
        ark_groth16::Groth16::<Bn254>::verify_proof(&prepared_vk, &ark_proof, &public_inputs)
            .unwrap()
    }
}

pub fn verify_winternitz_and_groth16(
    pub_key: &Vec<[u8; 20]>,
    signature: &[Vec<u8>],
    message: &[u8],
    params: &Parameters,
) -> bool {
    let start = env::cycle_count();
    if !verify_signature(pub_key, signature, message, params).unwrap() {
        return false;
    }
    let end = env::cycle_count();
    println!("WNV: {}", end - start);
    let compressed_seal: [u8; 128] = message[0..128].try_into().unwrap();
    let total_work: [u8; 16] = message[128..144].try_into().unwrap();
    let seal = match Groth16Seal::from_compressed(&compressed_seal) {
        Ok(seal) => seal,
        Err(_) => return false,
    };

    let groth16_proof = Groth16::new(seal, total_work);
    let start = env::cycle_count();
    let res = groth16_proof.verify();
    let end = env::cycle_count();
    println!("G16V: {}", end - start);
    println!("{}", res);
    res
}
