use crate::constants::{A0_ARK, A1_ARK, BN_254_CONTROL_ID_ARK, PREPARED_VK};
use crate::groth16_utils::{
    create_claim_digest, create_output_digest
};
use crate::utils::to_decimal;
use ark_bn254::{Bn254, Fr};
use ark_ff::{PrimeField, Field};
use ark_groth16::{PreparedVerifyingKey, Proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use hex::ToHex;
use risc0_zkvm::guest::env;

use std::str::FromStr;
type G1 = ark_bn254::G1Affine;
type G2 = ark_bn254::G2Affine;

#[derive(Copy, Clone, Debug)]
pub struct Groth16Seal {
    a: G1,
    b: G2,
    c: G1,
}

impl Groth16Seal {
    pub fn new(a: G1, b: G2, c: G1) -> Groth16Seal {
        Groth16Seal { a, b, c }
    }

    pub fn from_seal(seal: &[u8; 256]) -> Groth16Seal {
        let a = G1::new(
            ark_bn254::Fq::from_be_bytes_mod_order(&seal[0..32]),
            ark_bn254::Fq::from_be_bytes_mod_order(&seal[32..64]),
        );

        let b = G2::new(
            ark_bn254::Fq2::from_base_prime_field_elems([
                ark_bn254::Fq::from_be_bytes_mod_order(&seal[96..128]),
                ark_bn254::Fq::from_be_bytes_mod_order(&seal[64..96]),
            ])
            .unwrap(),
            ark_bn254::Fq2::from_base_prime_field_elems([
                ark_bn254::Fq::from_be_bytes_mod_order(&seal[160..192]),
                ark_bn254::Fq::from_be_bytes_mod_order(&seal[128..160]),
            ])
            .unwrap(),
        );

        let c = G1::new(
            ark_bn254::Fq::from_be_bytes_mod_order(&seal[192..224]),
            ark_bn254::Fq::from_be_bytes_mod_order(&seal[224..256]),
        );

        Groth16Seal::new(a, b, c)
    }

    // first decompress than create a new Groth16Seal
    pub fn from_compressed(compressed: &[u8; 128]) -> Result<Groth16Seal, SerializationError> {
        let a_compressed = &compressed[0..32];
        let b_compressed = &compressed[32..96];
        let c_compressed = &compressed[96..128];
        let a = ark_bn254::G1Affine::deserialize_compressed(a_compressed)?;
        let b = ark_bn254::G2Affine::deserialize_compressed(b_compressed)?;
        let c = ark_bn254::G1Affine::deserialize_compressed(c_compressed)?;

        Ok(Groth16Seal::new(a, b, c))
    }

    pub fn to_compressed(&self) -> Result<[u8; 128], SerializationError> {
        let mut a_compressed = [0u8; 32];
        let mut b_compressed = [0u8; 64];
        let mut c_compressed = [0u8; 32];
        ark_bn254::G1Affine::serialize_with_mode(&self.a, &mut a_compressed[..], Compress::Yes)
            .unwrap();
        ark_bn254::G2Affine::serialize_with_mode(&self.b, &mut b_compressed[..], Compress::Yes)
            .unwrap();
        ark_bn254::G1Affine::serialize_with_mode(&self.c, &mut c_compressed[..], Compress::Yes)
            .unwrap();

        let mut compressed = [0u8; 128];
        compressed[0..32].copy_from_slice(&a_compressed);
        compressed[32..96].copy_from_slice(&b_compressed);
        compressed[96..128].copy_from_slice(&c_compressed);

        Ok(compressed)
    }

    pub fn a(&self) -> &G1 {
        &self.a
    }

    pub fn b(&self) -> &G2 {
        &self.b
    }

    pub fn c(&self) -> &G1 {
        &self.c
    }
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

impl From<Groth16Seal> for Proof<Bn254> {
    fn from(g16_seal: Groth16Seal) -> Self {
        Proof::<Bn254> {
            a: g16_seal.a,
            b: g16_seal.b,
            c: g16_seal.c,
        }
    }
}
