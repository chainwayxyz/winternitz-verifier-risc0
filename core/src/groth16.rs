use crate::constants::{A0_ARK, A1_ARK, BN_254_CONTROL_ID_ARK, PREPARED_VK};
use crate::error::FieldError;
use crate::groth16_utils::{
    create_claim_digest, create_output_digest, g1_compress, g1_decompress, g2_compress,
    g2_decompress,
};
use crate::utils::to_decimal;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{PreparedVerifyingKey, Proof};
use ark_serialize::CanonicalDeserialize;
use hex::ToHex;
use risc0_zkvm::guest::env;

use std::str::FromStr;
#[derive(Copy, Clone)]
pub struct G1 {
    x: [u8; 32],
    y: [u8; 32],
}

impl G1 {
    pub fn new_from_vec(point: &[[u8; 32]]) -> G1 {
        assert!(point.len() == 2, "point must contain exactly two elements");
        G1 {
            x: point[0],
            y: point[1],
        }
    }
    pub fn new_from_bytes(x: &[u8; 32], y: &[u8; 32]) -> G1 {
        G1 { x: *x, y: *y }
    }

    pub fn x(&self) -> &[u8; 32] {
        &self.x
    }

    pub fn y(&self) -> &[u8; 32] {
        &self.y
    }
}

#[derive(Copy, Clone)]
pub struct G2 {
    // 0 -> Real, 1 -> Imaginary
    x0: [u8; 32],
    x1: [u8; 32],
    y0: [u8; 32],
    y1: [u8; 32],
}

impl G2 {
    pub fn new_from_vec(point: &[[u8; 32]; 4]) -> G2 {
        assert!(point.len() == 4, "point must contain exactly four elements");
        G2 {
            x0: point[0],
            x1: point[1],
            y0: point[2],
            y1: point[3],
        }
    }
    pub fn new_from_bytes(x0: &[u8; 32], x1: &[u8; 32], y0: &[u8; 32], y1: &[u8; 32]) -> G2 {
        G2 {
            x0: *x0,
            x1: *x1,
            y0: *y0,
            y1: *y1,
        }
    }

    pub fn x0(&self) -> &[u8; 32] {
        &self.x0
    }

    pub fn x1(&self) -> &[u8; 32] {
        &self.x1
    }

    pub fn y0(&self) -> &[u8; 32] {
        &self.y0
    }

    pub fn y1(&self) -> &[u8; 32] {
        &self.y1
    }
}

#[derive(Copy, Clone)]
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
        let a = G1::new_from_bytes(
            seal[0..32].try_into().expect("slice has correct length"),
            seal[32..64].try_into().expect("slice has correct length"),
        );
        let b = G2::new_from_bytes(
            seal[64..96].try_into().expect("slice has correct length"),
            seal[96..128].try_into().expect("slice has correct length"),
            seal[128..160].try_into().expect("slice has correct length"),
            seal[160..192].try_into().expect("slice has correct length"),
        );
        let c = G1::new_from_bytes(
            seal[192..224].try_into().expect("slice has correct length"),
            seal[224..256].try_into().expect("slice has correct length"),
        );
        Groth16Seal::new(a, b, c)
    }
    // first decompress than create a new Groth16Seal
    pub fn from_compressed(compressed: &[u8; 128]) -> Result<Groth16Seal, FieldError> {
        let a = G1::new_from_vec(&g1_decompress(&compressed[0..32])?);
        let b = G2::new_from_vec(&g2_decompress(&compressed[32..96])?);
        let c = G1::new_from_vec(&g1_decompress(&compressed[96..128])?);
        Ok(Groth16Seal::new(a, b, c))
    }

    pub fn to_compressed(&self) -> Result<[u8; 128], FieldError> {
        let a = g1_compress([&self.a.x, &self.a.y]);
        let b = g2_compress([[&self.b.x0, &self.b.x1], [&self.b.y0, &self.b.y1]])?;
        let c = g1_compress([&self.c.x, &self.c.y]);

        let mut compressed = [0u8; 128];
        compressed[0..32].copy_from_slice(&a);
        compressed[32..96].copy_from_slice(&b);
        compressed[96..128].copy_from_slice(&c);

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
