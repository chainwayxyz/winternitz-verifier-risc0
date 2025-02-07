use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{BigInteger256, Field, PrimeField};
use ark_std::ops::Neg;

#[derive(Clone, Debug)]
pub struct CompressedG1 {
    pub x: Vec<u8>,
    pub y_parity: bool,
}

#[derive(Clone, Debug)]
pub struct CompressedG2 {
    pub x_0: Vec<u8>,
    pub x_1: Vec<u8>,
    pub y_parity: bool,
}

#[derive(Clone, Debug)]
pub struct CompressedProof {
    pub a: CompressedG1,
    pub b: CompressedG2,
    pub c: CompressedG1,
}

/// Compresses a G1 element by storing only x and a parity bit for y.
pub fn compress_g1(point: G1Affine) -> CompressedG1 {
    let x_bytes = point.x.into_repr().to_bytes_le();
    let y_parity = point.y.is_odd();

    CompressedG1 {
        x: x_bytes,
        y_parity,
    }
}

/// Compresses a G2 element by storing only x-coordinates and a parity bit for y.
pub fn compress_g2(point: G2Affine) -> CompressedG2 {
    let x_0_bytes = point.x.c0.into_repr().to_bytes_le();
    let x_1_bytes = point.x.c1.into_repr().to_bytes_le();
    let y_parity = point.y.c0.is_odd(); // Using c0's parity bit

    CompressedG2 {
        x_0: x_0_bytes,
        x_1: x_1_bytes,
        y_parity,
    }
}

/// Decompresses a G1 element by reconstructing y from x.
pub fn decompress_g1(compressed_g1: CompressedG1) -> Option<G1Affine> {
    let x = Fq::from_le_bytes_mod_order(&compressed_g1.x);

    // Calculate x³ + b
    let right_side = (x * x * x) + Bn254::COEFF_B;

    // Try to find square root
    right_side.sqrt().map(|mut y| {
        // Ensure correct parity
        if y.is_odd() != compressed_g1.y_parity {
            y = y.neg();
        }

        G1Affine::new(x, y)
    })
}

/// Decompresses a G2 element by reconstructing y from (x_0, x_1).
pub fn decompress_g2(compressed_g2: CompressedG2) -> Option<G2Affine> {
    let x_0 = Fq::from_le_bytes_mod_order(&compressed_g2.x_0);
    let x_1 = Fq::from_le_bytes_mod_order(&compressed_g2.x_1);
    let x = Fq2::new(x_0, x_1);

    // Calculate x³ + b where b is in Fq2
    let b_g2 = Fq2::new(Bn254::COEFF_B, Fq::zero());
    let right_side = (x * x * x) + b_g2;

    // Try to find square root
    right_side.sqrt().map(|mut y| {
        // Ensure correct parity of c0
        if y.c0.is_odd() != compressed_g2.y_parity {
            y = y.neg();
        }

        G2Affine::new(x, y)
    })
}
