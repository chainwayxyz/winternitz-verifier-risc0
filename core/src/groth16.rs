use crate::constants::{CONST_27_82, CONST_3_82, MODULUS};
use crate::utils::{bigint_to_bytes, bytes_to_bigint, negate_bigint, sqrt_f2, sqrt_fp};
use num_bigint::BigUint;
use num_traits::One;

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
        Groth16Seal { a: a, b: b, c: c }
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
    pub fn from_compressed(compressed: &[u8; 128]) -> Option<Groth16Seal> {
        let a = G1::new_from_vec(&g1_decompress(&compressed[0..32])?);
        let b = G2::new_from_vec(&g2_decompress(&compressed[32..96])?);
        let c = G1::new_from_vec(&g1_decompress(&compressed[96..128])?);
        Some(Groth16Seal::new(a, b, c))
    }

    pub fn to_compressed(&self) -> [u8; 128] {
        let a = g1_compress(vec![self.a.x.to_vec(), self.a.y.to_vec()]);
        let b = g2_compress(vec![
            vec![self.b.x0.to_vec(), self.b.x1.to_vec()],
            vec![self.b.y0.to_vec(), self.b.y1.to_vec()],
        ]);
        let c = g1_compress(vec![self.c.x.to_vec(), self.c.y.to_vec()]);

        let mut compressed = [0u8; 128];
        compressed[0..32].copy_from_slice(&a);
        compressed[32..96].copy_from_slice(&b);
        compressed[96..128].copy_from_slice(&c);

        compressed
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

pub fn g2_compress(point: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
    let x_real = BigUint::from_bytes_be(&point[0][1]);
    let x_imaginary = BigUint::from_bytes_be(&point[0][0]);
    let y_real = BigUint::from_bytes_be(&point[1][1]);
    let y_img = BigUint::from_bytes_be(&point[1][0]);

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

pub fn g2_decompress(compressed: &[u8]) -> Option<[[u8; 32]; 4]> {
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
    let (mut y0, mut y1) = sqrt_f2(y0, y1, hint, &modulus);

    if negate_point {
        y1 = negate_bigint(&y1, &modulus);
        y0 = negate_bigint(&y0, &modulus);
    }

    let to_bytes = |v: &BigUint| -> [u8; 32] {
        v.to_bytes_be()
            .try_into()
            .expect("BigInt should fit in 32 bytes")
    };

    Some([to_bytes(&x0), to_bytes(&x1), to_bytes(&y0), to_bytes(&y1)])
}

pub fn g1_decompress(compressed: &[u8]) -> Option<[[u8; 32]; 2]> {
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
    let to_bytes = |v: &BigUint| -> [u8; 32] {
        v.to_bytes_be()
            .try_into()
            .expect("BigInt should fit in 32 bytes")
    };
    Some([to_bytes(&x), to_bytes(&y)])
}
