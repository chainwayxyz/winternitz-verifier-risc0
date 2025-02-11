use num_bigint::BigUint;
use crate::constants::{CONST_27_82, CONST_3_82, MODULUS};
use crate::utils::{bigint_to_bytes, negate_bigint, sqrt_fp};
struct Groth16 {}

#[derive(Copy, Clone)]
struct G1 {
    x: [u8; 32],
    y: [u8; 32],
}

impl G1 {
    pub fn new_from_vec(point: &[&[u8; 32]]) -> G1 {
        assert!(point.len() == 2, "point must contain exactly two elements");
        G1 {
            x: *point[0],
            y: *point[1],
        }
    }
    pub fn new_from_bytes(x: &[u8; 32], y: &[u8; 32]) -> G1 {
        G1 {
            x: *x,
            y: *y,
        }
    }
}

#[derive(Copy, Clone)]
struct G2 {
    // 0 -> Real, 1 -> Imaginary
    x0: [u8; 32], 
    x1: [u8; 32], 
    y0: [u8; 32],
    y1: [u8; 32],
}

impl G2 {
    pub fn new_from_vec(point: &[&[u8; 32]]) -> G2 {
        assert!(point.len() == 4, "point must contain exactly four elements");
        G2 {
            x0: *point[0],
            x1: *point[1],
            y0: *point[2],
            y1: *point[3],
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
}

#[derive(Copy, Clone)]
pub struct Groth16Seal {
    a: G1,
    b: G2,
    c: G1,
}

impl Groth16Seal {
    pub fn new(a: G1, b: G2, c: G1) -> Groth16Seal {
        Groth16Seal {
            a: a,
            b: b,
            c: c,
        }
    }

    pub fn from_seal(seal: &[u8; 256]) -> Groth16Seal {
        let a = G1::new_from_bytes(
            seal[0..32].try_into().expect("slice with incorrect length"),
            seal[32..64].try_into().expect("slice with incorrect length"),
        );
        let b = G2::new_from_bytes(
            seal[64..96].try_into().expect("slice with incorrect length"),
            seal[96..128].try_into().expect("slice with incorrect length"),
            seal[128..160].try_into().expect("slice with incorrect length"),
            seal[160..192].try_into().expect("slice with incorrect length"),
        );
        let c = G1::new_from_bytes(
            seal[192..224].try_into().expect("slice with incorrect length"),
            seal[224..256].try_into().expect("slice with incorrect length"),
        );
        Groth16Seal::new(a, b, c)

    }

    pub fn get_compressed(&self) -> [u8; 128] {
        let a = g1_compress(vec![self.a.x.to_vec(), self.a.y.to_vec()]);
        let b = g2_compress(vec![vec![self.b.x0.to_vec(), self.b.x1.to_vec()], vec![self.b.y0.to_vec(), self.b.y1.to_vec()]]);
        let c = g1_compress(vec![self.c.x.to_vec(), self.c.y.to_vec()]);

        let mut compressed = [0u8; 128];
        compressed[0..32].copy_from_slice(&a);
        compressed[32..96].copy_from_slice(&b);
        compressed[96..128].copy_from_slice(&c);

        compressed
        
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