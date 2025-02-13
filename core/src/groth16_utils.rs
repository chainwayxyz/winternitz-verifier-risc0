use crate::{
    constants::{
        ASSUMPTIONS, CLAIM_TAG, CONST_27_82, CONST_3_82, INPUT, MODULUS, OUTPUT_TAG, POST_STATE,
        PRE_STATE,
    },
    error::FieldError,
    field::{bigint_to_bytes, bytes_to_bigint, negate_bigint, sqrt_f2, sqrt_fp},
};
use num_bigint::BigUint;
use num_traits::One;
use sha2::{Digest, Sha256};

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

pub fn g1_compress(point: [&[u8; 32]; 2]) -> Vec<u8> {
    let modulus = BigUint::parse_bytes(MODULUS, 10).unwrap();

    let x = BigUint::from_bytes_be(point[0]);
    let y = BigUint::from_bytes_be(point[1]);

    let y_neg = negate_bigint(&y, &modulus);
    let sign: u8 = if y < y_neg { 0x1 } else { 0x0 };

    let compressed = (&x << 1) | BigUint::from(sign);

    bigint_to_bytes(&compressed).to_vec()
}

pub fn g2_compress(point: [[&[u8; 32]; 2]; 2]) -> Result<Vec<u8>, FieldError> {
    let x_real = BigUint::from_bytes_be(point[0][1]);
    let x_imaginary = BigUint::from_bytes_be(point[0][0]);
    let y_real = BigUint::from_bytes_be(point[1][1]);
    let y_img = BigUint::from_bytes_be(point[1][0]);

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

    let d = sqrt_fp(&((m.pow(2) + n.pow(2)) % &modulus), &modulus)?;

    let d_check = (y_real.pow(2) + y_img.pow(2)) % modulus;

    let hint = if d == d_check { 0x0 } else { 0x2 };

    let flag = sign | hint;

    let compressed_x0 = (&x_real << 2) | BigUint::from(flag);
    let compressed_x1 = x_imaginary;

    let mut compressed = Vec::new();
    compressed.extend_from_slice(&bigint_to_bytes(&compressed_x0));
    compressed.extend_from_slice(&bigint_to_bytes(&compressed_x1));
    Ok(compressed)
}

pub fn g2_decompress(compressed: &[u8]) -> Result<[[u8; 32]; 4], FieldError> {
    if compressed.len() != 64 {
        return Err(FieldError::InputLengthError);
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
    let (mut y0, mut y1) = sqrt_f2(y0, y1, hint, &modulus)?;

    if negate_point {
        y1 = negate_bigint(&y1, &modulus);
        y0 = negate_bigint(&y0, &modulus);
    }

    let to_bytes = |v: &BigUint| -> [u8; 32] {
        let bytes = v.to_bytes_be();
        let mut padded = [0u8; 32];
        assert!(bytes.len() <= 32, "BigInt should fit in 32 bytes");
        let start = 32 - bytes.len();
        padded[start..].copy_from_slice(&bytes);
        padded
    };

    Ok([to_bytes(&x0), to_bytes(&x1), to_bytes(&y0), to_bytes(&y1)])
}

pub fn g1_decompress(compressed: &[u8]) -> Result<[[u8; 32]; 2], FieldError> {
    if compressed.len() != 32 {
        return Err(FieldError::InputLengthError);
    }

    let modulus = BigUint::parse_bytes(MODULUS, 10).unwrap();

    let compressed_x = bytes_to_bigint(&compressed.try_into().unwrap());
    let negate_point = (&compressed_x & BigUint::one()) == BigUint::one();
    let x = &compressed_x >> 1;

    let y = sqrt_fp(&((&x * &x * &x + BigUint::from(3u8)) % &modulus), &modulus)?;
    let y = if negate_point {
        negate_bigint(&y, &modulus)
    } else {
        y
    };
    let to_bytes = |v: &BigUint| -> [u8; 32] {
        let bytes = v.to_bytes_be();
        let mut padded = [0u8; 32];

        assert!(bytes.len() <= 32, "BigInt should fit in 32 bytes");
        let start = 32 - bytes.len();
        padded[start..].copy_from_slice(&bytes);

        padded
    };
    Ok([to_bytes(&x), to_bytes(&y)])
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_g1_compress_decompress() {
        let point: [&[u8; 32]; 2] = [
            &[
                37, 249, 107, 214, 225, 232, 168, 217, 53, 174, 70, 189, 137, 24, 233, 140, 18,
                111, 113, 65, 96, 8, 180, 161, 224, 242, 43, 188, 115, 247, 143, 51,
            ],
            &[
                33, 33, 87, 206, 194, 59, 9, 199, 90, 47, 52, 239, 49, 146, 111, 105, 21, 104, 181,
                51, 84, 206, 81, 229, 121, 70, 103, 174, 168, 110, 6, 10,
            ],
        ];

        let compressed = g1_compress(point);
        let decompressed = g1_decompress(&compressed).unwrap();

        let decompressed = [&decompressed[0], &decompressed[1]];

        assert_eq!(point, decompressed);
    }

    #[test]
    fn test_g2_compress_decompress() {
        let point: [[&[u8; 32]; 2]; 2] = [
            [
                &[
                    35, 33, 36, 90, 31, 174, 79, 207, 213, 220, 76, 247, 96, 161, 74, 156, 119, 47,
                    171, 67, 147, 139, 150, 207, 124, 164, 162, 38, 184, 238, 172, 6,
                ],
                &[
                    9, 177, 109, 110, 255, 135, 222, 228, 52, 212, 173, 46, 136, 135, 49, 19, 28,
                    211, 183, 137, 2, 126, 180, 210, 9, 126, 139, 158, 78, 222, 247, 25,
                ],
            ],
            [
                &[
                    9, 73, 235, 56, 193, 140, 207, 136, 131, 23, 78, 223, 205, 26, 64, 23, 43, 92,
                    76, 158, 88, 3, 241, 182, 214, 159, 254, 121, 54, 107, 253, 219,
                ],
                &[
                    9, 215, 151, 118, 28, 116, 190, 162, 13, 28, 241, 30, 226, 185, 110, 108, 7,
                    129, 231, 239, 158, 97, 78, 72, 178, 213, 139, 131, 37, 9, 58, 250,
                ],
            ],
        ];

        let compressed = g2_compress(point).unwrap();
        let decompressed = g2_decompress(&compressed).unwrap();

        let decompressed = [
            [&decompressed[1], &decompressed[0]],
            [&decompressed[3], &decompressed[2]],
        ];

        assert_eq!(point, decompressed);
    }

    #[test]
    fn test_g1_compress_decompress_small_number() {
        let point: [&[u8; 32]; 2] = [
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 2,
            ],
        ];

        let compressed = g1_compress(point);
        let decompressed = g1_decompress(&compressed).unwrap();

        let decompressed = [&decompressed[0], &decompressed[1]];

        assert_eq!(point, decompressed);
    }

    #[test]
    fn test_g2_compress_decompress_small_number() {
        let point: [[&[u8; 32]; 2]; 2] = [
            [
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 12, 14,
                ],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ],
            [
                &[
                    0, 62, 203, 101, 35, 162, 243, 24, 160, 20, 131, 54, 150, 145, 235, 58, 164, 2,
                    111, 102, 79, 22, 7, 54, 110, 147, 87, 81, 199, 125, 94, 94,
                ],
                &[
                    28, 200, 245, 204, 45, 213, 100, 23, 213, 173, 160, 60, 171, 232, 163, 82, 192,
                    85, 210, 127, 250, 141, 200, 16, 202, 178, 24, 189, 84, 134, 168, 45,
                ],
            ],
        ];
        let compressed = g2_compress(point).unwrap();
        let decompressed = g2_decompress(&compressed).unwrap();

        let decompressed = [
            [&decompressed[1], &decompressed[0]],
            [&decompressed[3], &decompressed[2]],
        ];

        assert_eq!(point, decompressed);
    }


    #[test]
    fn test_g1_compress_decompress_error() {
        let point: [&[u8; 32]; 2] = [
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 4,
            ],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 2,
            ],
        ];

        let compressed = g1_compress(point);
        let decompressed = g1_decompress(&compressed).unwrap_err();

        assert_eq!(FieldError::F1SquareRootError, decompressed);

    }


}
