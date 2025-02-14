pub mod constants;
pub mod error;
pub mod field;
pub mod groth16;
pub mod groth16_utils;
pub mod utils;
pub mod winternitz;
use ark_std::vec::Vec;
use groth16::{Groth16, Groth16Seal};
use risc0_zkvm::guest::env;
use std::convert::TryInto;
use winternitz::{verify_signature, Parameters};

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
