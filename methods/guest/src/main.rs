use bitcoin::Witness;
use risc0_zkvm::guest::env;
use winternitz_core::{hash160, verify_signature, Parameters, PublicKey};

fn main() {
    let pub_key: PublicKey = env::read();
    let params: Parameters = env::read();
    let signature: Witness = env::read();
    let _res = verify_signature(&pub_key, &signature, &params);
    let mut pub_key_concat: Vec<u8> = vec![0; pub_key.len() * 20];
    for (i, pubkey) in pub_key.iter().enumerate() {
        pub_key_concat[i * 20..(i + 1) * 20].copy_from_slice(pubkey);
    }
    env::commit(&hash160(&pub_key_concat));
}
