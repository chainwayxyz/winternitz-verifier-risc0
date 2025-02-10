use bitcoin::Witness;
use risc0_zkvm::guest::env;
use winternitz_core::{hash160, verify_signature, Parameters, PublicKey};

fn main() {
    let pub_key: PublicKey = env::read();
    let params: Parameters = env::read();
    let signature: Vec<Vec<u8>> = env::read();
    let message: Vec<u8> = env::read();
    let total_work: [u8; 16]  = env::read();
    let image_id: [u32; 8]  = env::read();
    println!("verification started");
    println!("{:?}", verify_signature(&pub_key, &signature, message.clone(), &params));
    println!("verified");
    println!("{:?}", total_work);
    env::verify(image_id, &total_work).expect("Could not verified.");
    let mut pub_key_concat: Vec<u8> = vec![0; pub_key.len() * 20];
    for (i, pubkey) in pub_key.iter().enumerate() {
        pub_key_concat[i * 20..(i + 1) * 20].copy_from_slice(pubkey);
    }
    env::commit(&hash160(&pub_key_concat));
}
