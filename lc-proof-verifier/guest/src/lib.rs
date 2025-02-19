use risc0_zkvm::guest::env;
use alloy_primitives::U256;
use jmt::{proof::SparseMerkleProof, KeyHash};
use alloy_rpc_types::EIP1186StorageProof;
use alloy_primitives::Bytes;

const LC_IMAGE_ID: [u8; 32] = hex_literal::hex!("f9b82dad0590a31c4d58345a8d9f3865857d00b50ada1cd0234ff9bb781e36b0");
const ADDRESS: [u8; 20] = hex_literal::hex!("3100000000000000000000000000000000000002");

pub fn lc_proof_verifier() -> bool {
    let journal: Vec<u8>  = env::read();
    let storage_proof: String = env::read();
    let storage_proof: EIP1186StorageProof = serde_json::from_str(&storage_proof).unwrap();

    env::verify(
        LC_IMAGE_ID,
        &journal
    ).unwrap();

    if journal.len() < 32 {
        return false;
    }

    let state_root: [u8; 32] = journal[0..32].try_into().unwrap();

    println!("storage value {:?}", storage_proof.value);

    storage_verify(storage_proof, state_root);

    println!("Proof verification done");

    true

}

fn storage_verify(storage_proof: EIP1186StorageProof, expected_root_hash: [u8; 32]) {
    let storage_key = [
        b"Evm/s/",
        ADDRESS.as_slice(),
        &[32],
        U256::from_le_slice(&storage_proof.key.as_b256().0)
            .to_be_bytes::<32>()
            .as_slice(),
    ]
    .concat();
    let key_hash = KeyHash::with::<sha2::Sha256>(storage_key.clone());

    let proved_value = if storage_proof.proof[1] == Bytes::from("y") {
        // Storage value exists and it's serialized form is:
        let bytes = [&[32], storage_proof.value.to_be_bytes::<32>().as_slice()].concat();
        Some(bytes)
    } else {
        // Storage value does not exist
        None
    };

    let storage_proof: SparseMerkleProof<sha2::Sha256> =
        borsh::from_slice(&storage_proof.proof[0]).unwrap();

    storage_proof
        .verify(jmt::RootHash(expected_root_hash), key_hash, proved_value)
        .expect("Account storage proof must be valid");
}
    