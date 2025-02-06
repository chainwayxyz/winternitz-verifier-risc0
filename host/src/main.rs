use winternitz::{
    WINTERNITZ_ELF, WINTERNITZ_ID
};
use headerchain::{HEADERCHAIN_ELF, HEADERCHAIN_ID};
use rand::Rng;
use risc0_zkvm::{ compute_image_id, default_prover, ExecutorEnv, ProverOpts, ReceiptClaim, SuccinctReceipt };
use rand::rngs::SmallRng;
use rand::SeedableRng;
use winternitz_core::{Parameters, sign_digits, generate_public_key};
use header_chain::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType};
use std::{any::Any, fs};
use borsh::BorshDeserialize;

const HEADERS: &[u8] = include_bytes!("regtest-headers.bin");

fn main() {
    let headerchain_proof: &[u8] = &generate_header_chain_proof();
    println!("len of header chain proof: {:?}", headerchain_proof.len());
    println!("First byte of header chain proof: {:?}", headerchain_proof[0]);
    let mut header_chain_proof_u32: Vec<u32> = Vec::with_capacity(headerchain_proof.len());
    for i in 0..headerchain_proof.len() {
        header_chain_proof_u32.push(headerchain_proof[i] as u32);
    }
    println!("Header Chain Proof: {:?}", header_chain_proof_u32[0]);
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let n0 = 1;
    let log_d = 4;
    let params = Parameters::new(n0, log_d);

    let input: u64 = 1;

    let mut rng = SmallRng::seed_from_u64(input);

    let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);
    println!("sign start");
    let signature = sign_digits(&params, &secret_key, header_chain_proof_u32);
    println!("sign end");

    let env = ExecutorEnv::builder()
        .write(&pub_key)
        .unwrap()
        .write(&params)
        .unwrap()
        .write(&signature)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let prove_info = prover
        .prove(env, WINTERNITZ_ELF)
        .unwrap();
    println!("Proof generated!" );
    
    let receipt = prove_info.receipt;
    println!("Output extracted! {:?}", receipt.inner.type_id());
    receipt
        .verify(WINTERNITZ_ID)
        .unwrap();
}



fn generate_header_chain_proof() -> Vec<u8> {
    let header_chain_guest_id: [u32; 8] = compute_image_id(HEADERCHAIN_ELF)
    .unwrap()
    .as_words()
    .try_into()
    .unwrap();

    println!("Header Chain Guest ID: {:?}", header_chain_guest_id);
    println!("Header Chain ID: {:?}", HEADERCHAIN_ID);

    let batch_size: usize = 1;

    let headers = HEADERS
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();

    
    let start = 0;
    let prev_proof = HeaderChainPrevProofType::GenesisBlock;

    let input = HeaderChainCircuitInput {
        method_id: header_chain_guest_id,
        prev_proof,
        block_headers: headers[start..start + batch_size].to_vec(),
    };

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&input).unwrap());
    let env = env.build().unwrap();

    let prover = default_prover();

    let receipt = prover
    .prove_with_opts(env, HEADERCHAIN_ELF, &ProverOpts::succinct())
    .unwrap()
    .receipt;

    let receipt_bytes = borsh::to_vec(&receipt).unwrap();

    return receipt_bytes;

}