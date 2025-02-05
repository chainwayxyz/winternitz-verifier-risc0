use winternitz::{
    WINTERNITZ_ELF, WINTERNITZ_ID
};
use headerchain::{HEADERCHAIN_ELF, HEADERCHAIN_ID};
use rand::Rng;
use risc0_zkvm::{ ExecutorEnv, ProverOpts, default_prover, compute_image_id };
use rand::rngs::SmallRng;
use rand::SeedableRng;
use winternitz_core::{Parameters, sign_digits, generate_public_key};
use header_chain::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType};
use std::fs;
use borsh::BorshDeserialize;

const HEADERS: &[u8] = include_bytes!("regtest-headers.bin");

fn main() {
    generate_header_chain_proof();
    
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let headers = HEADERS
    .chunks(80)
    .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
    .collect::<Vec<CircuitBlockHeader>>();

    let n0 = 1;
    let log_d = 4;
    let params = Parameters::new(n0, log_d);

    let input: u64 = 1;

    let mut rng = SmallRng::seed_from_u64(input);

    let message: Vec<u32> = (0..n0).map(|_| rng.gen::<u32>() % log_d ).collect();

    let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);

    let signature = sign_digits(&params, &secret_key, message);


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
    println!("Receipt extracted! {:?}", receipt);

    let _output: u32 = receipt.journal.decode().expect("Failed to decode journal");
    receipt
        .verify(WINTERNITZ_ID)
        .unwrap();
}



fn generate_header_chain_proof(){
    let output_file_path = "host/src/output/receipt.bin";
    let header_chain_guest_id: [u32; 8] = compute_image_id(HEADERCHAIN_ELF)
    .unwrap()
    .as_words()
    .try_into()
    .unwrap();

    println!("Header Chain Guest ID: {:?}", header_chain_guest_id);
    println!("Header Chain ID: {:?}", HEADERCHAIN_ID);

    let batch_size: usize = 20;

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
    fs::write(output_file_path, &receipt_bytes).expect("Failed to write receipt to output file");

}