use ark_bn254::g1;
use borsh::{self, BorshDeserialize};
use header_chain::header_chain::{
    BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader, HeaderChainCircuitInput,
    HeaderChainPrevProofType,
};
use headerchain::{HEADERCHAIN_ELF, HEADERCHAIN_ID};
use host::{compress_g1, compress_g2};
use rand::rngs::SmallRng;
use rand::Rng;
use rand::SeedableRng;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::{any::Any, fs};
use winternitz::{WINTERNITZ_ELF, WINTERNITZ_ID};
use winternitz_core::{generate_public_key, sign_digits, Parameters};
use work_only::{WORK_ONLY_ELF, WORK_ONLY_ID};

const HEADERS: &[u8] = include_bytes!("regtest-headers.bin");

fn main() {
    let headerchain_proof: Receipt = generate_header_chain_proof();
    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(&headerchain_proof.journal.bytes[..]).unwrap();
    println!("{:?}", block_header_circuit_output.method_id);
    let work_only_groth16_proof_receipt = call_work_only(
        headerchain_proof,
        &block_header_circuit_output,
        block_header_circuit_output.method_id,
    );
    let work_only_groth16_proof_serialized =
        borsh::to_vec(&work_only_groth16_proof_receipt).unwrap();
    println!(
        "GROTH16 PROOF WITH WORK: {:#?}",
        work_only_groth16_proof_receipt
    );
    let mut work_only_groth16_proof_serialized_u32: Vec<u32> =
        Vec::with_capacity(work_only_groth16_proof_serialized.len());
    let g16_proof = work_only_groth16_proof_receipt.inner.groth16().unwrap();
    println!("GROTH16 PROOF: {:#?}", g16_proof);
    let seal_vec = g16_proof.seal;
    let g16_ark = ark_groth16::Proof::from(seal_vec);
    let a_compressed = compress_g1(g16_ark.a);
    let b_compressed = compress_g2(g16_ark.b);
    let c_compressed = compress_g1(g16_ark.c);
    let compressed_proof = borsh::to_vec(&(a_compressed, b_compressed, c_compressed)).unwrap();

    let commited_total_work: [u8; 16] = work_only_groth16_proof_receipt.journal.decode().unwrap();
    println!("{:?}", commited_total_work);
    for (_, num) in work_only_groth16_proof_serialized.iter().enumerate() {
        work_only_groth16_proof_serialized_u32.push(*num as u32);
    }

    println!(
        "len of seal {:?}",
        work_only_groth16_proof_receipt.seal_size()
    );
    println!(
        "len of proof: {:?}",
        work_only_groth16_proof_serialized_u32.len()
    );
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    let n0 = work_only_groth16_proof_serialized_u32.len();
    let log_d = 8;
    let params = Parameters::new(n0.try_into().unwrap(), log_d);
    let input: u64 = 1;
    let mut rng = SmallRng::seed_from_u64(input);
    let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);
    let signature = sign_digits(&params, &secret_key, work_only_groth16_proof_serialized_u32);
    let env = ExecutorEnv::builder()
        .add_assumption(work_only_groth16_proof_receipt)
        .write(&pub_key)
        .unwrap()
        .write(&params)
        .unwrap()
        .write(&signature)
        .unwrap()
        .write(&commited_total_work)
        .unwrap()
        .write(&WORK_ONLY_ID)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let prove_info = prover.prove(env, WINTERNITZ_ELF).unwrap();
    println!("Proof generated!");
    let receipt = prove_info.receipt;
    println!("Receipt: {:#?}", receipt);

    println!("Output extracted! {:?}", receipt.inner.type_id());
    receipt.verify(WINTERNITZ_ID).unwrap();
}

fn call_work_only(
    receipt: Receipt,
    block_header_circuit_output: &BlockHeaderCircuitOutput,
    image_id: [u32; 8],
) -> Receipt {
    let env = ExecutorEnv::builder()
        .add_assumption(receipt)
        .write(&block_header_circuit_output)
        .unwrap()
        .write(&image_id)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let receipt = prover
        .prove_with_opts(env, WORK_ONLY_ELF, &ProverOpts::groth16())
        .unwrap()
        .receipt;
    return receipt;
}

fn generate_header_chain_proof() -> Receipt {
    let header_chain_guest_id: [u32; 8] = compute_image_id(HEADERCHAIN_ELF)
        .unwrap()
        .as_words()
        .try_into()
        .unwrap();

    println!("Header Chain Guest ID: {:?}", header_chain_guest_id);
    println!("Header Chain ID: {:?}", HEADERCHAIN_ID);
    let batch_size: usize = 3;

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

    return receipt;
}
