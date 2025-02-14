use borsh::{self, BorshDeserialize};
use header_chain::header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, ExecutorEnv, ProverOpts, Receipt,
};
use std::convert::TryInto;
use winternitz_core::groth16::Groth16Seal;
use winternitz_core::winternitz::{generate_public_key, sign_digits, Parameters};

const HEADERS: &[u8] = include_bytes!("regtest-headers.bin");
const HEADERCHAIN_ELF: &[u8] = include_bytes!("../../elfs/regtest-headerchain-guest");
const WINTERNITZ_ELF: &[u8] = include_bytes!("../../elfs/regtest-winternitz-guest");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../elfs/regtest-work-only-guest");


fn main() {
    let headerchain_id: [u32; 8] = compute_image_id(HEADERCHAIN_ELF).unwrap().into();
    let winternitz_id: [u32; 8] = compute_image_id(WINTERNITZ_ELF).unwrap().into();
    let work_only_id: [u32; 8] = compute_image_id(WORK_ONLY_ELF).unwrap().into();

    println!("HEADERCHAIN_ID: {:?}", headerchain_id);
    println!("WINTERNITZ_ID: {:?}", winternitz_id);
    println!("WORK_ONLY_ID: {:?}", work_only_id);

    let headerchain_proof: Receipt = generate_header_chain_proof();
    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(&headerchain_proof.journal.bytes[..]).unwrap();
    let work_only_groth16_proof_receipt: Receipt = call_work_only(
        headerchain_proof,
        &block_header_circuit_output,
        block_header_circuit_output.method_id,
    );

    let g16_proof_receipt: &risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> =
        work_only_groth16_proof_receipt.inner.groth16().unwrap();

    println!("g16_proof_receipt: {:?}", g16_proof_receipt);

    let seal = Groth16Seal::from_seal(g16_proof_receipt.seal.as_slice().try_into().unwrap());

    let compressed_proof = seal.to_compressed().unwrap();

    let commited_total_work: [u8; 16] = work_only_groth16_proof_receipt
        .journal
        .bytes
        .try_into()
        .unwrap();

    let mut compressed_proof_and_total_work: Vec<u8> = vec![0; 144];
    compressed_proof_and_total_work[0..128].copy_from_slice(&compressed_proof);
    compressed_proof_and_total_work[128..144].copy_from_slice(&commited_total_work);

    let n0 = compressed_proof_and_total_work.len();
    let log_d = 8;
    let params = Parameters::new(n0.try_into().unwrap(), log_d);
    let input: u64 = 1;
    let mut rng = SmallRng::seed_from_u64(input);
    let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);

    let signature = sign_digits(&params, &secret_key, &compressed_proof_and_total_work);
    let env = ExecutorEnv::builder()
        .write(&pub_key)
        .unwrap()
        .write(&params)
        .unwrap()
        .write(&signature)
        .unwrap()
        .write(&compressed_proof_and_total_work)
        .unwrap()
        .build()
        .unwrap();
    let executor = default_executor();

    let _ = executor.execute(env, WINTERNITZ_ELF);
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

    return receipt;
}
