use borsh::{self, BorshDeserialize};
use header_chain::header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput,
    HeaderChainPrevProofType,
};
use std::convert::TryInto;
use headerchain::{HEADERCHAIN_ELF, HEADERCHAIN_ID};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_zkvm::{compute_image_id, default_executor, default_prover, Executor, ExecutorEnv, ProverOpts, Receipt};
use risc0_groth16::Seal;
use winternitz::{WINTERNITZ_ELF, WINTERNITZ_ID};
use winternitz_core::{generate_public_key, sign_digits, Parameters};
use work_only::{WORK_ONLY_ELF, WORK_ONLY_ID};
use host::{g1_compress, g2_compress};

const HEADERS: &[u8] = include_bytes!("regtest-headers.bin");

fn le_to_be(input: [u32; 16]) -> [u32; 16] {
    let mut output = input;
    output.chunks_exact_mut(4).for_each(|chunk| { chunk.reverse(); println!("{:?}", chunk) });
    output.reverse();
    output
}
fn main() {
    let headerchain_proof: Receipt = generate_header_chain_proof();
    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(&headerchain_proof.journal.bytes[..]).unwrap();
    println!("{:?}", block_header_circuit_output.method_id);
    let work_only_groth16_proof_receipt: Receipt = call_work_only(
        headerchain_proof,
        &block_header_circuit_output,
        block_header_circuit_output.method_id,
    );
        
    let g16_proof: &risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> = work_only_groth16_proof_receipt.inner.groth16().unwrap();
    
    let seal= Seal::from_vec(&g16_proof.seal).unwrap();

    let a_compressed = g1_compress(seal.a);
    let b_compressed  = g2_compress(seal.b);
    let c_compressed = g1_compress(seal.c);

    let commited_total_work: [u8; 16] = work_only_groth16_proof_receipt.journal.bytes.try_into().unwrap();

    let mut compressed_proof: Vec<u8> = vec![0; 144];
    compressed_proof[0..32].copy_from_slice(&a_compressed[..32]);
    compressed_proof[32..96].copy_from_slice(&b_compressed[..64]);
    compressed_proof[96..128].copy_from_slice(&c_compressed[..32]);
    compressed_proof[128..144].copy_from_slice(&commited_total_work);
    

    let n0 = compressed_proof.len();
    let log_d = 8;
    let params = Parameters::new(n0.try_into().unwrap(), log_d);
    let input: u64 = 1;
    let mut rng = SmallRng::seed_from_u64(input);
    let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);


    let signature = sign_digits(&params, &secret_key, &compressed_proof);
    let env = ExecutorEnv::builder()
        .write(&pub_key)
        .unwrap()
        .write(&params)
        .unwrap()
        .write(&signature)
        .unwrap()
        .write(&compressed_proof)
        .unwrap()
        .write(&WORK_ONLY_ID)
        .unwrap()
        .build()
        .unwrap();

    
    let executor = default_executor();
    println!("Exec result: {:?}", executor.execute(env, WINTERNITZ_ELF).unwrap());
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

