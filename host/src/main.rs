use bitcoin::consensus::Decodable;
use borsh::{self, BorshDeserialize};
use bitcoin::hashes::Hash;
use final_spv::merkle_tree::BitcoinMerkleTree;
use final_spv::spv::SPV;
use header_chain::header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use header_chain::mmr_native::MMRNative;
use host::fetch_light_client_proof;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, ExecutorEnv, ProverOpts, Receipt,
};
use std::convert::TryInto;
use std::env;
use winternitz_core::groth16::CircuitGroth16Proof;
use winternitz_core::winternitz::{
    generate_public_key, sign_digits, Parameters, WinternitzCircuitInput,
};
use winternitz_core::WorkOnlyCircuitInput;

const HEADERS: &[u8] = include_bytes!("bin-files/testnet4-headers.bin");
const TESTNET_BLOCK_46698: &[u8] = include_bytes!("bin-files/testnet4_block_46698.bin");
const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("bin-files/first_70000_proof.bin");
const HEADERCHAIN_ELF: &[u8] = include_bytes!("../../elfs/regtest-headerchain-guest");
const WINTERNITZ_ELF: &[u8] = include_bytes!("../../elfs/regtest-winternitz-guest");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../elfs/regtest-work-only-guest");
#[tokio::main]
async fn main() {
    // let headerchain_id: [u32; 8] = compute_image_id(HEADERCHAIN_ELF).unwrap().into();
    println!("testnet block 46698: {:?}", TESTNET_BLOCK_46698);
    println!("testnet block 46698 vec: {:?}", TESTNET_BLOCK_46698.to_vec());
    let winternitz_id: [u32; 8] = compute_image_id(WINTERNITZ_ELF).unwrap().into();
    let work_only_id: [u32; 8] = compute_image_id(WORK_ONLY_ELF).unwrap().into();

    // println!("HEADERCHAIN_ID: {:?}", headerchain_id);
    println!("WINTERNITZ_ID: {:?}", winternitz_id);
    println!("WORK_ONLY_ID: {:?}", work_only_id);

    let headerchain_proof: Receipt = match env::var("GENERATE_PROOF") {
        Ok(_) => generate_header_chain_proof(),
        Err(_) => Receipt::try_from_slice(HEADER_CHAIN_INNER_PROOF).unwrap(),
    };


    let headers = HEADERS
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();
    let mut mmr_native = MMRNative::new();
    for header in headers.iter() {
        mmr_native.append(header.compute_block_hash());
    }
    // println!("MMR_ROOT: {:?}", mmr_native);

    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(&headerchain_proof.journal.bytes[..]).unwrap();

    let work_only_circuit_input: WorkOnlyCircuitInput = WorkOnlyCircuitInput {
        header_chain_circuit_output: block_header_circuit_output.clone(),
    };
    let work_only_groth16_proof_receipt: Receipt =
        call_work_only(headerchain_proof, &work_only_circuit_input);

    let g16_proof_receipt: &risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> =
        work_only_groth16_proof_receipt.inner.groth16().unwrap();
    println!("G16 PROOF RECEIPT: {:?}", g16_proof_receipt);

    let seal =
        CircuitGroth16Proof::from_seal(g16_proof_receipt.seal.as_slice().try_into().unwrap());

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
    let light_client_proof = fetch_light_client_proof().await.unwrap();

    let block_vec = TESTNET_BLOCK_46698.to_vec();
    let block_46698 = bitcoin::block::Block::consensus_decode(&mut block_vec.as_slice()).unwrap();
    let move_tx = block_46698.txdata[20].clone();
    let block_46698_txids: Vec<[u8; 32]> = block_46698
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().as_raw_hash().to_byte_array())
        .collect();
    let mmr_inclusion_proof = mmr_native.generate_proof(46698);
    let block_46698_mt = BitcoinMerkleTree::new(block_46698_txids);
    let move_tx_proof = block_46698_mt.generate_proof(20);
    let spv: SPV = SPV {
        transaction: move_tx.into(),
        block_inclusion_proof: move_tx_proof,
        block_header: block_46698.header.into(),
        mmr_inclusion_proof: mmr_inclusion_proof.1,
    };

    let winternitz_circuit_input: WinternitzCircuitInput = WinternitzCircuitInput {
        pub_key,
        params,
        signature,
        message: compressed_proof_and_total_work,
        hcp: block_header_circuit_output,
        payout_spv: spv,
        lcp: light_client_proof,
    };

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&winternitz_circuit_input).unwrap());
    let env = env.build().unwrap();
    let executor = default_executor();

    let _ = executor.execute(env, WINTERNITZ_ELF);
}

fn call_work_only(receipt: Receipt, input: &WorkOnlyCircuitInput) -> Receipt {
    let mut binding = ExecutorEnv::builder();
    binding.add_assumption(receipt);
    let env = binding.write_slice(&borsh::to_vec(&input).unwrap());
    let env = env.build().unwrap();
    let prover = default_prover();
    prover
        .prove_with_opts(env, WORK_ONLY_ELF, &ProverOpts::groth16())
        .unwrap()
        .receipt
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

    prover
        .prove_with_opts(env, HEADERCHAIN_ELF, &ProverOpts::succinct())
        .unwrap()
        .receipt
}
