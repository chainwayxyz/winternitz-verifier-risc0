use header_chain::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::guest::env;
use crypto_bigint::{U256, U128, Encoding};
fn main() {
    let block_header_circuit_output: BlockHeaderCircuitOutput = env::read(); 
    let image_id: [u32; 8]  = env::read();
    env::verify(image_id, &borsh::to_vec(&block_header_circuit_output).unwrap()).unwrap();
    let total_work_u256: U256 = U256::from_be_bytes(block_header_circuit_output.chain_state.total_work);
    let (i, chain_state_total_work_u128): (U128, U128) = total_work_u256.into();
    let mut words = chain_state_total_work_u128.to_words();
    words.reverse();
    env::commit(&words);
}