use alloy::{primitives::keccak256, providers::{Provider, ProviderBuilder}};
use alloy_primitives::U256;
use alloy_rpc_types::EIP1186AccountProofResponse;
use anyhow::bail;
use hex::decode;
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Receipt};
use serde_json::json;



const UTXOS_STORAGE_INDEX: [u8; 32] = hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000026");
const DEPOSIT_MAPPING_STORAGE_INDEX: [u8; 32] = hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000027");
const TX_ID: [u8; 32] = hex_literal::hex!("2DA38853594CCB2DC9C3D4066BDEEE5FAD72E0688112BA27EE572383A11434D8");

const LC_PROOF_VERIFIER_ELF: &[u8] = include_bytes!("../../elfs/regtest-lc-proof-verifier-guest");
const LIGHT_CLIENT_PROVER_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
const CITREA_TESTNET_RPC: &str = "https://rpc.testnet.citrea.xyz/";
const CONTRACT_ADDRESS: &str = "0x3100000000000000000000000000000000000002";
#[tokio::main]
pub async fn fetch_light_client_proof() {
    let provider = ProviderBuilder::new().on_http(LIGHT_CLIENT_PROVER_URL.parse().unwrap());
    let client = provider.client();
    let request = json!({
        "l1_height": 70029
    });

    let response: serde_json::Value = client
        .request("lightClientProver_getLightClientProofByL1Height", request)
        .await
        .unwrap();
    let proof_str = response["proof"].as_str().expect("Proof is not a string")[2..].to_string();
    let l2_height = response["lightClientProofOutput"]["lastL2Height"]
        .as_str()
        .expect("l2 height is not a string");

    let bytes = decode(proof_str).expect("Invalid hex");
    let decoded: InnerReceipt = bincode::deserialize(&bytes).expect("Failed to deserialize");
    let receipt = receipt_from_inner(decoded).expect("Failed to create receipt");


    let ind = 18;
    let tx_index: u32 = ind * 2;

    let storage_address_bytes = keccak256(UTXOS_STORAGE_INDEX);
    println!("Storage address: {:?}", &storage_address_bytes[..]);
    let storage_address: U256 = U256::from_be_bytes(<[u8; 32]>::try_from(&storage_address_bytes[..]).expect("Slice with incorrect length"));
    let storage_key: alloy_primitives::Uint<256, 4> = storage_address + U256::from(tx_index);
    let storage_key_hex = hex::encode(storage_key.to_be_bytes::<32>());
    println!("Storage key: {:?}", &storage_key_hex);
    let storage_key_hex = format!("0x{}", storage_key_hex);

    let mut concantenated: [u8; 64] = [0; 64];

    concantenated[0..32].copy_from_slice(&TX_ID);
    concantenated[32..64].copy_from_slice(&DEPOSIT_MAPPING_STORAGE_INDEX);

    let storage_address_deposit = keccak256(concantenated);
    let storage_address_deposit_hex = hex::encode(storage_address_deposit);
    let storage_address_deposit_hex = format!("0x{}", storage_address_deposit_hex);
    println!("Storage address deposit: {:?}", &storage_address_deposit_hex);


    let citrea_provider = ProviderBuilder::new().on_http(CITREA_TESTNET_RPC.parse().unwrap());

    let citrea_client = citrea_provider.client();
    let request = json!([
        CONTRACT_ADDRESS,
        [storage_key_hex, storage_address_deposit_hex],
        l2_height
        ]
    );

    let response: serde_json::Value  = citrea_client
        .request("eth_getProof", request)
        .await
        .unwrap();
    // serialize the response

    //deserialize the response
    let response: EIP1186AccountProofResponse = serde_json::from_value(response).unwrap();
    
    let serialized = serde_json::to_string(&response.storage_proof[0]).unwrap();

    let serialized_deposit = serde_json::to_string(&response.storage_proof[1]).unwrap();


    let mut binding = ExecutorEnv::builder();
    let env = binding
        .write(&receipt.journal.bytes)
        .unwrap()
        .write(&serialized)
        .unwrap()
        .write(&ind)
        .unwrap()
        .write(&serialized_deposit)
        .unwrap()
        .add_assumption(receipt)
        .build()
        .unwrap();

    let prover = default_prover();

    _ = prover.prove(env, LC_PROOF_VERIFIER_ELF);
}

fn receipt_from_inner(inner: InnerReceipt) -> anyhow::Result<Receipt> {
    let mb_claim = inner.claim().or_else(|_| bail!("Claim is empty"))?;
    let claim = mb_claim
        .value()
        .or_else(|_| bail!("Claim content is empty"))?;
    let output = claim
        .output
        .value()
        .or_else(|_| bail!("Output content is empty"))?;
    let Some(output) = output else {
        bail!("Output body is empty");
    };

    let journal = output
        .journal
        .value()
        .or_else(|_| bail!("Journal content is empty"))?;
    Ok(Receipt::new(inner, journal))
}
