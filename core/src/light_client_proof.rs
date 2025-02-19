use alloy::providers::{Provider, ProviderBuilder};
use anyhow::bail;
use risc0_zkvm::{Receipt, InnerReceipt};
use serde_json::json;
use tokio;
use hex::decode;
use bincode;


#[tokio::main]
pub async fn fetch_light_client_proof() {
    let url = "https://light-client-prover.testnet.citrea.xyz/";
    let provider = ProviderBuilder::new()
        .on_http(url.parse().unwrap());
    let client = provider.client();
    let request = json!({
        "l1_height": 70029
    });

    let response: serde_json::Value = client.request("lightClientProver_getLightClientProofByL1Height", request).await.unwrap();
    let proof_str = response["proof"].as_str().expect("Proof is not a string")[2..].to_string();
    let bytes = decode(proof_str).expect("Invalid hex");
    let decoded: InnerReceipt = bincode::deserialize(&bytes).expect("Failed to deserialize");
    let receipt = receipt_from_inner(decoded).expect("Failed to create receipt");  

    println!("Receipt: {:?}", receipt);



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