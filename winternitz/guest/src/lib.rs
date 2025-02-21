use ark_bn254::{Bn254, Fr};
use ark_groth16::PreparedVerifyingKey;
use ark_serialize::CanonicalDeserialize;
use constants::{
    A0_ARK, A1_ARK, ASSUMPTIONS, BN_254_CONTROL_ID_ARK, CLAIM_TAG, INPUT, OUTPUT_TAG, POST_STATE,
    PREPARED_VK, PRE_STATE,
};
use hex::ToHex;
use lc_proof::lc_proof_verifier;
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use winternitz_core::utils::hash160;
use winternitz_core::winternitz::{
    verify_signature, WinternitzCircuitInput, WinternitzCircuitOutput,
};
use winternitz_core::zkvm::ZkvmGuest;
use winternitz_core::{groth16::CircuitGroth16Proof, utils::to_decimal};
mod constants;
mod lc_proof;

pub fn create_output_digest(total_work: &[u8; 16]) -> [u8; 32] {
    let total_work_digest: [u8; 32] = Sha256::digest(total_work).into();
    let len_output: [u8; 2] = hex::decode("0200").unwrap().try_into().unwrap();

    let output_pre_digest: [u8; 98] = [
        &OUTPUT_TAG,
        &total_work_digest[..],
        &ASSUMPTIONS[..],
        &len_output[..],
    ]
    .concat()
    .try_into()
    .expect("slice has correct length");

    Sha256::digest(output_pre_digest).into()
}

pub fn create_claim_digest(output_digest: &[u8; 32]) -> [u8; 32] {
    let data: [u8; 8] = [0; 8];

    let claim_len: [u8; 2] = [4, 0];

    let concatenated = [
        &CLAIM_TAG,
        &INPUT,
        &PRE_STATE,
        &POST_STATE,
        output_digest,
        &data[..],
        &claim_len,
    ]
    .concat();

    let mut claim_digest = Sha256::digest(concatenated);
    claim_digest.reverse();

    claim_digest.into()
}
pub struct CircuitGroth16WithTotalWork {
    groth16_seal: CircuitGroth16Proof,
    total_work: [u8; 16],
}

impl CircuitGroth16WithTotalWork {
    pub fn new(
        groth16_seal: CircuitGroth16Proof,
        total_work: [u8; 16],
    ) -> CircuitGroth16WithTotalWork {
        CircuitGroth16WithTotalWork {
            groth16_seal,
            total_work,
        }
    }

    pub fn verify(&self) -> bool {
        let ark_proof = self.groth16_seal.into();
        let start = env::cycle_count();
        let prepared_vk: PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> =
            CanonicalDeserialize::deserialize_uncompressed(PREPARED_VK).unwrap();
        let end = env::cycle_count();
        println!("PVK: {}", end - start);
        let start = env::cycle_count();

        let output_digest = create_output_digest(&self.total_work);

        let claim_digest: [u8; 32] = create_claim_digest(&output_digest);

        let claim_digest_hex: String = claim_digest.encode_hex();
        let c0_str = &claim_digest_hex[32..64];
        let c1_str = &claim_digest_hex[0..32];

        let c0_dec = to_decimal(c0_str).unwrap();
        let c1_dec = to_decimal(c1_str).unwrap();

        let c0 = Fr::from_str(&c0_dec).unwrap();
        let c1 = Fr::from_str(&c1_dec).unwrap();

        let public_inputs = vec![A0_ARK, A1_ARK, c0, c1, BN_254_CONTROL_ID_ARK];

        let end = env::cycle_count();
        println!("PPI: {}", end - start);
        ark_groth16::Groth16::<Bn254>::verify_proof(&prepared_vk, &ark_proof, &public_inputs)
            .unwrap()
    }
}

pub fn verify_winternitz_and_groth16(input: &WinternitzCircuitInput) -> bool {
    let start = env::cycle_count();
    if !verify_signature(&input) {
        return false;
    }

    let end = env::cycle_count();
    println!("WNV: {}", end - start);
    let compressed_seal: [u8; 128] = match input.message[0..128].try_into() {
        Ok(compressed_seal) => compressed_seal,
        Err(_) => return false,
    };
    let total_work: [u8; 16] = match input.message[128..144].try_into() {
        Ok(total_work) => total_work,
        Err(_) => return false,
    };

    let seal = match CircuitGroth16Proof::from_compressed(&compressed_seal) {
        Ok(seal) => seal,
        Err(_) => return false,
    };

    let groth16_proof = CircuitGroth16WithTotalWork::new(seal, total_work);
    let start = env::cycle_count();
    let res = groth16_proof.verify();
    let end = env::cycle_count();
    println!("G16V: {}", end - start);
    println!("{}", res);
    res
}

pub fn winternitz_circuit(guest: &impl ZkvmGuest) {
    let start = env::cycle_count();
    let input: WinternitzCircuitInput = guest.read_from_host();

    
    verify_winternitz_and_groth16(&input);
    

    // [0, 0, 0, 0, 147, 1, 0, 0, 118, 250, 126, 190, 176, 135, 0, 199]
    // Total work: [199, 0, 135, 176, 190, 126, 250, 118, 0, 0, 1, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    println!("{:?}", &input.message[128..144]);
    let mut total_work: [u8; 32] = [0; 32];
    total_work[16..32].copy_from_slice(&input.message[128..144].chunks_exact(4).flat_map(|c| c.iter().rev()).copied().collect::<Vec<_>>());

    println!("Total work: {:?}", total_work);
    println!("HCP total work: {:?}", input.hcp.chain_state.total_work);
    if input.hcp.chain_state.total_work < total_work {
        panic!("Invalid total work");
    }
    let mut pub_key_concat: Vec<u8> = vec![0; input.pub_key.len() * 20];
    for (i, pubkey) in input.pub_key.iter().enumerate() {
        pub_key_concat[i * 20..(i + 1) * 20].copy_from_slice(pubkey);
    }

    

    guest.commit(&WinternitzCircuitOutput {
        winternitz_pubkeys_digest: hash160(&pub_key_concat),
    });
    let end = env::cycle_count();
    println!("WNT: {}", end - start);

    // MMR WILL BE FETCHED FROM LC PROOF WHEN IT IS READY - THIS IS JUST FOR PROOF OF CONCEPT
    let mmr = input.hcp.chain_state.block_hashes_mmr;

    println!("SPV verification {:?}", input.payout_spv.verify(mmr));

    let user_wd_outpoint_str = lc_proof_verifier(input.lcp);
    let user_wd_txid = bitcoin::Txid::from_str(&user_wd_outpoint_str).unwrap();
    assert_eq!(user_wd_txid, input.payout_spv.transaction.input[0].previous_output.txid);
}
