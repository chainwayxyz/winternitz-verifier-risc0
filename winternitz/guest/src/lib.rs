use ark_bn254::{Bn254, Fr};
use ark_groth16::PreparedVerifyingKey;
use ark_serialize::CanonicalDeserialize;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
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
    verify_winternitz_signature, WinternitzCircuitInput, WinternitzCircuitOutput, WinternitzHandler
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

pub fn verify_winternitz_and_groth16(input: &WinternitzHandler) -> bool {
    let start = env::cycle_count();
    let res = verify_winternitz_signature(input);
    let end = env::cycle_count();
    println!("WNV: {}", end - start);
    res
}

pub fn convert_to_groth16_and_verify(message: &Vec<u8>) -> bool {
    let compressed_seal: [u8; 128] = match message[0..128].try_into() {
        Ok(compressed_seal) => compressed_seal,
        Err(_) => return false,
    };
    let total_work: [u8; 16] = match message[128..144].try_into() {
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
    let mut watchtower_flags: Vec<bool> = vec![];
    for winternitz_handler in &input.winternitz_details {
        watchtower_flags.push(verify_winternitz_signature(&winternitz_handler));
    }

    let mut wt_messages_with_idxs: Vec<(usize, Vec<u8>)> = vec![];
    for (wt_idx, flag) in watchtower_flags.iter().enumerate() {
        if *flag {
            wt_messages_with_idxs.push((wt_idx, input.winternitz_details[wt_idx].message.clone()));
        }
    }
    // sort by total work from the largest to the smallest
    wt_messages_with_idxs.sort_by(|a, b| b.1.cmp(&a.1));
    let mut total_work = [0u8; 32];
    for pair in wt_messages_with_idxs.iter() {
        if convert_to_groth16_and_verify(&pair.1) {
            total_work[16..32].copy_from_slice(&pair.1[128..144].chunks_exact(4).flat_map(|c| c.iter().rev()).copied().collect::<Vec<_>>());
            break;
        }
    }

    // println!("{:?}", &input.message[128..144]);
    // let mut total_work: [u8; 32] = [0; 32];
    // total_work[16..32].copy_from_slice(&input.message[128..144].chunks_exact(4).flat_map(|c| c.iter().rev()).copied().collect::<Vec<_>>());

    println!("Total work: {:?}", total_work);
    println!("HCP total work: {:?}", input.hcp.chain_state.total_work);
    if input.hcp.chain_state.total_work < total_work {
        panic!("Invalid total work");
    }
    let num_wts = input.winternitz_details.len();
    let pk_size = input.winternitz_details[0].pub_key.len();
    let mut pub_key_concat: Vec<u8> = vec![0; num_wts * pk_size * 20];
    for (i, wots_handler) in input.winternitz_details.iter().enumerate() {
        for (j, pubkey) in wots_handler.pub_key.iter().enumerate() {
            pub_key_concat[(pk_size * i * 20 + j * 20)..(pk_size * i * 20 + (j + 1) * 20)].copy_from_slice(pubkey);
        }
        // pub_key_concat[i * 20..(i + 1) * 20].copy_from_slice(wots_handler.pub_key.as_slice());
    }

    // MMR WILL BE FETCHED FROM LC PROOF WHEN IT IS READY - THIS IS JUST FOR PROOF OF CONCEPT
    let mmr = input.hcp.chain_state.block_hashes_mmr;

    println!("SPV verification {:?}", input.payout_spv.verify(mmr));

    let user_wd_outpoint_str = lc_proof_verifier(input.lcp);
    let user_wd_outpoint = num_bigint::BigUint::from_str(&user_wd_outpoint_str).unwrap();
    let user_wd_txid = bitcoin::Txid::from_byte_array(user_wd_outpoint.to_bytes_be().as_slice().try_into().unwrap());
    assert_eq!(user_wd_txid, input.payout_spv.transaction.input[0].previous_output.txid);
    println!("{:?}", input.payout_spv.transaction.output);
    let last_output = input.payout_spv.transaction.output.last().unwrap();
    let last_output_script = last_output.script_pubkey.to_bytes();
    assert!(last_output_script[0] == 0x6a);
    let len = last_output_script[1];
    let operator_id  = last_output_script[2..(2 + len as usize)].to_vec();

    guest.commit(&WinternitzCircuitOutput {
        winternitz_pubkeys_digest: hash160(&pub_key_concat),
        correct_watchtowers: watchtower_flags,
        payout_tx_blockhash: input.payout_spv.block_header.compute_block_hash(),
        last_blockhash: [0u8; 32], // TODO: Change here
        deposit_txid: [0u8; 32], // TODO: Change here
        operator_id: operator_id,
    });
    let end = env::cycle_count();
    println!("WNT: {}", end - start);

}
