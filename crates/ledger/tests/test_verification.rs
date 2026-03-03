// Run this test with:
// cargo test --package mina-tree --test test_zkapp

use ark_ff::{fp, Fp, One, Zero};
use base64::{engine::general_purpose, Engine};
use mina_curves::pasta::{Fq};
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesBaseProofsVerifiedStableV1,
    PicklesProofProofsVerified2ReprStableV2, PicklesProofProofsVerified2ReprStableV2StatementFp,
    PicklesProofProofsVerifiedMaxStableV2,
};

use mina_tree::{
    account,
    proofs::{
        prover::make_padded_proof_from_p2p,
        verification::{
            compute_deferred_values, get_message_for_next_step_proof,
            get_message_for_next_wrap_proof, get_prepared_statement, run_checks, verify_with, VK,
        },
        verifiers::make_zkapp_verifier_index,
    },
    scan_state::transaction_logic::zkapp_statement::{TransactionCommitment, ZkappStatement},
    VerificationKey,
};
use rsexp::{OfSexp, Sexp};
use serde::Deserialize;

pub fn proof_from_b64_sexp_max(
    proof_sexp_b64: &str,
) -> Result<PicklesProofProofsVerified2ReprStableV2, String> {
    let sexp_bytes = general_purpose::STANDARD
        .decode(proof_sexp_b64.trim())
        .map_err(|e| format!("base64 decode failure: {e:?}"))?;

    let sexp =
        rsexp::from_slice(&sexp_bytes).map_err(|e| format!("S-exp parsing failure: {e:?}"))?;

    PicklesProofProofsVerified2ReprStableV2::of_sexp(&sexp)
        .map_err(|e| format!("S-exp -> proof(max) decode failure: {e:?}"))
}

pub fn vk_from_b64_binprot(vk_b64: &str) -> Result<MinaBaseVerificationKeyWireStableV1, String> {
    // let bytes = general_purpose::STANDARD
    //     .decode(vk_b64.trim())
    //     .map_err(|e| format!("base64 decode failure: {e:?}"))?;

    // let mut cur = Cursor::new(bytes);
    MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64)
        .map_err(|e| format!("binprot decode failure: {e:?}"))
}

#[test]
fn test_proof_example_verification() {
    let proof_example_b64 =
        include_str!("../../../tests/files/zkapps/proof_string.txt").to_string();

    let proof_example = proof_from_b64_sexp_max(&proof_example_b64);

    let proof_test = PicklesProofProofsVerifiedMaxStableV2::deserialize(serde_json::Value::String(
        proof_example_b64,
    ));

    assert!(
        proof_example.is_ok(),
        "proof example decode failed: {proof_example:?}"
    );
}

#[test]
fn test_proof_verification() {
    let input: [u8; 32] = [1u8; 32];

    let proof_b64 = include_str!("proof.txt").to_string();
    let vk_b64 = include_str!("vk.txt").to_string();

    let proof: Result<PicklesProofProofsVerified2ReprStableV2, String> =
        proof_from_b64_sexp_max(&proof_b64);
    assert!(proof.is_ok(), "proof decode failed: {proof:?}");

    let vk_wire: MinaBaseVerificationKeyWireStableV1 =
        MinaBaseVerificationKeyWireStableV1::from_base64(&vk_b64)
            .map_err(|e| format!("binprot decode failure: {e:?}"))
            .expect("vk decode failed");

    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> vk runtime");

    // Index
    let verifier_index = make_zkapp_verifier_index(&verification_key);

    // Public input
    let mut public_input: Vec<Fp<fp::MontBackend<mina_curves::pasta::fields::FrConfig, 4>, 4>> =
        vec![Fq::zero(); verifier_index.public];
    // public_input[0] = Fq::zero();
    public_input[1] = Fq::one();

    let app_state = ();

    let proof_unwrap = proof.unwrap();

    //
    let deferred_values = compute_deferred_values(&proof_unwrap).expect("deferred values");
    let checks_ok = run_checks(&proof_unwrap, &verifier_index);

    eprintln!("public input: {:?}", verifier_index.public);

    // Proof padded
    let proof = make_padded_proof_from_p2p(&proof_unwrap).expect("pad proof");

    // Verify
    let result = verify_with(&verifier_index, &proof, &public_input);

    assert!(result.is_ok(), "invalid proof: {:?}", result.err());
}

#[test]
fn test_verify_with() {
    let proof_b64 = include_str!("proof.txt").to_string();
    let vk_b64 = include_str!("vk.txt").to_string();

    let proof: PicklesProofProofsVerified2ReprStableV2 =
        proof_from_b64_sexp_max(&proof_b64).expect("proof decode");

    let vk_wire: MinaBaseVerificationKeyWireStableV1 =
        MinaBaseVerificationKeyWireStableV1::from_base64(&vk_b64).expect("vk decode");

    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> vk runtime");

    // 1) create vk index
    let verifier_index = make_zkapp_verifier_index(&verification_key);

    let vk = VK {
        commitments: *verification_key.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    // 2) app_state empty
    let app_state: ZkappStatement = ZkappStatement {
        account_update: TransactionCommitment(fp::Fp::one()),
        calls: TransactionCommitment::empty(),
    };

    // 3) generate public input
    let deferred_values = compute_deferred_values(&proof).expect("deferred values");
    let checks_ok = run_checks(&proof, vk.index);

    let msg_next_step = get_message_for_next_step_proof(
        &proof.statement.messages_for_next_step_proof,
        &vk.commitments,
        &app_state,
    )
    .expect("message_for_next_step");

    let msg_next_wrap =
        get_message_for_next_wrap_proof(&proof.statement.proof_state.messages_for_next_wrap_proof)
            .expect("message_for_next_wrap");

    let prepared_statement = get_prepared_statement(
        &msg_next_step,
        &msg_next_wrap,
        deferred_values,
        &proof.statement.proof_state.sponge_digest_before_evaluations,
    );

    let npublic_input = vk.index.public;
    let public_inputs = prepared_statement
        .to_public_input(npublic_input)
        .expect("to_public_input");

    // 4) check proof
    let prover_proof = make_padded_proof_from_p2p(&proof).expect("make_padded_proof");

    match verify_with(vk.index, &prover_proof, &public_inputs) {
        Ok(()) => assert!(checks_ok, "verify_with OK mais checks KO"),
        Err(e) => panic!("invalid proof: {e:?}"),
    }
}
