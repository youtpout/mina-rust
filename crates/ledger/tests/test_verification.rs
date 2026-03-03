// Run this test with:
// cargo test --package mina-tree --test test_zkapp

use anyhow::{Context, Result};
use ark_ff::{fp, One, Zero};
use base64::{engine::general_purpose, Engine};
use mina_curves::pasta::{Fp, Fq};
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesBaseProofsVerifiedStableV1,
    PicklesProofProofsVerified2ReprStableV2, PicklesProofProofsVerified2ReprStableV2StatementFp,
    PicklesProofProofsVerifiedMaxStableV2,
};

use mina_tree::{
    VerificationKey, account, proofs::{
        prover::make_padded_proof_from_p2p, to_field_elements::ToFieldElements, verification::{
            VK, compute_deferred_values, get_message_for_next_step_proof, get_message_for_next_wrap_proof, get_prepared_statement, run_checks, verify_with
        }, verifiers::make_zkapp_verifier_index
    }, scan_state::transaction_logic::zkapp_statement::{TransactionCommitment, ZkappStatement}
};
use rsexp::{OfSexp, Sexp};
use serde::Deserialize;
use serde_json::Value;
use std::{fs, str::FromStr};

#[derive(Clone, Copy, Debug)]
pub struct AppState8(pub [Fp; 8]);


impl ToFieldElements<Fp> for AppState8 {
    fn to_field_elements(&self, out: &mut Vec<Fp>) {
        // Push the 8 field elements in order.
        out.extend_from_slice(&self.0);
    }
}


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


fn parse_tx_json_maybe_string(s: &str) -> anyhow::Result<Value> {
    // The file can be either a JSON object, or a JSON string containing an escaped JSON object.
    let v: Value = serde_json::from_str(s)?;
    if let Value::String(inner) = v {
        Ok(serde_json::from_str::<Value>(&inner)?)
    } else {
        Ok(v)
    }
}


fn fp_from_decimal_str(s: &str) -> Result<Fp> {
    // Values are encoded as decimal strings in your tx JSON.
    // mina_curves::pasta::Fp::from_str returns Result<_, ()>, so convert the unit error into anyhow.
    Fp::from_str(s).map_err(|_| anyhow::anyhow!("invalid Fp decimal string: {s}"))
}

pub fn load_app_state8_from_txn_file(raw: &str) -> anyhow::Result<AppState8> {
    let v = parse_tx_json_maybe_string(&raw).context("parse txn.json")?;

    // JSON path: accountUpdates[0].body.update.appState
    let app = &v["accountUpdates"][0]["body"]["update"]["appState"];
    let arr = app
        .as_array()
        .context("missing accountUpdates[0].body.update.appState array")?;

    if arr.len() != 8 {
        anyhow::bail!("appState must have 8 elements, got {}", arr.len());
    }

    let mut out = [Fp::zero(); 8];

    for (i, x) in arr.iter().enumerate() {
        out[i] = match x {
            // null means "no value provided in the update"; for verification messages we still need a field element.
            Value::Null => Fp::zero(),

            // Decimal string field element.
            Value::String(s) => fp_from_decimal_str(s)
                .with_context(|| format!("parse appState[{i}] decimal field element"))?,

            other => anyhow::bail!("appState[{i}] expected string or null, got {other}"),
        };
    }

    Ok(AppState8(out))
}


#[test]
fn test_verify_with() {
    let proof_b64 = include_str!("proof.txt").to_string();
    let vk_b64 = include_str!("vk.txt").to_string();
    let txn_json: String = include_str!("txn.json").to_string();

    let proof: PicklesProofProofsVerified2ReprStableV2 =
        proof_from_b64_sexp_max(&proof_b64).expect("proof decode");

    let vk_wire: MinaBaseVerificationKeyWireStableV1 =
        MinaBaseVerificationKeyWireStableV1::from_base64(&vk_b64).expect("vk decode");

    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> vk runtime");

    let verifier_index = make_zkapp_verifier_index(&verification_key);

    let vk = VK {
        commitments: *verification_key.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    let app_state = load_app_state8_from_txn_file(&txn_json)
        .expect("failed to load and parse appState from txn.json");

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

    eprintln!("public_inputs: {public_inputs:?}");

    let prover_proof = make_padded_proof_from_p2p(&proof).expect("make_padded_proof");

    match verify_with(vk.index, &prover_proof, &public_inputs) {
        Ok(()) => assert!(checks_ok, "verify_with OK mais checks KO"),
        Err(e) => panic!("invalid proof: {e:?}"),
    }
}
