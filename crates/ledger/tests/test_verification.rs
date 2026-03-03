// Run this test with:
// cargo test --package mina-tree --test test_zkapp

use base64::{engine::general_purpose, Engine};
use mina_p2p_messages::v2::{
    PicklesBaseProofsVerifiedStableV1, PicklesProofProofsVerified2ReprStableV2,
    PicklesProofProofsVerified2ReprStableV2StatementFp, PicklesProofProofsVerifiedMaxStableV2,
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

#[test]
fn test_proof_verification() {
    //let verification_key = "AACcenc1yLdGBm4xtUN1dpModROI0zovuy5rz2a94vfdBgG1C75BqviU4vw6JUYqODF8n9ivtfeU5s9PcpEGIP0htil2mfx8v2DB5RuNQ7VxJWkha0TSnJJsOl0FxhjldBbOY3tUZzZxHpPhHOKHz";
    let proof_b64 = include_str!("proof.txt").to_string();
    let proof_example_b64 =
        include_str!("../../../tests/files/zkapps/proof_string.txt").to_string();
    let input = [1u8; 32];


let proof_b64 = include_str!("proof.txt").trim();


    let proof_example = PicklesProofProofsVerifiedMaxStableV2::deserialize(serde_json::Value::String(proof_example_b64.to_string()));
    let proof = proof_from_b64_sexp_max(&proof_b64);

    eprintln!("proof result = {:#?}", proof);

    assert!(
        proof_example.is_ok(),
        "proof example decode failed: {proof:?}"
    );
   // assert!(proof.is_ok(), "proof decode failed: {proof:?}");
}
