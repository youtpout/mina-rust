// Run this test with:
// cargo test --package mina-tree --test test_zkapp

use ark_ff::{fp, Fp, One, Zero};
use base64::{engine::general_purpose, Engine};
use mina_curves::pasta::Fq;
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesBaseProofsVerifiedStableV1,
    PicklesProofProofsVerified2ReprStableV2, PicklesProofProofsVerified2ReprStableV2StatementFp,
    PicklesProofProofsVerifiedMaxStableV2,
};

use mina_tree::{
    proofs::{
        prover::make_padded_proof_from_p2p, verification::verify_with,
        verifiers::make_zkapp_verifier_index,
    },
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
    let mut public_input = vec![Fq::zero(); 40];
    // public_input[0] = Fq::zero(); 
    // public_input[1] = Fq::one(); 

    // Proof padded
    let proof = make_padded_proof_from_p2p(&proof.unwrap()).expect("pad proof");

    // Verify
    let result = verify_with(&verifier_index, &proof, &public_input);

    assert!(result.is_ok(), "invalid proof: {:?}", result.err());
}
