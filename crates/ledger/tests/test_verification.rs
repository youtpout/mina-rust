// Run this test with:
// cargo test --package mina-tree --test test_zkapp

use ark_ff::Zero;
use base64::{engine::general_purpose, Engine};
use mina_curves::pasta::Fp;
use mina_p2p_messages::{
    bigint::BigInt,
    list::List,
    pseq::PaddedSeq,
    string::{TokenSymbol, ZkAppUri},
    v2::{
        CurrencyAmountStableV1, CurrencyBalanceStableV1, CurrencyFeeStableV1,
        MinaBaseAccountUpdateAccountPreconditionStableV1,
        MinaBaseAccountUpdateAuthorizationKindStableV1, MinaBaseAccountUpdateBodyEventsStableV1,
        MinaBaseAccountUpdateBodyFeePayerStableV1, MinaBaseAccountUpdateBodyStableV1,
        MinaBaseAccountUpdateFeePayerStableV1, MinaBaseAccountUpdateMayUseTokenStableV1,
        MinaBaseAccountUpdatePreconditionsStableV1, MinaBaseAccountUpdateTStableV1,
        MinaBaseAccountUpdateUpdateStableV1, MinaBaseAccountUpdateUpdateStableV1AppStateA,
        MinaBaseAccountUpdateUpdateStableV1Delegate,
        MinaBaseAccountUpdateUpdateStableV1Permissions, MinaBaseAccountUpdateUpdateStableV1Timing,
        MinaBaseAccountUpdateUpdateStableV1TokenSymbol,
        MinaBaseAccountUpdateUpdateStableV1VerificationKey,
        MinaBaseAccountUpdateUpdateStableV1VotingFor, MinaBaseAccountUpdateUpdateStableV1ZkappUri,
        MinaBaseAccountUpdateUpdateTimingInfoStableV1, MinaBaseControlStableV2,
        MinaBasePermissionsStableV2, MinaBaseReceiptChainHashStableV1,
        MinaBaseSignedCommandMemoStableV1, MinaBaseUserCommandStableV2,
        MinaBaseVerificationKeyWireStableV1, MinaBaseZkappCommandTStableV1WireStableV1,
        MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesA,
        MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAA,
        MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAACallsA,
        MinaBaseZkappPreconditionAccountStableV2, MinaBaseZkappPreconditionAccountStableV2Balance,
        MinaBaseZkappPreconditionAccountStableV2BalanceA,
        MinaBaseZkappPreconditionAccountStableV2Delegate,
        MinaBaseZkappPreconditionAccountStableV2ProvedState,
        MinaBaseZkappPreconditionAccountStableV2ReceiptChainHash,
        MinaBaseZkappPreconditionAccountStableV2StateA,
        MinaBaseZkappPreconditionProtocolStateEpochDataStableV1,
        MinaBaseZkappPreconditionProtocolStateEpochDataStableV1EpochLedger,
        MinaBaseZkappPreconditionProtocolStateEpochDataStableV1EpochSeed,
        MinaBaseZkappPreconditionProtocolStateEpochDataStableV1StartCheckpoint,
        MinaBaseZkappPreconditionProtocolStateStableV1,
        MinaBaseZkappPreconditionProtocolStateStableV1Amount,
        MinaBaseZkappPreconditionProtocolStateStableV1AmountA,
        MinaBaseZkappPreconditionProtocolStateStableV1GlobalSlot,
        MinaBaseZkappPreconditionProtocolStateStableV1GlobalSlotA,
        MinaBaseZkappPreconditionProtocolStateStableV1Length,
        MinaBaseZkappPreconditionProtocolStateStableV1LengthA,
        MinaBaseZkappPreconditionProtocolStateStableV1SnarkedLedgerHash,
        MinaNumbersGlobalSlotSinceGenesisMStableV1, MinaNumbersGlobalSlotSpanStableV1,
        MinaStateBlockchainStateValueStableV2SignedAmount, PicklesProofProofsVerified2ReprStableV2,
        PicklesProofProofsVerifiedMaxStableV2, StateHash,
    },
};
use mina_signer::Signature;
use mina_tree::{
    proofs::public_input,
    scan_state::{
        currency::{Amount, Fee, Magnitude, Nonce, Sgn, Signed, Slot},
        transaction_logic::{
            zkapp_command::{
                Account, AccountPreconditions, AccountUpdate, Actions, AuthorizationKind, Body,
                CallForest, Control, Events, FeePayer, FeePayerBody, MayUseToken, Numeric,
                Preconditions, Tree, Update, WithStackHash, ZkAppCommand, ZkAppPreconditions,
            },
            Memo,
        },
    },
    MutableFp, TokenId,
};
use rsexp::{OfSexp, Sexp};

pub fn proof_from_b64_sexp_max(
    proof_sexp_b64: &str,
) -> Result<PicklesProofProofsVerifiedMaxStableV2, String> {
    let sexp_bytes = general_purpose::STANDARD
        .decode(proof_sexp_b64.trim())
        .map_err(|e| format!("base64 decode failure: {e:?}"))?;

    let sexp =
        rsexp::from_slice(&sexp_bytes).map_err(|e| format!("S-exp parsing failure: {e:?}"))?;

    PicklesProofProofsVerifiedMaxStableV2::of_sexp(&sexp)
        .map_err(|e| format!("S-exp -> proof(max) decode failure: {e:?}"))
}

#[test]
fn test_proof_verification() {
    //let verification_key = "AACcenc1yLdGBm4xtUN1dpModROI0zovuy5rz2a94vfdBgG1C75BqviU4vw6JUYqODF8n9ivtfeU5s9PcpEGIP0htil2mfx8v2DB5RuNQ7VxJWkha0TSnJJsOl0FxhjldBbOY3tUZzZxHpPhHOKHz";
    let proof_b64 = include_str!("proof.txt").to_string();
    let proof_example_b64 =
        include_str!("../../../tests/files/zkapps/proof_string.txt").to_string();
    let input = [1u8; 32];

    let proof_example = proof_from_b64_sexp_max(&proof_example_b64);
    let proof = proof_from_b64_sexp_max(&proof_b64);

    eprintln!("proof result = {:#?}", proof);

    assert!(proof_example.is_ok(), "proof example decode failed: {proof:?}");
    assert!(proof.is_ok(), "proof decode failed: {proof:?}");
}
