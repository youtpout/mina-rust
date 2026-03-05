// Run this test with:
// cargo test --test test_verification -- --nocapture

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use juniper::{execute_sync, graphql_object, EmptySubscription, FieldResult, RootNode, Variables};
use juniper_axum::graphql;
use ledger::{
    proofs::{
        prover::make_padded_proof_from_p2p,
        verification::{
            compute_deferred_values, get_message_for_next_step_proof,
            get_message_for_next_wrap_proof, get_prepared_statement, run_checks, verify_with, VK,
        },
        verifiers::make_zkapp_verifier_index,
    },
    scan_state::transaction_logic::{verifiable, zkapp_command, TransactionStatus, WithStatus},
    verifier::common::{check, CheckResult},
    VerificationKey,
};
use mina_core::transaction::Transaction;
use mina_node_native::graphql::zkapp::{
    GraphQLSendZkappResponse, InputGraphQLZkappCommand, SendZkappInput,
};
use mina_p2p_messages::v2::{
    MinaBaseUserCommandStableV2, MinaBaseVerificationKeyWireStableV1,
    MinaBaseZkappCommandTStableV1WireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use rsexp::OfSexp;
use serde_json::Value;
use std::sync::Mutex;
use verification_test::parse_zkapp_command_json;

// Context — adapt to your needs
struct Context {
    // Store the parsed transaction here
    result: Mutex<Option<MinaBaseUserCommandStableV2>>,
}
impl juniper::Context for Context {}

// Dummy query root (required by Juniper)
struct Query;
#[graphql_object]
#[graphql(context = Context)]
impl Query {
    fn dummy() -> bool {
        true
    }
}

struct Mutation;
#[graphql_object]
#[graphql(context = Context)]
impl Mutation {
    fn send_zkapp(
        context: &Context,
        input: SendZkappInput,
    ) -> FieldResult<GraphQLSendZkappResponse> {
        // Juniper already parsed the GraphQL input into SendZkappInput
        let wire: MinaBaseUserCommandStableV2 = input.try_into()?;

        // Store the wire transaction for later use
        *context.result.lock().unwrap() = Some(wire.clone());

        // Return a response (needed by Juniper to match the query selection set)
        let response = GraphQLSendZkappResponse::try_from(wire)?;
        Ok(response)
    }
}

fn proof_from_b64_sexp_max(
    proof_sexp_b64: &str,
) -> Result<PicklesProofProofsVerified2ReprStableV2> {
    // Decode base64 -> bytes
    let sexp_bytes = general_purpose::STANDARD
        .decode(proof_sexp_b64.trim())
        .map_err(|e| anyhow::anyhow!("base64 decode proof: {e:?}"))?;

    // rsexp::Error is NOT StdError -> no `.context()`
    let sexp =
        rsexp::from_slice(&sexp_bytes).map_err(|e| anyhow::anyhow!("parse proof S-exp: {e:?}"))?;

    let proof = PicklesProofProofsVerified2ReprStableV2::of_sexp(&sexp)
        .map_err(|e| anyhow::anyhow!("S-exp -> proof decode: {e:?}"))?;

    Ok(proof)
}

#[test]
fn test_parse_zkapp_command() {
    let graphql_query = include_str!("graphql.txt");

    let schema = RootNode::new(Query, Mutation, EmptySubscription::<Context>::new());
    let ctx = Context {
        result: Mutex::new(None),
    };

    let (result, errors) =
        execute_sync(graphql_query, None, &schema, &Variables::new(), &ctx).unwrap();

    if !errors.is_empty() {
        eprintln!("GraphQL errors: {:?}", errors);
    }

    // Retrieve the fully parsed and converted transaction
    let wire_txn = ctx
        .result
        .lock()
        .unwrap()
        .take()
        .expect("transaction was parsed");

}

#[test]
fn test_verify_with() {
    let proof_b64 = include_str!("proof.txt");
    let vk_b64 = include_str!("vk.txt");
    let txn_json = include_str!("txn.json");
    let graphql = include_str!("graphql.txt");

    // Decode proof
    let proof = proof_from_b64_sexp_max(proof_b64).expect("decode proof");

    // Decode VK
    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64).expect("decode vk base64");
    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime vk");

    // Build verifier index + VK wrapper
    let verifier_index = make_zkapp_verifier_index(&verification_key);
    let vk = VK {
        commitments: *verification_key.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    // let json_cmd = parse_zkapp_command_json(&graphql).expect("decode command");
    // let input_cmd: InputGraphQLZkappCommand = json_cmd.into();
    // let wire: MinaBaseUserCommandStableV2 = input_cmd.try_into()?;

    // // runtime -> verifiable zkapp command (si ton code a déjà cette conversion)
    // // sinon tu dois la fournir via un wrapper/local trait (orphan rules)
    // let zkapp_cmd_verifiable: zkapp_command::verifiable::ZkAppCommand = (&zkapp_runtime).into();

    // // ✅ ce que check() attend
    // let cmd = WithStatus {
    //     data: verifiable::UserCommand::ZkAppCommand(Box::new(wire.into())),
    //     status: TransactionStatus::Applied,
    // };

    // let (_vk_from_tx, zkapp_stmt_from_tx, _proof_from_tx) = match check(cmd) {
    //     CheckResult::ValidAssuming((_valid_cmd, mut xs)) => xs.pop().expect("no vk/stmt/proof"),
    //     other => panic!("expected ValidAssuming(..), got: {other:?}"),
    // };

    // // Recompute deferred values + run additional checks
    // let deferred_values = compute_deferred_values(&proof).expect("compute deferred values");
    // let checks_ok = run_checks(&proof, vk.index);

    // let msg_next_step = get_message_for_next_step_proof(
    //     &proof.statement.messages_for_next_step_proof,
    //     &vk.commitments,
    //     &zkapp_stmt_from_tx,
    // )
    // .expect("get_message_for_next_step_proof");

    // let msg_next_wrap =
    //     get_message_for_next_wrap_proof(&proof.statement.proof_state.messages_for_next_wrap_proof)
    //         .expect("get_message_for_next_wrap_proof");

    // let prepared_statement = get_prepared_statement(
    //     &msg_next_step,
    //     &msg_next_wrap,
    //     deferred_values,
    //     &proof.statement.proof_state.sponge_digest_before_evaluations,
    // );

    // let public_inputs = prepared_statement
    //     .to_public_input(vk.index.public)
    //     .expect("prepared_statement -> public inputs");

    // eprintln!("public_inputs: {public_inputs:?}");

    // let prover_proof = make_padded_proof_from_p2p(&proof).expect("make_padded_proof");

    // match verify_with(vk.index, &prover_proof, &public_inputs) {
    //     Ok(()) => assert!(checks_ok, "verify_with OK but run_checks failed"),
    //     Err(e) => panic!("invalid proof: {e:?}"),
    // }
}
