use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use juniper::{
    execute_sync, graphql_object, EmptySubscription, FieldResult, RootNode, Variables,
};
use mina_node_native::graphql::zkapp::{GraphQLSendZkappResponse, SendZkappInput};
use mina_p2p_messages::v2::{
    MinaBaseControlStableV2, MinaBaseUserCommandStableV2,
    MinaBaseZkappCommandTStableV1WireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use rsexp::OfSexp;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Juniper schema (minimal, only used to parse GraphQL mutation syntax)
// ---------------------------------------------------------------------------

struct Context {
    result: Mutex<Option<MinaBaseUserCommandStableV2>>,
}
impl juniper::Context for Context {}

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
        let wire: MinaBaseUserCommandStableV2 = input.try_into()?;
        *context.result.lock().unwrap() = Some(wire.clone());
        let response = GraphQLSendZkappResponse::try_from(wire)?;
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parsed result from a GraphQL `sendZkapp` mutation file.
pub struct ParsedZkappTransaction {
    /// The full wire-format user command (fee payer + account updates + memo).
    pub wire_command: MinaBaseUserCommandStableV2,
    /// The zkApp command extracted from the wire command.
    pub zkapp_command: MinaBaseZkappCommandTStableV1WireStableV1,
    /// The proof from the first account update that carries one.
    pub proof: PicklesProofProofsVerified2ReprStableV2,
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Parse a GraphQL `sendZkapp` mutation string and extract the wire
/// transaction, zkApp command, and the first proof found in account updates.
///
/// The input must be a complete GraphQL mutation, e.g.:
/// ```graphql
/// mutation {
///   sendZkapp(input: { zkappCommand: { ... } }) { ... }
/// }
/// ```
pub fn parse_graphql_zkapp(graphql_str: &str) -> Result<ParsedZkappTransaction> {
    // Build a throwaway Juniper schema to leverage its GraphQL parser
    let schema = RootNode::new(Query, Mutation, EmptySubscription::<Context>::new());
    let ctx = Context {
        result: Mutex::new(None),
    };

    let (_value, errors) =
        execute_sync(graphql_str, None, &schema, &Variables::new(), &ctx)
            .map_err(|e| anyhow::anyhow!("GraphQL execution error: {e:?}"))?;

    if !errors.is_empty() {
        return Err(anyhow::anyhow!("GraphQL field errors: {errors:?}"));
    }

    let wire_command = ctx
        .result
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| anyhow::anyhow!("No transaction was parsed from the GraphQL mutation"))?;

    // Extract the inner zkApp command
    let zkapp_command = match &wire_command {
        MinaBaseUserCommandStableV2::ZkappCommand(cmd) => cmd.clone(),
        _ => return Err(anyhow::anyhow!("Expected ZkappCommand variant")),
    };

    // Extract the first proof from account updates
    let proof = extract_first_proof(&zkapp_command)?;

    Ok(ParsedZkappTransaction {
        wire_command,
        zkapp_command,
        proof,
    })
}

/// Convenience wrapper: read a GraphQL mutation file from disk and parse it.
pub fn parse_graphql_zkapp_file(path: &str) -> Result<ParsedZkappTransaction> {
    let graphql_str =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Read {path}: {e}"))?;
    parse_graphql_zkapp(&graphql_str)
}

/// Decode a standalone base64-encoded S-expression proof.
pub fn proof_from_b64_sexp(
    proof_sexp_b64: &str,
) -> Result<PicklesProofProofsVerified2ReprStableV2> {
    let sexp_bytes = general_purpose::STANDARD
        .decode(proof_sexp_b64.trim())
        .map_err(|e| anyhow::anyhow!("base64 decode proof: {e:?}"))?;

    let sexp = rsexp::from_slice(&sexp_bytes)
        .map_err(|e| anyhow::anyhow!("parse proof S-exp: {e:?}"))?;

    PicklesProofProofsVerified2ReprStableV2::of_sexp(&sexp)
        .map_err(|e| anyhow::anyhow!("S-exp -> proof decode: {e:?}"))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Walk account updates and return the first proof found.
fn extract_first_proof(
    zkapp: &MinaBaseZkappCommandTStableV1WireStableV1,
) -> Result<PicklesProofProofsVerified2ReprStableV2> {
    for update in zkapp.account_updates.iter() {
        if let MinaBaseControlStableV2::Proof(proof) = &update.elt.account_update.authorization {
            return Ok((*proof.clone()).into());
        }
    }
    Err(anyhow::anyhow!(
        "No proof found in any account update authorization"
    ))
}