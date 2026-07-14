use ledger::Account;
use mina_p2p_messages::v2::{MinaBaseSignedCommandPayloadStableV2, MinaBaseSignedCommandStableV2};
use pickles::{api::O1jsWrapProofJson, recorded::RecordedCircuit};
use serde::{Deserialize, Serialize};

use crate::ResourceId;

pub const BACKEND_API_VERSION: u16 = 1;
pub const WIRE_FORMAT_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Versioned<T> {
    pub version: u16,
    pub payload: T,
}

impl<T> Versioned<T> {
    pub const fn current(payload: T) -> Self {
        Self {
            version: WIRE_FORMAT_VERSION,
            payload,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendInfo {
    pub backend_api_version: u16,
    pub wire_format_version: u16,
    pub mina_rust_version: String,
    pub proof_system: String,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileCircuitRequest {
    pub circuit: RecordedCircuit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileCircuitResponse {
    pub circuit_id: ResourceId,
    pub circuit_digest: String,
    pub witness_size: u32,
    pub public_output_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProveCircuitRequest {
    pub circuit_id: ResourceId,
    pub witness: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProveCircuitN1OverRequest {
    pub circuit_id: ResourceId,
    pub previous_proof_id: ResourceId,
    pub witness: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProveCircuitN2OverRequest {
    pub circuit_id: ResourceId,
    pub first_proof_id: ResourceId,
    pub second_proof_id: ResourceId,
    pub witness: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofResponse {
    pub app_state: Vec<String>,
    pub proof: O1jsWrapProofJson,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeptProofResponse {
    pub proof_id: ResourceId,
    pub app_state: Vec<String>,
    pub proof: O1jsWrapProofJson,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecursiveProofResponse {
    pub proof_id: ResourceId,
    pub app_state: Vec<String>,
    pub proof: O1jsWrapProofJson,
    pub challenge_polynomial_commitment: (String, String),
    pub old_bulletproof_challenges: Vec<String>,
    pub dlog_plonk_index: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecursiveN2ProofResponse {
    pub app_state: Vec<String>,
    pub proof: O1jsWrapProofJson,
    pub challenge_polynomial_commitments: Vec<(String, String)>,
    pub old_bulletproof_challenges: Vec<Vec<String>>,
    pub dlog_plonk_index: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofRequest {
    pub app_state: Vec<String>,
    pub proof: O1jsWrapProofJson,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRecursiveProofRequest {
    pub app_state: Vec<String>,
    pub proof: O1jsWrapProofJson,
    pub challenge_polynomial_commitments: Vec<(String, String)>,
    pub old_bulletproof_challenges: Vec<Vec<String>>,
    pub dlog_plonk_index: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofResponse {
    pub valid: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLedgerRequest {
    pub depth: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerResponse {
    pub ledger_id: ResourceId,
    pub root_hash: String,
    pub account_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerRootRequest {
    pub ledger_id: ResourceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerRootResponse {
    pub root_hash: String,
    pub account_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerGetAccountRequest {
    pub ledger_id: ResourceId,
    pub public_key: String,
    pub token_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerAccountResponse {
    pub account: Option<Account>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerSetAccountRequest {
    pub ledger_id: ResourceId,
    pub account: Account,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkId {
    Mainnet,
    Testnet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignatureNonceMode {
    Legacy,
    Chunked,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTransactionRequest {
    pub private_key: String,
    pub network: NetworkId,
    pub nonce_mode: SignatureNonceMode,
    pub payload: MinaBaseSignedCommandPayloadStableV2,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTransactionResponse {
    pub command: MinaBaseSignedCommandStableV2,
    pub binprot_base64: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "input", rename_all = "camelCase")]
pub enum BackendRequest {
    GetInfo,
    CompileCircuit(CompileCircuitRequest),
    ProveCircuit(ProveCircuitRequest),
    ProveCircuitKeep(ProveCircuitRequest),
    ProveCircuitN1Over(ProveCircuitN1OverRequest),
    ProveCircuitN2Over(ProveCircuitN2OverRequest),
    VerifyProof(VerifyProofRequest),
    VerifyRecursiveProof(VerifyRecursiveProofRequest),
    CreateLedger(CreateLedgerRequest),
    LedgerRoot(LedgerRootRequest),
    LedgerGetAccount(LedgerGetAccountRequest),
    LedgerSetAccount(LedgerSetAccountRequest),
    SignTransaction(SignTransactionRequest),
    DropCircuit { circuit_id: ResourceId },
    DropProof { proof_id: ResourceId },
    DropLedger { ledger_id: ResourceId },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "output", rename_all = "camelCase")]
pub enum BackendResponse {
    Info(BackendInfo),
    CircuitCompiled(CompileCircuitResponse),
    ProofCreated(ProofResponse),
    ProofKept(KeptProofResponse),
    RecursiveProofCreated(RecursiveProofResponse),
    RecursiveN2ProofCreated(RecursiveN2ProofResponse),
    ProofVerified(VerifyProofResponse),
    LedgerCreated(LedgerResponse),
    LedgerRoot(LedgerRootResponse),
    LedgerAccount(LedgerAccountResponse),
    LedgerAccountSet(LedgerRootResponse),
    TransactionSigned(SignedTransactionResponse),
    ResourceDropped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "value", rename_all = "camelCase")]
pub enum WireResponse {
    Ok(BackendResponse),
    Error(WireError),
}
