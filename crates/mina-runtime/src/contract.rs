use ledger::Account;
use mina_p2p_messages::v2::{
    MinaBaseSignedCommandPayloadStableV2, MinaBaseSignedCommandStableV2,
    MinaBaseZkappCommandTStableV1WireStableV1,
};
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
    pub witness: Vec<String>,
    pub proofs_verified: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileCircuitResponse {
    pub circuit_id: ResourceId,
    pub circuit_digest: String,
    pub witness_size: u32,
    pub public_output_size: usize,
    /// Canonical Mina side-loaded VK (bin_prot bytes, base64) — the same
    /// `verificationKey.data` jsoo's `Program.compile()` returns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_key_base64: Option<String>,
    /// Mina account-level hash of the side-loaded VK (decimal field string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_key_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileProgramRequest {
    pub branches: Vec<CompileCircuitRequest>,
    /// A prover-key cache payload (base64) to restore from instead of
    /// compiling; a stale or corrupt payload silently falls back to a full
    /// compile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_bytes_base64: Option<String>,
    /// When set, the response carries the program's prover-key cache
    /// payload for the caller to persist.
    #[serde(default)]
    pub want_cache_bytes: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileProgramResponse {
    pub branches: Vec<CompileCircuitResponse>,
    /// The prover-key cache payload (base64), when requested and freshly
    /// compiled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_bytes_base64: Option<String>,
    /// Whether this program was restored from the supplied cache payload.
    #[serde(default)]
    pub restored_from_cache: bool,
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
    /// Mina transaction authorization proof (base64-encoded S-expression).
    /// This is the value expected by an account update's `authorization.proof`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_proof: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeptProofResponse {
    pub proof_id: ResourceId,
    pub app_state: Vec<String>,
    pub proof: O1jsWrapProofJson,
    /// Mina transaction authorization proof (base64-encoded S-expression).
    /// This is the value expected by an account update's `authorization.proof`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_proof: Option<String>,
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
#[serde(rename_all = "camelCase")]
pub struct SignZkappCommandRequest {
    pub private_key: String,
    pub network: NetworkId,
    pub command: MinaBaseZkappCommandTStableV1WireStableV1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedZkappCommandResponse {
    pub command: MinaBaseZkappCommandTStableV1WireStableV1,
    pub binprot_base64: String,
    pub signer_public_key: String,
    pub signed_account_updates: usize,
}

/// Seeds the in-process SRS or Lagrange-basis cache from an o1js `Cache`
/// entry payload (jsoo JSON format, base64 on the wire). `domain_log2`
/// absent seeds the SRS itself; present seeds a Lagrange basis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedSrsCacheRequest {
    pub curve: String,
    pub payload_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_log2: Option<u32>,
    /// Reads the compact binary layout instead of the o1js `Cache` JSON.
    /// It holds the same points in about a third of the bytes, but only
    /// this implementation understands it.
    #[serde(default)]
    pub raw: bool,
}

/// Exports the in-process SRS (`domain_log2` absent) or a Lagrange basis
/// (`domain_log2` present) as an o1js `Cache` entry payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSrsCacheRequest {
    pub curve: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_log2: Option<u32>,
    /// Writes the compact binary layout instead of the o1js `Cache` JSON.
    #[serde(default)]
    pub raw: bool,
}

/// The exported jsoo payload, base64 on the wire; `None` when the SRS or
/// basis has not been materialized in this process yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SrsCachePayloadResponse {
    pub payload_base64: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "input", rename_all = "camelCase")]
pub enum BackendRequest {
    GetInfo,
    CompileCircuit(CompileCircuitRequest),
    CompileProgram(CompileProgramRequest),
    ProgramCacheKey(CompileProgramRequest),
    SeedSrsCache(SeedSrsCacheRequest),
    ExportSrsCache(ExportSrsCacheRequest),
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
    SignZkappCommand(SignZkappCommandRequest),
    DropCircuit { circuit_id: ResourceId },
    DropProof { proof_id: ResourceId },
    DropLedger { ledger_id: ResourceId },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "output", rename_all = "camelCase")]
pub enum BackendResponse {
    Info(BackendInfo),
    CircuitCompiled(CompileCircuitResponse),
    ProgramCompiled(CompileProgramResponse),
    ProgramCacheKey(String),
    SrsCacheSeeded(bool),
    SrsCachePayload(SrsCachePayloadResponse),
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
    ZkappCommandSigned(SignedZkappCommandResponse),
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
