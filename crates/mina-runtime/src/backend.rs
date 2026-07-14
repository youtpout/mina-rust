use std::panic::{catch_unwind, AssertUnwindSafe};

use ledger::{AccountId, BaseLedger, Database, TokenId, V2};
use mina_curves::pasta::Fp;
use mina_signer::CompressedPubKey;
use pickles::{
    api::MinaWrapProof,
    recorded::{
        prove_recorded_base_case, prove_recorded_base_case_keep, prove_recorded_n1_over_keep,
        RecordedCircuit, RecordedProofHandle,
    },
    verify::{verify_side_loaded_base_case, verify_side_loaded_with_step_vk},
};
use sha2::{Digest, Sha256};

use crate::{
    contract::*, transaction::sign_transaction, BackendConfig, ResourceError, ResourceStore,
};

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("wire format version {actual} is unsupported; expected {expected}")]
    Version { expected: u16, actual: u16 },
    #[error("invalid field element: {0}")]
    Field(String),
    #[error("invalid recorded circuit: {0}")]
    Circuit(String),
    #[error("Pickles proving failed: {0}")]
    Proving(String),
    #[error("transaction operation failed: {0}")]
    Transaction(String),
    #[error("Ledger operation failed: {0}")]
    Ledger(String),
    #[error(transparent)]
    Resource(#[from] ResourceError),
    #[error("wire serialization failed: {0}")]
    Serialization(String),
}

impl BackendError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Version { .. } => "unsupported_version",
            Self::Field(_) => "invalid_field",
            Self::Circuit(_) => "invalid_circuit",
            Self::Proving(_) => "proving_failed",
            Self::Transaction(_) => "transaction_failed",
            Self::Ledger(_) => "ledger_failed",
            Self::Resource(ResourceError::LimitReached { .. }) => "resource_limit",
            Self::Resource(ResourceError::NotFound { .. }) => "resource_not_found",
            Self::Resource(ResourceError::Poisoned) => "resource_lock_poisoned",
            Self::Serialization(_) => "serialization_failed",
        }
    }

    fn wire(&self) -> WireError {
        WireError {
            code: self.code().to_owned(),
            message: self.to_string(),
        }
    }
}

pub struct Backend {
    circuits: ResourceStore<RecordedCircuit>,
    proofs: ResourceStore<RecordedProofHandle>,
    ledgers: ResourceStore<Database<V2>>,
}

impl Default for Backend {
    fn default() -> Self {
        Self::new(BackendConfig::default())
    }
}

impl Backend {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            circuits: ResourceStore::new(config.max_resources),
            proofs: ResourceStore::new(config.max_resources),
            ledgers: ResourceStore::new(config.max_resources),
        }
    }

    pub fn info(&self) -> BackendInfo {
        BackendInfo {
            backend_api_version: BACKEND_API_VERSION,
            wire_format_version: WIRE_FORMAT_VERSION,
            mina_rust_version: env!("CARGO_PKG_VERSION").to_owned(),
            proof_system: "proof-systems/pickle-rs".to_owned(),
            capabilities: [
                "ledger-v1",
                "mina-signed-command-v2",
                "recorded-circuit-v1",
                "pickles-base-proof-v1",
                "pickles-kept-base-proof-v1",
                "pickles-recursive-n1-v1",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }

    pub fn compile_circuit(
        &self,
        request: CompileCircuitRequest,
    ) -> Result<CompileCircuitResponse, BackendError> {
        request
            .circuit
            .validate()
            .map_err(|error| BackendError::Circuit(format!("{error:?}")))?;
        let encoded = serde_json::to_vec(&request.circuit)
            .map_err(|error| BackendError::Serialization(error.to_string()))?;
        let digest = hex::encode(Sha256::digest(encoded));
        let witness_size = request.circuit.aux_count;
        let public_output_size = request.circuit.output.len();
        let circuit_id = self.circuits.insert(request.circuit)?;
        Ok(CompileCircuitResponse {
            circuit_id,
            circuit_digest: digest,
            witness_size,
            public_output_size,
        })
    }

    pub fn prove_circuit(
        &self,
        request: ProveCircuitRequest,
    ) -> Result<ProofResponse, BackendError> {
        let circuit = self.circuits.with(request.circuit_id, Clone::clone)?;
        let witness = parse_fields(&request.witness)?;
        let proved = catch_unwind(AssertUnwindSafe(|| {
            prove_recorded_base_case(circuit, witness)
        }))
        .map_err(|_| BackendError::Proving("the Pickles prover panicked".to_owned()))?
        .map_err(|error| BackendError::Proving(format!("{error:?}")))?;
        Ok(ProofResponse {
            app_state: fields_to_strings(&proved.app_state),
            proof: proved.proof.to_o1js_json_value(),
        })
    }

    pub fn verify_proof(
        &self,
        request: VerifyProofRequest,
    ) -> Result<VerifyProofResponse, BackendError> {
        let app_state = parse_fields(&request.app_state)?;
        let proof = match MinaWrapProof::from_o1js_json_value(request.proof) {
            Ok(proof) => proof,
            Err(error) => {
                return Ok(VerifyProofResponse {
                    valid: false,
                    reason: Some(format!("{error:?}")),
                });
            }
        };
        Ok(match verify_side_loaded_base_case(&app_state, &proof) {
            Ok(_) => VerifyProofResponse {
                valid: true,
                reason: None,
            },
            Err(error) => VerifyProofResponse {
                valid: false,
                reason: Some(format!("{error:?}")),
            },
        })
    }

    pub fn prove_circuit_keep(
        &self,
        request: ProveCircuitRequest,
    ) -> Result<KeptProofResponse, BackendError> {
        let circuit = self.circuits.with(request.circuit_id, Clone::clone)?;
        let witness = parse_fields(&request.witness)?;
        let handle = catch_unwind(AssertUnwindSafe(|| {
            prove_recorded_base_case_keep(circuit, witness)
        }))
        .map_err(|_| BackendError::Proving("the Pickles prover panicked".to_owned()))?
        .map_err(|error| BackendError::Proving(format!("{error:?}")))?;
        let envelope = handle.to_recorded_proof();
        let proof_id = self.proofs.insert(handle)?;
        Ok(KeptProofResponse {
            proof_id,
            app_state: fields_to_strings(&envelope.app_state),
            proof: envelope.proof.to_o1js_json_value(),
        })
    }

    pub fn prove_circuit_n1_over(
        &self,
        request: ProveCircuitN1OverRequest,
    ) -> Result<RecursiveProofResponse, BackendError> {
        let circuit = self.circuits.with(request.circuit_id, Clone::clone)?;
        let witness = parse_fields(&request.witness)?;
        let handle = self
            .proofs
            .with(request.previous_proof_id, |previous| {
                catch_unwind(AssertUnwindSafe(|| {
                    prove_recorded_n1_over_keep(previous, circuit, witness)
                }))
            })?
            .map_err(|_| BackendError::Proving("the Pickles prover panicked".to_owned()))?
            .map_err(|error| BackendError::Proving(format!("{error:?}")))?;
        let proved = handle
            .to_recorded_n1_proof()
            .expect("N1 proving always returns a recursive handle");
        let proof_id = self.proofs.insert(handle)?;
        Ok(RecursiveProofResponse {
            proof_id,
            app_state: fields_to_strings(&proved.app_state),
            proof: proved.proof.to_o1js_json_value(),
            challenge_polynomial_commitment: point_to_strings(
                proved.challenge_polynomial_commitment,
            ),
            old_bulletproof_challenges: fields_to_strings(&proved.old_bulletproof_challenges),
            dlog_plonk_index: proved
                .dlog_plonk_index
                .into_iter()
                .map(point_to_strings)
                .collect(),
        })
    }

    pub fn verify_recursive_proof(
        &self,
        request: VerifyRecursiveProofRequest,
    ) -> Result<VerifyProofResponse, BackendError> {
        let app_state = parse_fields(&request.app_state)?;
        let dlog_plonk_index = parse_points(&request.dlog_plonk_index)?;
        let commitments = parse_points(&request.challenge_polynomial_commitments)?;
        let challenges = request
            .old_bulletproof_challenges
            .iter()
            .map(|values| parse_fields(values))
            .collect::<Result<Vec<_>, _>>()?;
        let proof = match MinaWrapProof::from_o1js_json_value(request.proof) {
            Ok(proof) => proof,
            Err(error) => {
                return Ok(VerifyProofResponse {
                    valid: false,
                    reason: Some(format!("{error:?}")),
                });
            }
        };
        Ok(
            match verify_side_loaded_with_step_vk(
                &app_state,
                Some(&dlog_plonk_index),
                &commitments,
                &challenges,
                &proof,
            ) {
                Ok(_) => VerifyProofResponse {
                    valid: true,
                    reason: None,
                },
                Err(error) => VerifyProofResponse {
                    valid: false,
                    reason: Some(format!("{error:?}")),
                },
            },
        )
    }

    pub fn create_ledger(
        &self,
        request: CreateLedgerRequest,
    ) -> Result<LedgerResponse, BackendError> {
        if request.depth == 0 || request.depth > 35 {
            return Err(BackendError::Ledger(format!(
                "Ledger depth {} is outside 1..=35",
                request.depth
            )));
        }
        let mut ledger = Database::create(request.depth);
        let root_hash = ledger.root_hash().to_string();
        let ledger_id = self.ledgers.insert(ledger)?;
        Ok(LedgerResponse {
            ledger_id,
            root_hash,
            account_count: 0,
        })
    }

    pub fn ledger_root(
        &self,
        request: LedgerRootRequest,
    ) -> Result<LedgerRootResponse, BackendError> {
        self.ledgers
            .with(request.ledger_id, |ledger| {
                let mut ledger = ledger.clone();
                LedgerRootResponse {
                    root_hash: ledger.root_hash().to_string(),
                    account_count: ledger.num_accounts(),
                }
            })
            .map_err(Into::into)
    }

    pub fn ledger_get_account(
        &self,
        request: LedgerGetAccountRequest,
    ) -> Result<LedgerAccountResponse, BackendError> {
        let public_key = CompressedPubKey::from_address(&request.public_key)
            .map_err(|error| BackendError::Ledger(error.to_string()))?;
        let token_id = match request.token_id {
            Some(token_id) => TokenId(
                token_id
                    .parse::<Fp>()
                    .map_err(|_| BackendError::Field(token_id))?,
            ),
            None => TokenId::default(),
        };
        let account_id = AccountId::new(public_key, token_id);
        self.ledgers
            .with(request.ledger_id, |ledger| {
                let account = ledger
                    .location_of_account(&account_id)
                    .and_then(|address| ledger.get(address))
                    .map(|account| *account);
                LedgerAccountResponse { account }
            })
            .map_err(Into::into)
    }

    pub fn ledger_set_account(
        &self,
        request: LedgerSetAccountRequest,
    ) -> Result<LedgerRootResponse, BackendError> {
        let response = self.ledgers.with(request.ledger_id, |ledger| {
            let mut ledger = ledger.clone();
            let account_id = request.account.id();
            if let Some(address) = ledger.location_of_account(&account_id) {
                ledger.set(address, Box::new(request.account));
            } else {
                ledger
                    .get_or_create_account(account_id, request.account)
                    .map_err(|error| BackendError::Ledger(format!("{error:?}")))?;
            }
            Ok(LedgerRootResponse {
                root_hash: ledger.root_hash().to_string(),
                account_count: ledger.num_accounts(),
            })
        })?;
        response
    }

    pub fn execute(
        &self,
        request: Versioned<BackendRequest>,
    ) -> Result<Versioned<BackendResponse>, BackendError> {
        if request.version != WIRE_FORMAT_VERSION {
            return Err(BackendError::Version {
                expected: WIRE_FORMAT_VERSION,
                actual: request.version,
            });
        }
        let response = match request.payload {
            BackendRequest::GetInfo => BackendResponse::Info(self.info()),
            BackendRequest::CompileCircuit(request) => {
                BackendResponse::CircuitCompiled(self.compile_circuit(request)?)
            }
            BackendRequest::ProveCircuit(request) => {
                BackendResponse::ProofCreated(self.prove_circuit(request)?)
            }
            BackendRequest::ProveCircuitKeep(request) => {
                BackendResponse::ProofKept(self.prove_circuit_keep(request)?)
            }
            BackendRequest::ProveCircuitN1Over(request) => {
                BackendResponse::RecursiveProofCreated(self.prove_circuit_n1_over(request)?)
            }
            BackendRequest::VerifyProof(request) => {
                BackendResponse::ProofVerified(self.verify_proof(request)?)
            }
            BackendRequest::VerifyRecursiveProof(request) => {
                BackendResponse::ProofVerified(self.verify_recursive_proof(request)?)
            }
            BackendRequest::CreateLedger(request) => {
                BackendResponse::LedgerCreated(self.create_ledger(request)?)
            }
            BackendRequest::LedgerRoot(request) => {
                BackendResponse::LedgerRoot(self.ledger_root(request)?)
            }
            BackendRequest::LedgerGetAccount(request) => {
                BackendResponse::LedgerAccount(self.ledger_get_account(request)?)
            }
            BackendRequest::LedgerSetAccount(request) => {
                BackendResponse::LedgerAccountSet(self.ledger_set_account(request)?)
            }
            BackendRequest::SignTransaction(request) => {
                BackendResponse::TransactionSigned(sign_transaction(request)?)
            }
            BackendRequest::DropCircuit { circuit_id } => {
                self.circuits.remove(circuit_id)?;
                BackendResponse::ResourceDropped
            }
            BackendRequest::DropProof { proof_id } => {
                self.proofs.remove(proof_id)?;
                BackendResponse::ResourceDropped
            }
            BackendRequest::DropLedger { ledger_id } => {
                self.ledgers.remove(ledger_id)?;
                BackendResponse::ResourceDropped
            }
        };
        Ok(Versioned::current(response))
    }

    pub fn execute_json(&self, request: &str) -> String {
        let result = serde_json::from_str::<Versioned<BackendRequest>>(request)
            .map_err(|error| BackendError::Serialization(error.to_string()))
            .and_then(|request| self.execute(request))
            .map(|response| WireResponse::Ok(response.payload))
            .unwrap_or_else(|error| WireResponse::Error(error.wire()));
        serde_json::to_string(&Versioned::current(result)).unwrap_or_else(|error| {
            serde_json::json!({
                "version": WIRE_FORMAT_VERSION,
                "payload": {
                    "status": "error",
                    "value": {
                        "code": "serialization_failed",
                        "message": error.to_string(),
                    }
                }
            })
            .to_string()
        })
    }
}

fn parse_fields(fields: &[String]) -> Result<Vec<Fp>, BackendError> {
    fields
        .iter()
        .map(|field| {
            field
                .parse::<Fp>()
                .map_err(|_| BackendError::Field(field.clone()))
        })
        .collect()
}

fn fields_to_strings(fields: &[Fp]) -> Vec<String> {
    fields.iter().map(ToString::to_string).collect()
}

fn parse_points(points: &[(String, String)]) -> Result<Vec<(Fp, Fp)>, BackendError> {
    points
        .iter()
        .map(|(x, y)| Ok((parse_field(x)?, parse_field(y)?)))
        .collect()
}

fn parse_field(field: &str) -> Result<Fp, BackendError> {
    field
        .parse::<Fp>()
        .map_err(|_| BackendError::Field(field.to_owned()))
}

fn point_to_strings((x, y): (Fp, Fp)) -> (String, String) {
    (x.to_string(), y.to_string())
}

#[cfg(test)]
mod tests {
    use ledger::{
        scan_state::{
            currency::{Amount, Balance, Fee, Nonce},
            transaction_logic::{
                signed_command::{Body, PaymentPayload, SignedCommand, SignedCommandPayload},
                Memo,
            },
        },
        Account,
    };
    use mina_curves::pasta::Fq;
    use mina_p2p_messages::v2::MinaBaseSignedCommandStableV2;
    use mina_signer::{Keypair, SecKey, Signature};
    use pickles::recorded::{LinComb, RecordedConstraint};

    use super::*;

    fn square_circuit() -> RecordedCircuit {
        RecordedCircuit {
            aux_count: 2,
            output: vec![LinComb::var(1)],
            constraints: vec![RecordedConstraint::Square {
                v: LinComb::var(0),
                square: LinComb::var(1),
            }],
        }
    }

    #[test]
    fn versioned_json_dispatch_and_ledger_lifecycle() {
        let backend = Backend::default();
        let request = serde_json::to_string(&Versioned::current(BackendRequest::CreateLedger(
            CreateLedgerRequest { depth: 20 },
        )))
        .unwrap();
        let response: Versioned<WireResponse> =
            serde_json::from_str(&backend.execute_json(&request)).unwrap();
        assert_eq!(response.version, WIRE_FORMAT_VERSION);
        let WireResponse::Ok(BackendResponse::LedgerCreated(created)) = response.payload else {
            panic!("unexpected backend response")
        };
        assert_eq!(created.account_count, 0);
        assert!(!created.root_hash.is_empty());

        let root = backend
            .ledger_root(LedgerRootRequest {
                ledger_id: created.ledger_id,
            })
            .unwrap();
        assert_eq!(root.root_hash, created.root_hash);

        let key = CompressedPubKey::from_address(
            "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
        )
        .unwrap();
        let account = Account::create_with(
            AccountId::new(key.clone(), TokenId::default()),
            Balance::from_u64(42),
        );
        let changed = backend
            .ledger_set_account(LedgerSetAccountRequest {
                ledger_id: created.ledger_id,
                account: account.clone(),
            })
            .unwrap();
        assert_eq!(changed.account_count, 1);
        assert_ne!(changed.root_hash, created.root_hash);
        assert_eq!(
            backend
                .ledger_get_account(LedgerGetAccountRequest {
                    ledger_id: created.ledger_id,
                    public_key: key.into_address(),
                    token_id: None,
                })
                .unwrap()
                .account,
            Some(account)
        );
    }

    #[test]
    fn rejects_unknown_wire_versions_with_a_stable_code() {
        let error = Backend::default()
            .execute(Versioned {
                version: 99,
                payload: BackendRequest::GetInfo,
            })
            .unwrap_err();
        assert_eq!(error.code(), "unsupported_version");
    }

    #[test]
    fn recorded_pickles_proof_round_trips_through_contract() {
        let backend = Backend::default();
        let compiled = backend
            .compile_circuit(CompileCircuitRequest {
                circuit: square_circuit(),
            })
            .unwrap();
        let proof = backend
            .prove_circuit(ProveCircuitRequest {
                circuit_id: compiled.circuit_id,
                witness: vec!["6".to_owned(), "36".to_owned()],
            })
            .unwrap();
        assert_eq!(proof.app_state, ["36"]);
        assert!(
            backend
                .verify_proof(VerifyProofRequest {
                    app_state: proof.app_state.clone(),
                    proof: proof.proof.clone(),
                })
                .unwrap()
                .valid
        );

        let mut wrong_state = proof.app_state;
        wrong_state[0] = "35".to_owned();
        assert!(
            !backend
                .verify_proof(VerifyProofRequest {
                    app_state: wrong_state,
                    proof: proof.proof,
                })
                .unwrap()
                .valid
        );
    }

    #[test]
    fn retained_proofs_drive_and_verify_a_chained_recursive_n1_program() {
        let backend = Backend::default();
        let compiled = backend
            .compile_circuit(CompileCircuitRequest {
                circuit: square_circuit(),
            })
            .unwrap();
        let base = backend
            .prove_circuit_keep(ProveCircuitRequest {
                circuit_id: compiled.circuit_id,
                witness: vec!["6".to_owned(), "36".to_owned()],
            })
            .unwrap();
        let first = backend
            .prove_circuit_n1_over(ProveCircuitN1OverRequest {
                circuit_id: compiled.circuit_id,
                previous_proof_id: base.proof_id,
                witness: vec!["7".to_owned(), "49".to_owned()],
            })
            .unwrap();
        assert_eq!(first.app_state, ["49"]);
        assert!(
            backend
                .verify_recursive_proof(VerifyRecursiveProofRequest {
                    app_state: first.app_state.clone(),
                    proof: first.proof.clone(),
                    challenge_polynomial_commitments: vec![first.challenge_polynomial_commitment,],
                    old_bulletproof_challenges: vec![first.old_bulletproof_challenges.clone()],
                    dlog_plonk_index: first.dlog_plonk_index.clone(),
                })
                .unwrap()
                .valid
        );
        let second = backend
            .prove_circuit_n1_over(ProveCircuitN1OverRequest {
                circuit_id: compiled.circuit_id,
                previous_proof_id: first.proof_id,
                witness: vec!["8".to_owned(), "64".to_owned()],
            })
            .unwrap();
        assert_eq!(second.app_state, ["64"]);
        assert!(
            backend
                .verify_recursive_proof(VerifyRecursiveProofRequest {
                    app_state: second.app_state,
                    proof: second.proof,
                    challenge_polynomial_commitments: vec![second.challenge_polynomial_commitment,],
                    old_bulletproof_challenges: vec![second.old_bulletproof_challenges],
                    dlog_plonk_index: second.dlog_plonk_index,
                })
                .unwrap()
                .valid
        );
        assert!(backend.proofs.remove(base.proof_id).is_ok());
        assert!(backend.proofs.remove(first.proof_id).is_ok());
        assert!(backend.proofs.remove(second.proof_id).is_ok());
        assert!(matches!(
            backend.proofs.remove(base.proof_id),
            Err(ResourceError::NotFound { .. })
        ));
    }

    #[test]
    fn signs_and_encodes_a_mina_payment() {
        const PRIVATE_KEY: &str = "EKFPQBAbjYkjM6p6fEaZAzufQgQs3spvUw1Uyq2Ghta81cpKrfGg";
        let keypair = Keypair::try_from(SecKey::from_base58(PRIVATE_KEY).unwrap()).unwrap();
        let public_key = keypair.public.into_compressed();
        let payload = SignedCommandPayload::create(
            Fee::from_u64(1_000_000),
            public_key.clone(),
            Nonce::from_u32(0),
            None,
            Memo::dummy(),
            Body::Payment(PaymentPayload {
                receiver_pk: public_key.clone(),
                amount: Amount::from_u64(2_000_000),
            }),
        );
        let placeholder = SignedCommand {
            payload,
            signer: public_key,
            signature: Signature::new(Fp::from(0), Fq::from(0)),
        };
        let stable: MinaBaseSignedCommandStableV2 = (&placeholder).into();

        let response = crate::transaction::sign_transaction(SignTransactionRequest {
            private_key: PRIVATE_KEY.to_owned(),
            network: NetworkId::Testnet,
            nonce_mode: SignatureNonceMode::Legacy,
            payload: stable.payload,
        })
        .unwrap();
        assert!(!response.binprot_base64.is_empty());
        let signed = SignedCommand::try_from(&response.command).unwrap();
        assert_ne!(signed.signature, placeholder.signature);
        assert_eq!(signed.signer, placeholder.signer);
    }
}
