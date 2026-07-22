use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use binprot::BinProtWrite;
use ledger::scan_state::transaction_logic::{
    signed_command::{
        Body, Common, PaymentPayload, SignedCommand, SignedCommandPayload, StakeDelegationPayload,
    },
    transaction_union_payload::TransactionUnionPayload,
    zkapp_command::{AuthorizationKind, Control, ZkAppCommand},
    zkapp_statement::TransactionCommitment,
    Memo,
};
use mina_p2p_messages::v2::{
    MinaBaseSignatureStableV1, MinaBaseSignedCommandPayloadBodyStableV2,
    MinaBaseSignedCommandPayloadStableV2, MinaBaseSignedCommandStableV2,
    MinaBaseStakeDelegationStableV2, MinaBaseZkappCommandTStableV1WireStableV1,
};
use mina_signer::{Keypair, NonceMode, SecKey, Signer};
use std::cell::Cell;

use crate::{
    contract::{
        NetworkId, SignTransactionRequest, SignZkappCommandRequest, SignatureNonceMode,
        SignedTransactionResponse, SignedZkappCommandResponse,
    },
    BackendError,
};

fn signer_network(network: NetworkId) -> mina_signer::NetworkId {
    match network {
        NetworkId::Mainnet => mina_signer::NetworkId::MAINNET,
        NetworkId::Testnet => mina_signer::NetworkId::TESTNET,
    }
}

fn convert_payload(
    payload: &MinaBaseSignedCommandPayloadStableV2,
) -> Result<SignedCommandPayload, BackendError> {
    let common = Common {
        fee: (&payload.common.fee).into(),
        fee_payer_pk: (&payload.common.fee_payer_pk)
            .try_into()
            .map_err(|error| BackendError::Transaction(format!("invalid fee payer: {error:?}")))?,
        nonce: (&payload.common.nonce).into(),
        valid_until: (&payload.common.valid_until).into(),
        memo: Memo::from(&payload.common.memo),
    };
    let body = match &payload.body {
        MinaBaseSignedCommandPayloadBodyStableV2::Payment(payment) => {
            Body::Payment(PaymentPayload {
                receiver_pk: (&payment.receiver_pk).try_into().map_err(|error| {
                    BackendError::Transaction(format!("invalid payment receiver: {error:?}"))
                })?,
                amount: payment.amount.clone().into(),
            })
        }
        MinaBaseSignedCommandPayloadBodyStableV2::StakeDelegation(
            MinaBaseStakeDelegationStableV2::SetDelegate { new_delegate },
        ) => Body::StakeDelegation(StakeDelegationPayload::SetDelegate {
            new_delegate: new_delegate.try_into().map_err(|error| {
                BackendError::Transaction(format!("invalid delegate: {error:?}"))
            })?,
        }),
    };
    Ok(SignedCommandPayload { common, body })
}

pub(crate) fn sign_transaction(
    request: SignTransactionRequest,
) -> Result<SignedTransactionResponse, BackendError> {
    let secret = SecKey::from_base58(&request.private_key)
        .map_err(|error| BackendError::Transaction(error.to_string()))?;
    let keypair =
        Keypair::try_from(secret).map_err(|error| BackendError::Transaction(error.to_string()))?;
    let payload = convert_payload(&request.payload)?;
    let signer_pk = keypair.public.into_compressed();
    if payload.common.fee_payer_pk != signer_pk {
        return Err(BackendError::Transaction(
            "the private key does not match the transaction fee payer".to_owned(),
        ));
    }

    let network = signer_network(request.network);
    let nonce_mode = match request.nonce_mode {
        SignatureNonceMode::Legacy => NonceMode::Legacy,
        SignatureNonceMode::Chunked => NonceMode::Chunked,
    };
    let payload_to_sign = TransactionUnionPayload::of_user_command_payload(&payload);
    let mut signer = mina_signer::create_legacy(network);
    let signature = signer.sign(&keypair, &payload_to_sign, nonce_mode);
    let signed = SignedCommand {
        payload,
        signer: signer_pk,
        signature,
    };
    let command = MinaBaseSignedCommandStableV2 {
        payload: request.payload,
        signer: (&signed.signer).into(),
        signature: MinaBaseSignatureStableV1::from(&signed.signature).into(),
    };
    let mut binprot = Vec::new();
    command
        .binprot_write(&mut binprot)
        .map_err(|error| BackendError::Transaction(error.to_string()))?;

    Ok(SignedTransactionResponse {
        command,
        binprot_base64: BASE64_STANDARD.encode(binprot),
    })
}

pub(crate) fn sign_zkapp_command(
    request: SignZkappCommandRequest,
) -> Result<SignedZkappCommandResponse, BackendError> {
    let secret = SecKey::from_base58(&request.private_key)
        .map_err(|error| BackendError::Transaction(error.to_string()))?;
    let keypair =
        Keypair::try_from(secret).map_err(|error| BackendError::Transaction(error.to_string()))?;
    let signer_public_key = keypair.public.into_compressed();
    let mut command: ZkAppCommand = (&request.command)
        .try_into()
        .map_err(|error| BackendError::Transaction(format!("invalid zkApp command: {error:?}")))?;

    if command.fee_payer.body.public_key != signer_public_key {
        return Err(BackendError::Transaction(
            "the private key does not match the zkApp fee payer".to_owned(),
        ));
    }

    command.account_updates.ensure_hashed();
    let memo_hash = command.memo.hash();
    let account_updates_hash = command.account_updates_hash();
    let fee_payer_hash =
        ledger::scan_state::transaction_logic::zkapp_command::AccountUpdate::of_fee_payer(
            command.fee_payer.clone(),
        )
        .digest();
    let commitment = TransactionCommitment::create(account_updates_hash);
    let full_commitment = commitment.create_complete(memo_hash, fee_payer_hash);

    let mut signer = mina_signer::create_kimchi(signer_network(request.network));
    let commitment_signature = signer.sign(&keypair, &commitment, NonceMode::Chunked);
    let full_commitment_signature = signer.sign(&keypair, &full_commitment, NonceMode::Chunked);
    command.fee_payer.authorization = full_commitment_signature.clone();

    let signed_account_updates = Cell::new(0usize);
    command.account_updates = command.account_updates.map_to(|account_update| {
        if account_update.body.public_key == signer_public_key
            && matches!(
                account_update.body.authorization_kind,
                AuthorizationKind::Signature
            )
        {
            signed_account_updates.set(signed_account_updates.get() + 1);
            let authorization = if account_update.body.use_full_commitment {
                full_commitment_signature.clone()
            } else {
                commitment_signature.clone()
            };
            return ledger::scan_state::transaction_logic::zkapp_command::AccountUpdate {
                body: account_update.body.clone(),
                authorization: Control::Signature(authorization),
            };
        }
        account_update.clone()
    });

    let stable: MinaBaseZkappCommandTStableV1WireStableV1 = (&command).into();
    let binprot_base64 = stable
        .to_base64()
        .map_err(|error| BackendError::Transaction(error.to_string()))?;
    Ok(SignedZkappCommandResponse {
        command: stable,
        binprot_base64,
        signer_public_key: signer_public_key.into_address(),
        signed_account_updates: signed_account_updates.get(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger::{
        scan_state::{
            currency::{Amount, Fee, Nonce, Sgn, Signed, Slot},
            transaction_logic::zkapp_command::{
                Account, AccountPreconditions, AccountUpdate, Actions, Body as ZkappBody,
                CallForest, Events, FeePayer, FeePayerBody, MayUseToken, Numeric, Preconditions,
                Tree, Update, WithStackHash, ZkAppPreconditions,
            },
        },
        MutableFp, TokenId,
    };
    use mina_curves::pasta::Fp;
    use mina_signer::Signature;

    const PRIVATE_KEY: &str = "EKFPQBAbjYkjM6p6fEaZAzufQgQs3spvUw1Uyq2Ghta81cpKrfGg";

    fn unsigned_zkapp_command(keypair: &Keypair) -> ZkAppCommand {
        let public_key = keypair.public.into_compressed();
        let fee_payer = FeePayer {
            body: FeePayerBody {
                public_key: public_key.clone(),
                fee: Fee::from_u64(1_000_000),
                valid_until: Some(Slot::from_u32(100_000)),
                nonce: Nonce::from_u32(0),
            },
            authorization: Signature::dummy(),
        };
        let account_update = AccountUpdate {
            body: ZkappBody {
                public_key,
                token_id: TokenId::default(),
                update: Update::noop(),
                balance_change: Signed {
                    magnitude: Amount::from_u64(0),
                    sgn: Sgn::Pos,
                },
                increment_nonce: false,
                events: Events::empty(),
                actions: Actions::empty(),
                call_data: Fp::from(0u64),
                preconditions: Preconditions {
                    network: ZkAppPreconditions::accept(),
                    account: AccountPreconditions(Account::accept()),
                    valid_while: Numeric::Ignore,
                },
                use_full_commitment: false,
                implicit_account_creation_fee: false,
                may_use_token: MayUseToken::No,
                authorization_kind: AuthorizationKind::Signature,
            },
            authorization: Control::Signature(Signature::dummy()),
        };
        let account_updates = CallForest(vec![WithStackHash {
            elt: Tree {
                account_update,
                account_update_digest: MutableFp::new(Fp::from(0u64)),
                calls: CallForest::new(),
            },
            stack_hash: MutableFp::new(Fp::from(0u64)),
        }]);
        account_updates.ensure_hashed();
        ZkAppCommand {
            fee_payer,
            account_updates,
            memo: Memo::empty(),
        }
    }

    #[test]
    fn signs_fee_payer_and_matching_account_update() {
        let secret = SecKey::from_base58(PRIVATE_KEY).expect("valid private key");
        let keypair = Keypair::try_from(secret).expect("valid keypair");
        let command = unsigned_zkapp_command(&keypair);
        let stable: MinaBaseZkappCommandTStableV1WireStableV1 = (&command).into();

        let response = sign_zkapp_command(SignZkappCommandRequest {
            private_key: PRIVATE_KEY.to_owned(),
            network: NetworkId::Testnet,
            command: stable,
        })
        .expect("zkApp command signing must succeed");

        assert_eq!(response.signed_account_updates, 1);
        assert!(!response.binprot_base64.is_empty());
        assert_eq!(response.signer_public_key, keypair.public.into_address());

        let signed: ZkAppCommand = (&response.command)
            .try_into()
            .expect("signed command must decode");
        signed.account_updates.ensure_hashed();
        let commitment = TransactionCommitment::create(signed.account_updates_hash());
        let fee_payer_hash = AccountUpdate::of_fee_payer(signed.fee_payer.clone()).digest();
        let full_commitment = commitment.create_complete(signed.memo.hash(), fee_payer_hash);
        let mut signer = mina_signer::create_kimchi(mina_signer::NetworkId::TESTNET);

        assert!(signer.verify(
            &signed.fee_payer.authorization,
            &keypair.public,
            &full_commitment
        ));
        let authorization = &signed.account_updates.0[0].elt.account_update.authorization;
        let Control::Signature(signature) = authorization else {
            panic!("account update must contain a signature");
        };
        assert!(signer.verify(signature, &keypair.public, &commitment));
    }
}
