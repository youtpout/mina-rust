use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use binprot::BinProtWrite;
use ledger::scan_state::transaction_logic::{
    signed_command::{
        Body, Common, PaymentPayload, SignedCommand, SignedCommandPayload, StakeDelegationPayload,
    },
    transaction_union_payload::TransactionUnionPayload,
    Memo,
};
use mina_p2p_messages::v2::{
    MinaBaseSignatureStableV1, MinaBaseSignedCommandPayloadBodyStableV2,
    MinaBaseSignedCommandPayloadStableV2, MinaBaseSignedCommandStableV2,
    MinaBaseStakeDelegationStableV2,
};
use mina_signer::{Keypair, NonceMode, SecKey, Signer};

use crate::{
    contract::{NetworkId, SignTransactionRequest, SignatureNonceMode, SignedTransactionResponse},
    BackendError,
};

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

    let network = match request.network {
        NetworkId::Mainnet => mina_signer::NetworkId::MAINNET,
        NetworkId::Testnet => mina_signer::NetworkId::TESTNET,
    };
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
