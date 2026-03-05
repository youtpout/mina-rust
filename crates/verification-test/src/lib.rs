use serde::Deserialize;
use serde_json;

// ---------------------------------------------------------------------------
// Serde-deserializable intermediate types (camelCase JSON -> Rust)
// These mirror the InputGraphQL* types but with serde support.
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonZkappCommand {
    pub fee_payer: JsonFeePayer,
    pub account_updates: Vec<JsonAccountUpdate>,
    pub memo: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonFeePayer {
    pub body: JsonFeePayerBody,
    pub authorization: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonFeePayerBody {
    pub public_key: String,
    pub fee: String,
    pub valid_until: Option<String>,
    pub nonce: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonAccountUpdate {
    pub body: JsonAccountUpdateBody,
    pub authorization: JsonAuthorization,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonAuthorization {
    pub proof: Option<String>,
    pub signature: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonAccountUpdateBody {
    pub public_key: String,
    pub token_id: String,
    pub update: JsonUpdate,
    pub balance_change: JsonBalanceChange,
    pub increment_nonce: bool,
    pub events: Vec<Vec<String>>,
    pub actions: Vec<Vec<String>>,
    pub call_data: String,
    pub call_depth: i32,
    pub preconditions: JsonPreconditions,
    pub use_full_commitment: bool,
    pub implicit_account_creation_fee: bool,
    pub may_use_token: JsonMayUseToken,
    pub authorization_kind: JsonAuthorizationKind,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonUpdate {
    pub app_state: Vec<Option<String>>,
    pub delegate: Option<String>,
    pub verification_key: Option<JsonVerificationKey>,
    pub permissions: Option<JsonPermissions>,
    pub zkapp_uri: Option<String>,
    pub token_symbol: Option<String>,
    pub timing: Option<JsonTiming>,
    pub voting_for: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonVerificationKey {
    pub data: String,
    pub hash: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonPermissions {
    pub edit_state: String,
    pub access: String,
    pub send: String,
    pub receive: String,
    pub set_delegate: String,
    pub set_permissions: String,
    pub set_verification_key: JsonSetVerificationKeyPermissions,
    pub set_zkapp_uri: String,
    pub edit_action_state: String,
    pub set_token_symbol: String,
    pub set_timing: String,
    pub set_voting_for: String,
    pub increment_nonce: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonSetVerificationKeyPermissions {
    pub auth: String,
    pub txn_version: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonTiming {
    pub initial_minimum_balance: String,
    pub cliff_time: i32,
    pub cliff_amount: String,
    pub vesting_period: i32,
    pub vesting_increment: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonBalanceChange {
    pub magnitude: String,
    pub sgn: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonMayUseToken {
    pub parents_own_token: bool,
    pub inherit_from_parent: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonAuthorizationKind {
    pub is_signed: bool,
    pub is_proved: bool,
    pub verification_key_hash: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonPreconditions {
    pub network: JsonPreconditionsNetwork,
    pub account: JsonPreconditionsAccount,
    pub valid_while: Option<JsonBounds>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonPreconditionsNetwork {
    pub snarked_ledger_hash: Option<String>,
    pub blockchain_length: Option<JsonBounds>,
    pub min_window_density: Option<JsonBounds>,
    pub total_currency: Option<JsonBounds>,
    pub global_slot_since_genesis: Option<JsonBounds>,
    pub staking_epoch_data: JsonEpochData,
    pub next_epoch_data: JsonEpochData,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonEpochData {
    pub ledger: JsonEpochLedger,
    pub seed: Option<String>,
    pub start_checkpoint: Option<String>,
    pub lock_checkpoint: Option<String>,
    pub epoch_length: Option<JsonBounds>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonEpochLedger {
    pub hash: Option<String>,
    pub total_currency: Option<JsonBounds>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonBounds {
    pub upper: String,
    pub lower: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonPreconditionsAccount {
    pub balance: Option<JsonBounds>,
    pub nonce: Option<JsonBounds>,
    pub receipt_chain_hash: Option<String>,
    pub delegate: Option<String>,
    pub state: Vec<Option<String>>,
    pub action_state: Option<String>,
    pub proved_state: Option<bool>,
    pub is_new: Option<bool>,
}

// ---------------------------------------------------------------------------
// Deserialization entry point
// ---------------------------------------------------------------------------

/// Deserialize a camelCase JSON string (the `zkappCommand` object from the
/// GraphQL `sendZkapp` mutation) into a `JsonZkappCommand`.
///
/// # Example
/// ```rust
/// let json_str = r#"{ "feePayer": { ... }, "accountUpdates": [...], "memo": "..." }"#;
/// let cmd = parse_zkapp_command_json(json_str).unwrap();
/// ```
pub fn parse_zkapp_command_json(json_str: &str) -> Result<JsonZkappCommand, serde_json::Error> {
    serde_json::from_str(json_str)
}

// ---------------------------------------------------------------------------
// Conversion: Json* -> InputGraphQL* types
// (assuming the InputGraphQL* types are imported from the existing crate)
// ---------------------------------------------------------------------------
//
// Uncomment and adapt the module path once integrated into your project:
//
// use crate::graphql::zkapp::{
//     InputGraphQLZkappCommand, InputGraphQLFeePayer, InputGraphQLFeePayerBody,
//     InputGraphQLAccountUpdate, InputGraphQLAccountUpdateBody, InputGraphQLAuthorization,
//     InputGraphQLAccountUpdateUpdate, InputGraphQLVerificationKey,
//     InputGraphQLAccountUpdateUpdatePermissions, InputGraphQLSetVerificationKeyPermissions,
//     InputGraphQLBalanceChange, InputGraphQLMayUseToken, InputGraphQLAuthorizationKind,
//     InputGraphQLPreconditions, InputGraphQLPreconditionsNetwork,
//     InputGraphQLPreconditionsAccount, InputGraphQLPreconditionsNetworkBounds,
//     InputGraphQLPreconditionsNetworkEpochData, InputGraphQLPreconditionsNetworkLedger,
//     InputGraphQLTiming,
// };
//
// impl From<JsonZkappCommand> for InputGraphQLZkappCommand {
//     fn from(v: JsonZkappCommand) -> Self {
//         Self {
//             memo: v.memo,
//             fee_payer: v.fee_payer.into(),
//             account_updates: v.account_updates.into_iter().map(Into::into).collect(),
//         }
//     }
// }
//
// impl From<JsonFeePayer> for InputGraphQLFeePayer {
//     fn from(v: JsonFeePayer) -> Self {
//         Self {
//             authorization: v.authorization,
//             body: v.body.into(),
//         }
//     }
// }
//
// impl From<JsonFeePayerBody> for InputGraphQLFeePayerBody {
//     fn from(v: JsonFeePayerBody) -> Self {
//         Self {
//             public_key: v.public_key,
//             fee: v.fee,
//             valid_until: v.valid_until,
//             nonce: v.nonce,
//         }
//     }
// }
//
// impl From<JsonAccountUpdate> for InputGraphQLAccountUpdate {
//     fn from(v: JsonAccountUpdate) -> Self {
//         Self {
//             body: v.body.into(),
//             authorization: v.authorization.into(),
//         }
//     }
// }
//
// impl From<JsonAuthorization> for InputGraphQLAuthorization {
//     fn from(v: JsonAuthorization) -> Self {
//         Self {
//             proof: v.proof,
//             signature: v.signature,
//         }
//     }
// }
//
// impl From<JsonAccountUpdateBody> for InputGraphQLAccountUpdateBody {
//     fn from(v: JsonAccountUpdateBody) -> Self {
//         Self {
//             public_key: v.public_key,
//             token_id: v.token_id,
//             update: v.update.into(),
//             balance_change: v.balance_change.into(),
//             increment_nonce: v.increment_nonce,
//             events: v.events,
//             actions: v.actions,
//             call_data: v.call_data,
//             call_depth: v.call_depth,
//             preconditions: v.preconditions.into(),
//             use_full_commitment: v.use_full_commitment,
//             implicit_account_creation_fee: v.implicit_account_creation_fee,
//             may_use_token: v.may_use_token.into(),
//             authorization_kind: v.authorization_kind.into(),
//         }
//     }
// }
//
// impl From<JsonUpdate> for InputGraphQLAccountUpdateUpdate {
//     fn from(v: JsonUpdate) -> Self {
//         Self {
//             app_state: v.app_state,
//             delegate: v.delegate,
//             verification_key: v.verification_key.map(Into::into),
//             permissions: v.permissions.map(Into::into),
//             zkapp_uri: v.zkapp_uri,
//             token_symbol: v.token_symbol,
//             timing: v.timing.map(Into::into),
//             voting_for: v.voting_for,
//         }
//     }
// }
//
// impl From<JsonVerificationKey> for InputGraphQLVerificationKey {
//     fn from(v: JsonVerificationKey) -> Self {
//         Self {
//             data: v.data,
//             hash: v.hash,
//         }
//     }
// }
//
// impl From<JsonPermissions> for InputGraphQLAccountUpdateUpdatePermissions {
//     fn from(v: JsonPermissions) -> Self {
//         Self {
//             edit_state: v.edit_state,
//             access: v.access,
//             send: v.send,
//             receive: v.receive,
//             set_delegate: v.set_delegate,
//             set_permissions: v.set_permissions,
//             set_verification_key: InputGraphQLSetVerificationKeyPermissions {
//                 auth: v.set_verification_key.auth,
//                 txn_version: v.set_verification_key.txn_version,
//             },
//             set_zkapp_uri: v.set_zkapp_uri,
//             edit_action_state: v.edit_action_state,
//             set_token_symbol: v.set_token_symbol,
//             set_timing: v.set_timing,
//             set_voting_for: v.set_voting_for,
//             increment_nonce: v.increment_nonce,
//         }
//     }
// }
//
// impl From<JsonTiming> for InputGraphQLTiming {
//     fn from(v: JsonTiming) -> Self {
//         Self {
//             initial_minimum_balance: v.initial_minimum_balance,
//             cliff_time: v.cliff_time,
//             cliff_amount: v.cliff_amount,
//             vesting_period: v.vesting_period,
//             vesting_increment: v.vesting_increment,
//         }
//     }
// }
//
// impl From<JsonBalanceChange> for InputGraphQLBalanceChange {
//     fn from(v: JsonBalanceChange) -> Self {
//         Self {
//             magnitude: v.magnitude,
//             sgn: v.sgn,
//         }
//     }
// }
//
// impl From<JsonMayUseToken> for InputGraphQLMayUseToken {
//     fn from(v: JsonMayUseToken) -> Self {
//         Self {
//             parents_own_token: v.parents_own_token,
//             inherit_from_parent: v.inherit_from_parent,
//         }
//     }
// }
//
// impl From<JsonAuthorizationKind> for InputGraphQLAuthorizationKind {
//     fn from(v: JsonAuthorizationKind) -> Self {
//         Self {
//             is_signed: v.is_signed,
//             is_proved: v.is_proved,
//             verification_key_hash: v.verification_key_hash,
//         }
//     }
// }
//
// impl From<JsonPreconditions> for InputGraphQLPreconditions {
//     fn from(v: JsonPreconditions) -> Self {
//         Self {
//             network: v.network.into(),
//             account: v.account.into(),
//             valid_while: v.valid_while.map(Into::into),
//         }
//     }
// }
//
// impl From<JsonBounds> for InputGraphQLPreconditionsNetworkBounds {
//     fn from(v: JsonBounds) -> Self {
//         Self {
//             upper: v.upper,
//             lower: v.lower,
//         }
//     }
// }
//
// impl From<JsonPreconditionsNetwork> for InputGraphQLPreconditionsNetwork {
//     fn from(v: JsonPreconditionsNetwork) -> Self {
//         Self {
//             snarked_ledger_hash: v.snarked_ledger_hash,
//             blockchain_length: v.blockchain_length.map(Into::into),
//             min_window_density: v.min_window_density.map(Into::into),
//             total_currency: v.total_currency.map(Into::into),
//             global_slot_since_genesis: v.global_slot_since_genesis.map(Into::into),
//             staking_epoch_data: v.staking_epoch_data.into(),
//             next_epoch_data: v.next_epoch_data.into(),
//         }
//     }
// }
//
// impl From<JsonEpochData> for InputGraphQLPreconditionsNetworkEpochData {
//     fn from(v: JsonEpochData) -> Self {
//         Self {
//             ledger: v.ledger.into(),
//             seed: v.seed,
//             start_checkpoint: v.start_checkpoint,
//             lock_checkpoint: v.lock_checkpoint,
//             epoch_length: v.epoch_length.map(Into::into),
//         }
//     }
// }
//
// impl From<JsonEpochLedger> for InputGraphQLPreconditionsNetworkLedger {
//     fn from(v: JsonEpochLedger) -> Self {
//         Self {
//             hash: v.hash,
//             total_currency: v.total_currency.map(Into::into),
//         }
//     }
// }
//
// impl From<JsonPreconditionsAccount> for InputGraphQLPreconditionsAccount {
//     fn from(v: JsonPreconditionsAccount) -> Self {
//         Self {
//             balance: v.balance.map(Into::into),
//             nonce: v.nonce.map(Into::into),
//             receipt_chain_hash: v.receipt_chain_hash,
//             delegate: v.delegate,
//             state: v.state,
//             action_state: v.action_state,
//             proved_state: v.proved_state,
//             is_new: v.is_new,
//         }
//     }
// }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_zkapp_command() {
        let json = r#"
{
  "feePayer": {
    "body": {
      "publicKey": "B62qk6bjA5HXrwUTcHapbJ9gjyrNPvuHyfrJ2cwJxCAgJScLqG6fCp5",
      "fee": "0",
      "validUntil": null,
      "nonce": "0"
    },
    "authorization": "7mXEnTbd52svjG8jG6kjAyJeoU4GvwwM378MD5MuVthY5QFKvkXKjFTXJq2gKwXY7YFHhhh9h1775qAmmeDLSsx2hmAWJrM5"
  },
  "accountUpdates": [
    {
      "body": {
        "publicKey": "B62qkqy6Uj1SZXyB69kii6RvosS24eJEnMfo8nQZX2EiET8iXjYjCsX",
        "tokenId": "wSHV2S4qX9jFsLjQo8r1BsMLH2ZRKsZx6EJd1sbozGPieEC4Jf",
        "update": {
          "appState": ["1", null, null, null, null, null, null, null],
          "delegate": null,
          "verificationKey": null,
          "permissions": null,
          "zkappUri": null,
          "tokenSymbol": null,
          "timing": null,
          "votingFor": null
        },
        "balanceChange": { "magnitude": "0", "sgn": "Positive" },
        "incrementNonce": false,
        "events": [],
        "actions": [],
        "callData": "10973483498879184113037800935614845081707912956718222723667978633201100759458",
        "callDepth": 0,
        "preconditions": {
          "network": {
            "snarkedLedgerHash": null,
            "blockchainLength": null,
            "minWindowDensity": null,
            "totalCurrency": null,
            "globalSlotSinceGenesis": null,
            "stakingEpochData": {
              "ledger": { "hash": null, "totalCurrency": null },
              "seed": null,
              "startCheckpoint": null,
              "lockCheckpoint": null,
              "epochLength": null
            },
            "nextEpochData": {
              "ledger": { "hash": null, "totalCurrency": null },
              "seed": null,
              "startCheckpoint": null,
              "lockCheckpoint": null,
              "epochLength": null
            }
          },
          "account": {
            "balance": null,
            "nonce": null,
            "receiptChainHash": null,
            "delegate": null,
            "state": ["0", null, null, null, null, null, null, null],
            "actionState": null,
            "provedState": null,
            "isNew": null
          },
          "validWhile": null
        },
        "useFullCommitment": false,
        "implicitAccountCreationFee": false,
        "mayUseToken": { "parentsOwnToken": false, "inheritFromParent": false },
        "authorizationKind": {
          "isSigned": false,
          "isProved": true,
          "verificationKeyHash": "6975621654232076434902806040703807846593353251939042322521605208137539070783"
        }
      },
      "authorization": {
        "proof": "KChzdGF0ZW1lbnQoKH...",
        "signature": null
      }
    }
  ],
  "memo": "E4YM2vTHhWEg66xpj52JErHUBU4pZ1yageL4TVDDpTTSsv8mK6YaH"
}
"#;

        let cmd = parse_zkapp_command_json(json).expect("Failed to deserialize zkapp command");

        // Verify fee payer
        assert_eq!(
            cmd.fee_payer.body.public_key,
            "B62qk6bjA5HXrwUTcHapbJ9gjyrNPvuHyfrJ2cwJxCAgJScLqG6fCp5"
        );
        assert_eq!(cmd.fee_payer.body.fee, "0");
        assert_eq!(cmd.fee_payer.body.nonce, "0");
        assert!(cmd.fee_payer.body.valid_until.is_none());

        // Verify account update
        assert_eq!(cmd.account_updates.len(), 1);
        let au = &cmd.account_updates[0];
        assert_eq!(
            au.body.public_key,
            "B62qkqy6Uj1SZXyB69kii6RvosS24eJEnMfo8nQZX2EiET8iXjYjCsX"
        );
        assert_eq!(au.body.update.app_state[0], Some("1".to_string()));
        assert!(au.body.update.app_state[1].is_none());
        assert!(!au.body.authorization_kind.is_signed);
        assert!(au.body.authorization_kind.is_proved);
        assert_eq!(
            au.body.authorization_kind.verification_key_hash.as_deref(),
            Some("6975621654232076434902806040703807846593353251939042322521605208137539070783")
        );

        // Verify preconditions account state
        assert_eq!(
            au.body.preconditions.account.state[0],
            Some("0".to_string())
        );
        assert!(au.body.preconditions.account.state[1].is_none());

        // Verify authorization
        assert!(au.authorization.proof.is_some());
        assert!(au.authorization.signature.is_none());

        // Verify memo
        assert_eq!(
            cmd.memo.as_deref(),
            Some("E4YM2vTHhWEg66xpj52JErHUBU4pZ1yageL4TVDDpTTSsv8mK6YaH")
        );

        println!("Deserialization successful: {:#?}", cmd.fee_payer.body);
    }
}