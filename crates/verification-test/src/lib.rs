use anyhow::{anyhow, Result};
use mina_p2p_messages::list::List;
use mina_p2p_messages::v2::{
    MinaBaseZkappCommandTStableV1WireStableV1,
    MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesA,
    MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAA,
    MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAACallsA,
};
use serde_json::{json, Map, Value};

fn enum_keep() -> Value {
    json!(["Keep"])
}

fn enum_set(v: Value) -> Value {
    json!(["Set", v])
}

fn opt_to_enum_some_none(v: &Value) -> Value {
    if v.is_null() {
        json!(["None"])
    } else {
        json!(["Some", v.clone()])
    }
}

/// Convert an 8-element array of strings/null into SetOrKeep tuples:
/// - null  -> ["Keep"]
/// - "123" -> ["Set","123"]
fn map_state8_keep_set(arr: &Value) -> Result<Value> {
    let a = arr
        .as_array()
        .ok_or_else(|| anyhow!("expected array for state/app_state"))?;

    if a.len() != 8 {
        return Err(anyhow!("expected 8 elements, got {}", a.len()));
    }

    let out: Vec<Value> = a
        .iter()
        .map(|x| {
            if x.is_null() {
                enum_keep()
            } else {
                // Field elements are encoded as decimal strings in your JSON
                enum_set(x.clone())
            }
        })
        .collect();

    Ok(Value::Array(out))
}

/// Recursively rename known camelCase keys to snake_case.
/// This avoids the classic "missing field fee_payer" error.
fn rename_keys_rec(v: &mut Value) {
    let mapping: &[(&str, &str)] = &[
        ("feePayer", "fee_payer"),
        ("accountUpdates", "account_updates"),
        ("publicKey", "public_key"),
        ("tokenId", "token_id"),
        ("balanceChange", "balance_change"),
        ("incrementNonce", "increment_nonce"),
        ("callData", "call_data"),
        ("callDepth", "call_depth"),
        ("useFullCommitment", "use_full_commitment"),
        ("implicitAccountCreationFee", "implicit_account_creation_fee"),
        ("mayUseToken", "may_use_token"),
        ("authorizationKind", "authorization_kind"),
        ("snarkedLedgerHash", "snarked_ledger_hash"),
        ("blockchainLength", "blockchain_length"),
        ("minWindowDensity", "min_window_density"),
        ("totalCurrency", "total_currency"),
        ("globalSlotSinceGenesis", "global_slot_since_genesis"),
        ("stakingEpochData", "staking_epoch_data"),
        ("nextEpochData", "next_epoch_data"),
        ("startCheckpoint", "start_checkpoint"),
        ("lockCheckpoint", "lock_checkpoint"),
        ("epochLength", "epoch_length"),
        ("receiptChainHash", "receipt_chain_hash"),
        ("actionState", "action_state"),
        ("provedState", "proved_state"),
        ("validWhile", "valid_while"),
        ("parentsOwnToken", "parents_own_token"),
        ("inheritFromParent", "inherit_from_parent"),
        ("isSigned", "is_signed"),
        ("isProved", "is_proved"),
        ("verificationKeyHash", "verification_key_hash"),
        ("verificationKey", "verification_key"),
        ("tokenSymbol", "token_symbol"),
        ("votingFor", "voting_for"),
        ("zkappUri", "zkapp_uri"),
        ("validUntil", "valid_until"),
        ("feePayer", "fee_payer"),
    ];

    match v {
        Value::Object(obj) => {
            // First rename keys at this level
            for (from, to) in mapping {
                if obj.contains_key(*from) && !obj.contains_key(*to) {
                    if let Some(val) = obj.remove(*from) {
                        obj.insert((*to).to_string(), val);
                    }
                }
            }
            // Then recurse into children
            for (_, vv) in obj.iter_mut() {
                rename_keys_rec(vv);
            }
        }
        Value::Array(a) => {
            for vv in a.iter_mut() {
                rename_keys_rec(vv);
            }
        }
        _ => {}
    }
}

/// Normalize the GraphQL-like JSON into something `mina_p2p_messages` wire types can deserialize.
pub fn normalize_json_for_wire(mut v: Value) -> Result<Value> {
    // Rename camelCase -> snake_case first
    rename_keys_rec(&mut v);

    // fee_payer.body.valid_until: null -> ["None"] / value -> ["Some", value]
    {
        let vu = v["fee_payer"]["body"]["valid_until"].clone();
        v["fee_payer"]["body"]["valid_until"] = opt_to_enum_some_none(&vu);
    }

    // update.app_state: [ "1", null, ... ] -> [ ["Set","1"], ["Keep"], ... ]
    {
        let app = v["account_updates"][0]["body"]["update"]["app_state"].clone();
        v["account_updates"][0]["body"]["update"]["app_state"] = map_state8_keep_set(&app)?;
    }

    // preconditions.account.state: same transformation
    {
        let st = v["account_updates"][0]["body"]["preconditions"]["account"]["state"].clone();
        v["account_updates"][0]["body"]["preconditions"]["account"]["state"] = map_state8_keep_set(&st)?;
    }

    // fee_payer.authorization: base58 string -> ["Signature", "..."]
    {
        let auth = v["fee_payer"]["authorization"].clone();
        if let Value::String(s) = auth {
            v["fee_payer"]["authorization"] = json!(["Signature", s]);
        }
    }

    // account_updates[i].authorization: { proof: "...", signature: null } -> ["Proof","..."] / ["Signature","..."] / ["NoneGiven"]
    if let Some(arr) = v["account_updates"].as_array_mut() {
        for au in arr.iter_mut() {
            let auth_obj = au.get("authorization").cloned().unwrap_or(Value::Null);
            let normalized = match auth_obj {
                Value::Object(mut o) => {
                    let proof = o.remove("proof").unwrap_or(Value::Null);
                    let sig = o.remove("signature").unwrap_or(Value::Null);
                    if let Value::String(p) = proof {
                        json!(["Proof", p])
                    } else if let Value::String(s) = sig {
                        json!(["Signature", s])
                    } else {
                        json!(["NoneGiven"])
                    }
                }
                Value::String(s) => json!(["Signature", s]),
                Value::Null => json!(["NoneGiven"]),
                _ => json!(["NoneGiven"]),
            };
            au.as_object_mut()
                .ok_or_else(|| anyhow!("account_updates[i] must be object"))?
                .insert("authorization".to_string(), normalized);
        }
    }

    Ok(v)
}

/// Build the CallForest "wire" wrappers (elt/calls/stack_hash) expected by Mina.
/// Your JSON provides a flat array of account updates. Your sample has one root (call_depth = 0),
/// so we generate a single-node forest with empty children.
fn wrap_account_updates_call_forest(mut normalized: Value) -> Result<Value> {
    let aus = normalized["account_updates"]
        .as_array()
        .ok_or_else(|| anyhow!("account_updates must be an array"))?
        .clone();

    // For now: build a forest with each element as a root with no calls.
    // If later you need nesting, you can group by call_depth like in your GraphQL code.
    let mut roots: Vec<Value> = Vec::with_capacity(aus.len());

    for au in aus {
        // Each node in wire is:
        // AccountUpdatesA { elt: AccountUpdatesAA { account_update, account_update_digest: (), calls }, stack_hash: () }
        let node = json!({
            "elt": {
                "account_update": au,
                "account_update_digest": null,
                "calls": []
            },
            "stack_hash": null
        });
        roots.push(node);
    }

    normalized["account_updates"] = Value::Array(roots);
    Ok(normalized)
}

/// Public entry point used by the test.
/// It accepts your JSON string and returns a MinaBaseZkappCommand wire type.
pub fn zkapp_wire_from_json_str(s: &str) -> Result<MinaBaseZkappCommandTStableV1WireStableV1> {
    let raw: Value = serde_json::from_str(s).map_err(|e| anyhow!("parse json: {e}"))?;

    let normalized = normalize_json_for_wire(raw)
        .map_err(|e| anyhow!("normalize json: {e:?}"))?;

    let normalized = wrap_account_updates_call_forest(normalized)
        .map_err(|e| anyhow!("wrap call forest: {e:?}"))?;

    // Finally deserialize into the official Mina wire type
    let wire: MinaBaseZkappCommandTStableV1WireStableV1 =
        serde_json::from_value(normalized).map_err(|e| anyhow!("json -> wire: {e}"))?;

    Ok(wire)
}