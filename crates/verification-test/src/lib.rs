use mina_p2p_messages::{
    list::List,
    v2::{
        MinaBaseAccountUpdateFeePayerStableV1, MinaBaseAccountUpdateTStableV1,
        MinaBaseSignedCommandMemoStableV1, MinaBaseZkappCommandTStableV1WireStableV1,
        MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesA,
        MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAA,
        MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAACallsA,
    },
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::borrow::Cow;
use anyhow::{anyhow, Result}; 
use ledger::scan_state::transaction_logic::zkapp_command; 

#[derive(Debug, thiserror::Error)]
pub enum ZkappJsonError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Missing field: {0}")]
    Missing(&'static str),

    #[error("Invalid field type for: {0}")]
    Invalid(&'static str),

    #[error("Cannot read callDepth in accountUpdates[{0}]")]
    CallDepth(usize),

    #[error("Memo base58check decode error: {0}")]
    Memo(String),
}

/// Minimal custom model matching your JSON exactly.
/// We purposely keep `body` and `authorization` as serde_json::Value to avoid tons of sub-classes.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkappCommandJson {
    pub fee_payer: FeePayerJson,
    pub account_updates: Vec<AccountUpdateJson>,
    pub memo: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeePayerJson {
    pub body: Value,
    pub authorization: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountUpdateJson {
    pub body: Value,
    pub authorization: Value, // { proof: "...", signature: null } etc.
}

/// Public helper: parse your JSON and return the Mina wire zkapp command.
/// The resulting type is: Mina_base__Zkapp_command.T.Stable.V1.Wire.Stable.V1
pub fn zkapp_wire_from_json_str(
    s: &str,
) -> Result<MinaBaseZkappCommandTStableV1WireStableV1, ZkappJsonError> {
    let parsed: ZkappCommandJson = serde_json::from_str(s)?;

    // 1) Convert fee_payer (camel -> snake) and deserialize into Mina type.
    let fee_payer_val = json_fee_payer_to_mina_value(&parsed.fee_payer)?;
    let fee_payer: MinaBaseAccountUpdateFeePayerStableV1 = serde_json::from_value(fee_payer_val)?;

    // 2) Build account_updates tree from flat list using callDepth.
    let account_updates = build_account_updates_tree(&parsed.account_updates)?;

    // 3) Memo: your JSON memo is base58check.
    let memo = MinaBaseSignedCommandMemoStableV1::from_base58check(&parsed.memo);

    Ok(MinaBaseZkappCommandTStableV1WireStableV1 {
        fee_payer,
        account_updates,
        memo,
    })
}

/// Convert feePayer JSON into a Value shaped like Mina expects.
/// Mina type expects: { body: { public_key, fee, valid_until, nonce }, authorization: "..." }
fn json_fee_payer_to_mina_value(fee_payer: &FeePayerJson) -> Result<Value, ZkappJsonError> {
    let body_snake = camel_to_snake_value(fee_payer.body.clone());
    Ok(Value::Object(Map::from_iter([
        (String::from("body"), body_snake),
        (
            String::from("authorization"),
            Value::String(fee_payer.authorization.clone()),
        ),
    ])))
}

/// Build Mina account_updates tree.
/// Mina wire expects a tree:
///   List< AccountUpdatesA { elt: AccountUpdatesAA { account_update, account_update_digest: (), calls }, stack_hash: () } >
///
/// Your JSON is a flat pre-order with callDepth.
/// We reconstruct the tree by grouping children while next.callDepth > current.callDepth.
fn build_account_updates_tree(
    flat: &[AccountUpdateJson],
) -> Result<List<MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesA>, ZkappJsonError> {
    // Precompute entries with depth + Mina account_update value.
    let mut entries: Vec<FlatEntry> = Vec::with_capacity(flat.len());

    for (i, au) in flat.iter().enumerate() {
        let depth = extract_call_depth(&au.body).ok_or(ZkappJsonError::CallDepth(i))?;

        // Merge { body, authorization } into a single object for MinaBaseAccountUpdateTStableV1.
        // Then camel->snake on the whole account update.
        let mut obj = Map::new();
        obj.insert("body".to_string(), au.body.clone());
        obj.insert("authorization".to_string(), au.authorization.clone());
        let snake = camel_to_snake_value(Value::Object(obj));

        let account_update: MinaBaseAccountUpdateTStableV1 = serde_json::from_value(snake)?;

        entries.push(FlatEntry {
            depth,
            account_update,
        });
    }

    // Recursively build calls tree using iterator + peek.
    let mut iter = entries.into_iter().peekable();
    let calls = build_tree_aux(&mut iter)?;

    Ok(calls
        .into_iter()
        .map(wrap_call_into_a)
        .collect::<List<MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesA>>())
}

/// Internal representation after converting each flat item into MinaBaseAccountUpdateTStableV1.
#[derive(Debug)]
struct FlatEntry {
    depth: u32,
    account_update: MinaBaseAccountUpdateTStableV1,
}

/// Node used by the aux builder, matching Mina's AA calls wrapper.
type CallNode = MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAACallsA;

/// Build List<CallNode> where CallNode.elt contains AA { account_update, digest: (), calls } and stack_hash: ().
fn build_tree_aux<I>(iter: &mut std::iter::Peekable<I>) -> Result<List<CallNode>, ZkappJsonError>
where
    I: Iterator<Item = FlatEntry>,
{
    let mut out = List::new();

    while let Some(entry) = iter.next() {
        let depth = entry.depth;

        // Collect direct children (those with greater depth) until we hit a sibling/parent.
        let mut children: Vec<FlatEntry> = Vec::new();
        while let Some(peek) = iter.peek() {
            if peek.depth > depth {
                // We can safely consume since we just peeked.
                children.push(iter.next().expect("peeked Some, so next must be Some"));
            } else {
                break;
            }
        }

        // Recurse on children by creating a nested iterator for that slice.
        let mut child_iter = children.into_iter().peekable();
        let calls = build_tree_aux(&mut child_iter)?;

        out.push_back(CallNode {
            elt: Box::new(MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAA {
                account_update: entry.account_update,
                account_update_digest: (),
                calls,
            }),
            stack_hash: (),
        });
    }

    Ok(out)
}

/// Wrap CallNode -> AccountUpdatesA (the outer wrapper used by Mina wire)
fn wrap_call_into_a(node: CallNode) -> MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesA {
    let CallNode { elt, stack_hash } = node;
    let MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAA {
        account_update,
        account_update_digest,
        calls,
    } = *elt;

    MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesA {
        elt: MinaBaseZkappCommandTStableV1WireStableV1AccountUpdatesAA {
            account_update,
            account_update_digest,
            calls,
        },
        stack_hash,
    }
}

/// Extract callDepth from your JSON accountUpdate.body.callDepth (camelCase).
fn extract_call_depth(body: &Value) -> Option<u32> {
    body.get("callDepth")?.as_u64().map(|x| x as u32)
}

/// Convert JSON object keys from camelCase to snake_case recursively.
/// This lets us deserialize into mina_p2p_messages generated structs (snake_case fields).
fn camel_to_snake_value(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, vv) in map {
                let sk = camel_to_snake_key(&k).into_owned();
                out.insert(sk, camel_to_snake_value(vv));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(camel_to_snake_value).collect()),
        other => other,
    }
}

/// Convert a single key from camelCase to snake_case.
/// Example: "feePayer" -> "fee_payer", "callDepth" -> "call_depth"
fn camel_to_snake_key(s: &str) -> Cow<'_, str> {
    // Fast path: if no uppercase, keep as-is.
    if !s.bytes().any(|b| (b'A'..=b'Z').contains(&b)) {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len() + 8);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}
