//! Stage B: produce a block with a *real* Pickles proof.
//!
//! Every other block-production scenario runs with `ProofKind::Dummy`, so none
//! of them exercise the proving stack. This one forces `ProofKind::Full` and
//! builds the block input with the current code instead of replaying a
//! captured fixture, which is what `proofs::transaction::tests::test_block_proof`
//! does. That removes fixture staleness as a variable: if the proof is
//! produced here, block proving works and the captured fixture is stale.
//!
//! To run locally:
//! ```bash
//! cargo test -r --package mina-node-testing --test block_production_full_proof \
//!   -- block_production_full_proof --exact --nocapture
//! ```

use std::time::Duration;

use mina_node::transition_frontier::genesis::{GenesisConfig, NonStakers};
use mina_node_testing::{
    cluster::{Cluster, ClusterConfig, ProofKind},
    scenarios::{ClusterRunner, RunCfgAdvanceTime},
    setup_without_rt,
    simulator::{Simulator, SimulatorConfig, SimulatorRunUntil},
    wait_for_other_tests,
};
use mina_p2p_messages::v2::{BlockTimeTimeStableV1, PROTOCOL_CONSTANTS};

/// Same run, but stopping after the step witness has been checked against the
/// circuit constraints, without building a proof. This separates two questions
/// that `ProofKind::Full` answers at once: does the witness satisfy the gate
/// constraints, and is it wired correctly (the permutation). `Full` fails on
/// the permutation; if `ConstraintsChecked` passes, the values themselves are
/// right and only their placement is wrong.
#[tokio::test]
async fn block_production_constraints_only() {
    run_block_production(ProofKind::ConstraintsChecked).await
}

#[tokio::test]
async fn block_production_full_proof() {
    run_block_production(ProofKind::Full).await
}

async fn run_block_production(proof_kind: ProofKind) {
    setup_without_rt();
    let w = wait_for_other_tests().await;

    let mut config = ClusterConfig::new(None).expect("failed to create cluster configuration");
    config.set_proof_kind(proof_kind);

    let initial_time = redux::Timestamp::global_now();
    let mut constants = PROTOCOL_CONSTANTS.clone();
    constants.genesis_state_timestamp =
        BlockTimeTimeStableV1((u64::from(initial_time) / 1_000_000).into());

    // A single whale producer owns essentially all the stake, so slots are won
    // immediately and we do not wait on VRF luck.
    let genesis_cfg = GenesisConfig::Counts {
        whales: 1,
        fish: 0,
        non_stakers: NonStakers::None,
        constants,
    };

    let cfg = SimulatorConfig {
        genesis: genesis_cfg.into(),
        seed_nodes: 1,
        normal_nodes: 0,
        snark_workers: 0,
        block_producers: 1,
        advance_time: RunCfgAdvanceTime::Rand(1..=200),
        // Genesis is length 1, so this asks for exactly one produced block.
        run_until: SimulatorRunUntil::BlockchainLength(2),
        run_until_timeout: Duration::from_secs(60 * 60),
        recorder: Default::default(),
    };

    let mut cluster = Cluster::new(config);
    let mut runner = ClusterRunner::new(&mut cluster, |_| {});

    let mut simulator = Simulator::new(initial_time, cfg);
    simulator.setup_and_run(&mut runner).await;

    let best_tip_length = runner
        .nodes_iter()
        .filter_map(|(_, node)| node.state().transition_frontier.best_tip())
        .map(|tip| tip.height())
        .max()
        .expect("no node reached a best tip");

    assert!(
        best_tip_length >= 2,
        "expected at least one produced block on top of genesis, best tip height is {best_tip_length}"
    );

    w.release();
}
