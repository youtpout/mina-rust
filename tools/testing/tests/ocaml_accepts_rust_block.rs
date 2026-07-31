//! Does an OCaml node accept a block produced by the Rust node?
//!
//! Everything else about block proving is self-consistent: the witness matches
//! the constants, the proof is produced, our own verifier accepts it. None of
//! that is evidence that the network would. This test is the one that asks a
//! third party.
//!
//! The OCaml node owns the genesis, because mina-rust cannot build a genesis
//! block from a daemon.json (see `solo_node::sync_to_genesis`). The Rust node
//! syncs from it, then produces a block on top with a real Pickles proof and
//! gossips it. The assertion is that the OCaml node adopts that block as its
//! best tip -- which it only does after verifying the proof.
//!
//! Needs Docker and the arm64 devnet daemon image:
//!
//! ```bash
//! docker pull gcr.io/o1labs-192920/mina-daemon:3.3.0-alpha1-6929a7e-noble-devnet-arm64
//! cargo test -r --package mina-node-testing --test ocaml_accepts_rust_block \
//!   -- ocaml_accepts_rust_block --exact --nocapture
//! ```

#![cfg(all(not(feature = "p2p-webrtc"), feature = "p2p-libp2p"))]

use std::time::Duration;

use mina_node::{
    account::AccountSecretKey, block_producer::BlockProducerConfig,
    transition_frontier::genesis::GenesisConfig, ActionKind,
};
use mina_node_testing::{
    cluster::{Cluster, ClusterConfig, ProofKind},
    node::{
        DaemonJson, OcamlNodeExecutable, OcamlNodeTestingConfig, OcamlStep,
        RustNodeBlockProducerTestingConfig, RustNodeTestingConfig,
    },
    scenario::{ListenerNode, ScenarioStep},
    scenarios::{ClusterRunner, RunCfg, RunCfgAdvanceTime},
    setup_without_rt, wait_for_other_tests,
};

/// Native arm64 build. The amd64 image runs under emulation on Apple Silicon,
/// which is too slow for a node that has to verify a block proof.
const OCAML_IMAGE: &str =
    "gcr.io/o1labs-192920/mina-daemon:3.3.0-alpha1-6929a7e-noble-devnet-arm64";

/// Genesis a little in the past, so slots are already being produced when the
/// nodes come up.
fn genesis_timestamp() -> String {
    use time::{format_description::well_known::Rfc3339, Duration as TDuration, OffsetDateTime};
    let t = OffsetDateTime::now_utc() - TDuration::minutes(10);
    t.replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
        .replace("+00:00", "Z")
}

/// The first generated account is the first whale, and its secret key is
/// written into the daemon.json next to its public key.
fn first_whale_sec_key(daemon_json: &DaemonJson) -> AccountSecretKey {
    let DaemonJson::InMem(json) = daemon_json else {
        panic!("expected a generated in-memory daemon.json");
    };
    let sk = json["ledger"]["accounts"][0]["sk"]
        .as_str()
        .expect("no sk on the first generated account");
    sk.parse().expect("could not parse the whale secret key")
}

#[tokio::test]
async fn ocaml_accepts_rust_block() {
    setup_without_rt();
    let w = wait_for_other_tests().await;

    // Without this, libp2p filters out private addresses and the two nodes
    // never find each other on the loopback. Every OCaml/Rust scenario in this
    // repo sets it.
    std::env::set_var("MINA_DISCOVERY_FILTER_ADDR", "false");
    // Proving saturates every core through rayon, and the OCaml daemon kills
    // itself when its Rpc_parallel children miss heartbeats for 15 minutes.
    // Leave it some room.
    if std::env::var("RAYON_NUM_THREADS").is_err() {
        let n = (std::thread::available_parallelism().map_or(4, |n| n.get()) * 2 / 3).max(2);
        std::env::set_var("RAYON_NUM_THREADS", n.to_string());
    }

    let mut config = ClusterConfig::new(None).expect("failed to create cluster configuration");
    config.set_proof_kind(ProofKind::Full);
    config.set_ocaml_node_executable(OcamlNodeExecutable::Docker(OCAML_IMAGE.to_owned()));

    let mut cluster = Cluster::new(config);
    let mut runner = ClusterRunner::new(&mut cluster, |_| {});

    let daemon_json = runner.daemon_json_gen_with_counts(&genesis_timestamp(), 1, 1);

    // Both nodes must be given the *same* genesis. Handing the Rust node
    // `DEVNET_CONFIG` instead leaves it computing the current epoch from
    // devnet's 2024 genesis timestamp while the chain it syncs starts minutes
    // ago, so its VRF evaluator looks at epoch 56 for a chain at epoch 0 and
    // never finds a won slot.
    let DaemonJson::InMem(genesis_json) = &daemon_json else {
        panic!("expected a generated in-memory daemon.json");
    };
    let genesis = std::sync::Arc::new(GenesisConfig::DaemonJson(Box::new(
        serde_json::from_value(genesis_json.clone()).expect("daemon.json is not a valid genesis"),
    )));

    let producer_sec_key = first_whale_sec_key(&daemon_json);
    let producer_pub_key = producer_sec_key.public_key();
    eprintln!("block producer: {producer_pub_key}");

    // The Rust node comes up first so the OCaml node can be given its address
    // as an initial peer. A Rust node that merely dials out is good enough to
    // sync from, but the OCaml node then does not count it as a peer and never
    // puts it in its gossip mesh, so a produced block never reaches it. This is
    // the shape `multi_node::connection_discovery::RustNodeAsSeed` uses, and it
    // is the only one in this repo where an OCaml node actually receives data
    // from a Rust one. Building the Rust genesis from the same daemon.json is
    // what makes this ordering possible: it no longer has to sync before it can
    // do anything.
    let rust_node = runner.add_rust_node(RustNodeTestingConfig {
        initial_time: redux::Timestamp::global_now(),
        genesis,
        max_peers: 100,
        initial_peers: Vec::new(),
        peer_id: Default::default(),
        snark_worker: None,
        block_producer: Some(RustNodeBlockProducerTestingConfig {
            config: BlockProducerConfig {
                pub_key: producer_pub_key.into(),
                custom_coinbase_receiver: None,
                proposed_protocol_version: None,
            },
            sec_key: producer_sec_key,
        }),
        timeouts: Default::default(),
        libp2p_port: None,
        recorder: Default::default(),
        peer_discovery: true,
    });

    eprintln!("waiting for the rust node's p2p to initialize");
    runner
        .run(
            RunCfg::default()
                .advance_time(RunCfgAdvanceTime::Real)
                .action_handler(move |id, _, _, action| {
                    id == rust_node
                        && matches!(action.action().kind(), ActionKind::P2pInitializeInitialize)
                }),
        )
        .await
        .expect("rust node p2p never initialized");

    let rust_dial_addr = runner.node(rust_node).unwrap().dial_addr();
    eprintln!("rust node listening at {rust_dial_addr}");

    // The address the Rust node advertises is on the loopback, which is useless
    // to the OCaml node under Docker Desktop: the container's 127.0.0.1 is the
    // Linux VM's loopback, not this host's. Inbound works, since the container
    // binds host ports, but outbound to a process listening on the host
    // loopback does not. The cluster binds on 0.0.0.0, so any address the
    // container can route to will do. On Linux, where the container really does
    // share the host network, leaving MINA_TEST_HOST_ADDR unset is correct.
    let ocaml_peer = match std::env::var("MINA_TEST_HOST_ADDR") {
        Ok(host) => rust_dial_addr
            .to_string()
            .replace("127.0.0.1", &host)
            .parse()
            .expect("could not rebuild the dial address for the container"),
        Err(_) => rust_dial_addr,
    };
    eprintln!("giving the ocaml node peer {ocaml_peer}");

    let ocaml_node = runner.add_ocaml_node(OcamlNodeTestingConfig {
        initial_peers: vec![ocaml_peer],
        daemon_json,
        block_producer: None,
    });

    eprintln!("waiting for the ocaml node to be ready");
    runner
        .exec_step(ScenarioStep::Ocaml {
            node_id: ocaml_node,
            step: OcamlStep::WaitReady {
                timeout: Duration::from_secs(10 * 60),
            },
        })
        .await
        .unwrap();

    // Dial the other way too, so neither direction is load-bearing on its own.
    runner
        .exec_step(ScenarioStep::ConnectNodes {
            dialer: rust_node,
            listener: ListenerNode::Ocaml(ocaml_node),
        })
        .await
        .unwrap();

    eprintln!("waiting for the rust node to sync from the ocaml node");
    runner
        .run(
            RunCfg::default()
                .advance_time(RunCfgAdvanceTime::Real)
                .action_handler(move |node_id, state, _, _| {
                    node_id == rust_node
                        && state.transition_frontier.sync.is_synced()
                        && state.transition_frontier.best_tip().is_some()
                }),
        )
        .await
        .expect("rust node did not sync from the ocaml node");

    let genesis_height = runner
        .node(rust_node)
        .unwrap()
        .state()
        .transition_frontier
        .best_tip()
        .map(|tip| tip.height())
        .unwrap();
    eprintln!("synced at height {genesis_height}, waiting for a produced block");

    runner
        .run(
            RunCfg::default()
                .advance_time(RunCfgAdvanceTime::Real)
                .timeout(Duration::from_secs(30 * 60))
                .action_handler(move |node_id, state, _, _| {
                    node_id == rust_node
                        && state
                            .transition_frontier
                            .best_tip()
                            .is_some_and(|tip| tip.height() > genesis_height)
                }),
        )
        .await
        .expect("rust node did not produce a block");

    let produced = runner
        .node(rust_node)
        .unwrap()
        .state()
        .transition_frontier
        .best_tip()
        .map(|tip| tip.hash().clone())
        .unwrap();
    eprintln!("rust node produced {produced}, waiting for the ocaml node to adopt it");

    // The OCaml node only makes this its best tip after verifying the block
    // proof, so this is the assertion that matters.
    let deadline = std::time::Instant::now() + Duration::from_secs(10 * 60);
    loop {
        let tip = runner
            .ocaml_node(ocaml_node)
            .unwrap()
            .synced_best_tip()
            .await
            .ok()
            .flatten();
        if tip.as_ref() == Some(&produced) {
            eprintln!("the ocaml node accepted the block produced by the rust node");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "ocaml node never adopted {produced}; its best tip is {tip:?}"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    runner
        .exec_step(ScenarioStep::Ocaml {
            node_id: ocaml_node,
            step: OcamlStep::KillAndRemove,
        })
        .await
        .unwrap();

    w.release();
}
