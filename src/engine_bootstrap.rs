//! Engine + channel bootstrap shared by the daemon.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use parking_lot::RwLock;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::MissedTickBehavior;

use crate::config::{ConfigManager, IPPool, PeerInfo};
use crate::metrics::EngineMetrics;
use crate::net::engine::{EngineCmd, P2PEngine, RosterChange};
use crate::net::pacing::PacingConfig;
use crate::net::pacing_defaults as pace_def;
use crate::net::pmtud_probe::bind_pmtud_probe_socket;
use crate::netinfo;
use crate::peer_cache::{load_peer_cache, remember_endpoint, save_peer_cache, PeerCache};
use crate::routing::{owner_vip, owner_vip_with_prefix, RoutingTable};
use crate::runtime_trace::RuntimeTrace;
use crate::ui_events::{UiEventBus, UiSink};

#[derive(Clone, Debug)]
pub struct EndpointLearned {
    pub vip: String,
    pub endpoint: String,
}

pub struct EngineRuntime {
    pub config: Arc<ConfigManager>,
    pub routing: Arc<RwLock<RoutingTable>>,
    pub cmd_tx: mpsc::Sender<EngineCmd>,
    pub tun_from_tun_tx: mpsc::Sender<Bytes>,
    pub tun_inject_rx: broadcast::Receiver<Bytes>,
    pub peer_cache_reset_tx: mpsc::UnboundedSender<oneshot::Sender<()>>,
    pub owner_vip_pool: Option<Arc<parking_lot::Mutex<IPPool>>>,
    pub engine_metrics: Arc<EngineMetrics>,
    pub runtime_trace: Arc<RuntimeTrace>,
    pub engine: P2PEngine,
    pub initial_pacing: PacingConfig,
    pub ui: UiSink,
}

pub async fn build_engine_runtime(config: Arc<ConfigManager>) -> Result<EngineRuntime> {
    let snap = config.snapshot();
    let listen_port = config.get_listen_port().max(7878);

    let sndbuf = if snap.udp_sndbuf > 0 {
        snap.udp_sndbuf as usize
    } else {
        (1024 * 1024) / 2
    };
    let rcvbuf = if snap.udp_rcvbuf > 0 {
        snap.udp_rcvbuf as usize
    } else {
        (1024 * 1024) / 2
    };

    let s2_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s2_sock.set_reuse_address(true)?;
    s2_sock.set_broadcast(true)?;
    s2_sock.bind(&SocketAddr::from(([0, 0, 0, 0], listen_port)).into())?;
    let _ = s2_sock.set_send_buffer_size(sndbuf);
    let _ = s2_sock.set_recv_buffer_size(rcvbuf);
    let std_sock: std::net::UdpSocket = s2_sock.into();
    std_sock.set_nonblocking(true)?;
    let socket = Arc::new(UdpSocket::from_std(std_sock)?);

    let routing = Arc::new(RwLock::new(RoutingTable::new()));

    let snap = config.snapshot();
    if snap.role == "peer" {
        let my_vip = snap.virtual_ip.clone();
        let owner_vip = owner_vip_with_prefix(&my_vip, snap.subnet_prefix.clamp(8, 30));
        let mut rt = routing.write();
        for p in &snap.peers {
            if p.virtual_ip.is_empty() || p.virtual_ip == my_vip || p.virtual_ip == owner_vip {
                continue;
            }
            if let Ok(ep) = p.real_ip.parse::<SocketAddr>() {
                let node_id = if p.node_id.is_empty() {
                    None
                } else {
                    Some(p.node_id.as_str())
                };
                rt.update(&p.virtual_ip, ep, node_id);
            }
        }
    }

    let cache_path = netinfo::peer_cache_path()?;
    let peer_cache = load_peer_cache(&cache_path).unwrap_or_default();
    {
        let mut rt = routing.write();
        for (vip, endpoints) in &peer_cache.by_vip {
            for ce in endpoints {
                if let Ok(ep) = ce.endpoint.parse::<SocketAddr>() {
                    rt.update(vip, ep, None);
                }
            }
        }
    }
    sync_owner_endpoint_cache_from_peer_cache(&config, &peer_cache);
    let ui = UiEventBus::new();
    let (endpoint_tx, peer_cache_reset_tx) = start_endpoint_cache_worker(
        cache_path.clone(),
        config.clone(),
        peer_cache.clone(),
        ui.clone(),
    );

    let tun_from_adapter_cap =
        pace_def::effective_tun_from_adapter_queue_packets(snap.tun_from_adapter_queue_packets);
    let (tun_from_tun_tx, tun_from_tun_rx) = mpsc::channel::<Bytes>(tun_from_adapter_cap);
    let tun_inject_cap =
        pace_def::effective_tun_inject_queue_packets(snap.tun_inject_queue_packets);
    let (tun_inject_tx, tun_inject_rx) = broadcast::channel::<Bytes>(tun_inject_cap);

    let (cmd_tx, cmd_rx) = mpsc::channel(256);

    let vip = config
        .snapshot()
        .virtual_ip
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 2));
    let node_id = config.snapshot().node_id.clone();

    let engine_metrics = Arc::new(EngineMetrics::new());
    let runtime_trace = Arc::new(RuntimeTrace::new());
    let subnet_prefix = config.snapshot().subnet_prefix.clamp(8, 30);
    let pmtud_probe_socket = bind_pmtud_probe_socket()?;
    let cfg = config.snapshot();
    let pace_clock_apply =
        crate::net::pace_clock::PaceClockApply::from_network_config(cfg.as_ref());
    let max_queue_packets = pace_def::effective_pace_max_queue_packets(cfg.pace_max_queue_packets);
    let (max_data_queue_packets, max_control_queue_packets) =
        crate::net::pacing::queue_split_limits(max_queue_packets);
    let tick_raw = pace_def::effective_pace_tick_us(cfg.pace_tick_us).min(1_000_000);
    let initial_pacing = PacingConfig {
        tick_us: crate::net::pace_clock::clamp_tick_us(tick_raw),
        target_pps: pace_def::effective_pace_target_pps(cfg.pace_target_pps),
        base_max_burst: pace_def::effective_base_max_burst(cfg.base_max_burst),
        budget_cap_packets: pace_def::effective_pace_budget_cap_packets(
            cfg.pace_budget_cap_packets,
        ),
        max_queue_packets,
        max_data_queue_packets,
        max_control_queue_packets,
        max_retransmit_queue_packets: (max_control_queue_packets / 3).max(4),
        drr_quantum: 1500,
        drr_enabled: cfg.drr_enabled,
        drr_small_packet_priority: cfg.drr_small_packet_priority,
        drr_small_packet_threshold_bytes: pace_def::effective_drr_small_packet_threshold_bytes(
            cfg.drr_small_packet_threshold_bytes,
        ),
        min_control_reserved_bytes_per_tick: pace_def::effective_reserved_bytes_per_tick(
            cfg.min_control_reserved_bytes_per_tick,
        ),
        min_retransmit_reserved_bytes_per_tick: pace_def::effective_reserved_bytes_per_tick(
            cfg.min_retransmit_reserved_bytes_per_tick,
        ),
        drr_rtt_aware: cfg.drr_rtt_aware,
        drr_rtt_scale_min: pace_def::effective_drr_rtt_scale_min(cfg.drr_rtt_scale_min),
        drr_rtt_scale_max: pace_def::effective_drr_rtt_scale_max(cfg.drr_rtt_scale_max),
        max_tick_work_us: crate::net::pacing_defaults::DEFAULT_MAX_TICK_WORK_US,
        apd: crate::net::pacing::apd_config_from_network(cfg.as_ref()),
        shed: crate::net::pacing::shed_config_from_network(cfg.as_ref()),
        background_cc: cfg.advanced.congestion.to_background_cc_config(),
        pace_rate_mode: pace_def::effective_pace_rate_mode(&cfg.pace_rate_mode),
        target_bps: pace_def::effective_pace_target_bps(cfg.pace_target_bps, cfg.pace_target_pps),
    };
    let mut engine = P2PEngine::new(
        socket,
        pmtud_probe_socket,
        routing.clone(),
        tun_from_tun_rx,
        tun_inject_tx,
        cmd_rx,
        config.get_role() == "owner",
        vip,
        node_id,
        subnet_prefix,
        engine_metrics.clone(),
        pace_clock_apply,
        initial_pacing.tick_us,
        runtime_trace.clone(),
        tun_inject_cap,
        ui.clone(),
    );
    // Apply advanced tuning from the persisted snapshot before the engine
    // starts its event loop, so intervals / failover / reliable / FEC / PMTUD
    // begin with the configured (clamped) values rather than defaults.
    engine.apply_advanced_tuning(crate::advanced_tuning::AdvancedTuning::from_network_config(
        cfg.as_ref(),
    ));
    let mut owner_vip_pool: Option<Arc<parking_lot::Mutex<IPPool>>> = None;
    if config.get_role() == "owner" {
        let pool = Arc::new(parking_lot::Mutex::new(IPPool::new(&vip.to_string())));
        owner_vip_pool = Some(pool.clone());
        for used in config.used_virtual_ips() {
            if used != vip.to_string() {
                pool.lock().mark_used(&used);
            }
        }
        for p in config.snapshot().peers.iter() {
            if !p.node_id.is_empty() && !p.virtual_ip.is_empty() {
                pool.lock().ensure_allocated(&p.node_id, &p.virtual_ip);
            }
        }
        let join_pool = pool.clone();
        let join_cfg = config.clone();
        let join_rt = routing.clone();
        engine.set_join_handler(Arc::new(move |node_id, from| {
            let endpoint = from.to_string();
            let removed = join_cfg.remove_peers_by_endpoint(&endpoint, &node_id);
            for p in removed {
                if !p.virtual_ip.is_empty() {
                    join_rt.write().remove(&p.virtual_ip);
                    join_pool.lock().release(&p.virtual_ip);
                }
            }
            if let Some(existing) = join_cfg.find_peer_by_node_id(&node_id) {
                return Some(existing.virtual_ip);
            }
            let assigned = join_pool.lock().allocate(&node_id);
            if let Some(ref vip) = assigned {
                join_cfg.add_peer(PeerInfo {
                    node_id: node_id.clone(),
                    name: node_id.clone(),
                    virtual_ip: vip.clone(),
                    real_ip: endpoint,
                });
            }
            assigned
        }));
        let leave_cfg = config.clone();
        engine.set_leave_handler(Arc::new(move |vip| {
            pool.lock().release(&vip);
            leave_cfg.remove_peer_by_vip(&vip);
        }));
    }
    {
        let endpoint_tx = endpoint_tx.clone();
        engine.set_endpoint_learned_handler(Arc::new(move |vip, ep| {
            let _ = endpoint_tx.send(EndpointLearned {
                vip,
                endpoint: ep.to_string(),
            });
        }));
    }
    if config.get_role() == "peer" {
        let roster_cfg = config.clone();
        engine.set_roster_changed_handler(Arc::new(move |change| match change {
            RosterChange::Upsert(peer) => roster_cfg.upsert_joiner_roster_peer(peer),
            RosterChange::Remove(vip) => roster_cfg.remove_joiner_roster_vip(&vip),
        }));
    }

    Ok(EngineRuntime {
        config,
        routing,
        cmd_tx,
        tun_from_tun_tx,
        tun_inject_rx,
        peer_cache_reset_tx,
        owner_vip_pool,
        engine_metrics,
        runtime_trace,
        engine,
        initial_pacing,
        ui,
    })
}

pub fn start_endpoint_cache_worker(
    cache_path: PathBuf,
    config: Arc<ConfigManager>,
    initial_cache: PeerCache,
    ui: UiSink,
) -> (
    UnboundedSender<EndpointLearned>,
    mpsc::UnboundedSender<oneshot::Sender<()>>,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<EndpointLearned>();
    let (reset_tx, mut reset_rx) = mpsc::unbounded_channel::<oneshot::Sender<()>>();
    tokio::spawn(async move {
        let mut cache = initial_cache;
        let mut dirty = false;
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                r = reset_rx.recv() => {
                    let Some(done) = r else {
                        break;
                    };
                    // Drop any learns queued before/during reset so they cannot
                    // rewrite peer_cache.json after wipe.
                    while rx.try_recv().is_ok() {}
                    cache = PeerCache::default();
                    dirty = false;
                    let path_rm = cache_path.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = std::fs::remove_file(&path_rm);
                    })
                    .await;
                    sync_owner_endpoint_cache_from_peer_cache(&config, &cache);
                    let _ = done.send(());
                }
                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        if dirty {
                            let path = cache_path.clone();
                            let snap = cache.clone();
                            match tokio::task::spawn_blocking(move || save_peer_cache(&path, &snap)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => ui.emit_stderr(format!("peer_cache save failed: {e}")),
                                Err(e) => ui.emit_stderr(format!("peer_cache save task: {e}")),
                            }
                            sync_owner_endpoint_cache_from_peer_cache(&config, &cache);
                        }
                        break;
                    };
                    remember_endpoint(&mut cache, &msg.vip, &msg.endpoint);
                    dirty = true;
                }
                _ = ticker.tick() => {
                    if dirty {
                        let path = cache_path.clone();
                        let snap = cache.clone();
                        match tokio::task::spawn_blocking(move || save_peer_cache(&path, &snap)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => ui.emit_stderr(format!("peer_cache save failed: {e}")),
                            Err(e) => ui.emit_stderr(format!("peer_cache save task: {e}")),
                        }
                        sync_owner_endpoint_cache_from_peer_cache(&config, &cache);
                        dirty = false;
                    }
                }
            }
        }
    });
    (tx, reset_tx)
}

pub fn sync_owner_endpoint_cache_from_peer_cache(config: &Arc<ConfigManager>, cache: &PeerCache) {
    let snap = config.snapshot();
    if snap.role != "peer" || snap.virtual_ip.is_empty() {
        return;
    }
    let owner_vip_key = owner_vip(&snap.virtual_ip);
    let endpoints: Vec<String> = cache
        .by_vip
        .get(&owner_vip_key)
        .map(|v| v.iter().map(|c| c.endpoint.clone()).collect())
        .unwrap_or_default();
    config.update(|cfg| {
        cfg.owner_endpoints_cache = endpoints.clone();
        if cfg.owner_real_ip.is_empty() {
            if let Some(first) = cfg.owner_endpoints_cache.first() {
                if let Some((ip, _)) = first.rsplit_once(':') {
                    cfg.owner_real_ip = ip.to_string();
                }
            }
        }
    });
}
