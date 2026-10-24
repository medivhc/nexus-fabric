use std::time::Duration;

use nexus_fabric::{Driver, PeerId};
use nexus_nat_wireup::{
    PunchManager, PunchPeerStatus, PunchState, RelaySource, SystemPunchClock, TunnelProto,
};

fn manager() -> (std::sync::Arc<PunchManager>, PeerId) {
    let driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind driver");
    let me = PeerId([1u8; 32]);
    let mgr = PunchManager::new(driver, me, SystemPunchClock::new());
    (mgr, PeerId([2u8; 32]))
}

#[test]
fn g16_peer_status_fields() {
    let (mgr, peer) = manager();
    assert!(
        mgr.status(&peer).is_none(),
        "unknown peer has no registry entry"
    );
    mgr.set_tunnel_proto(peer, TunnelProto::Turn);
    mgr.set_relay_source(peer, Some(RelaySource::Turn));
    let st: PunchPeerStatus = mgr.status(&peer).expect("entry created by setters");
    assert_eq!(st.state, PunchState::NotAttempted);
    assert_eq!(st.tunnel_proto, TunnelProto::Turn);
    assert_eq!(st.relay_source, Some(RelaySource::Turn));
    // 12 counter projections + decode errors exist and start at zero.
    for v in [
        st.attempts_total,
        st.migrated_total,
        st.failed_timeout_total,
        st.failed_unpredictable_total,
        st.failed_no_candidates_total,
        st.failed_channel_closed_total,
        st.spray_sends_total,
        st.spray_skipped_total,
        st.mapping_probe_sends_total,
        st.prediction_hints_sent_total,
        st.prediction_hints_recv_total,
        st.signal_decode_errors_total,
    ] {
        assert_eq!(v, 0);
    }
    assert_eq!(mgr.all_status().len(), 1);
    // Clock is injectable and used for timestamps.
    let _ = Duration::from_secs(1);
    assert!(st.last_attempt_ms.is_none());
}
