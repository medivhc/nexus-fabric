//! Bootstrap 帧编解码组合根适配（v2 §5.5，S1）。
//!
//! `nexus-connectivity` 不能依赖 `nexus-discovery`（架构红线，见
//! `crates/nexus-connectivity/src/fib_resolver.rs`）；本文件在 `apps/nexus` 组合根把
//! connectivity 的解耦类型 [`BootstrapCtrl`]/外层握手帧，映射到 discovery 的
//! `AutoDiscoveryFrame` 与 `bootstrap_join` 字节格式——与 `DiscoveryFibResolver` 同构。

use nexus_connectivity::bootstrap_server::{
    BootstrapCtrl, BootstrapFrameCodec, BootstrapOuterCode, BootstrapPeer, BootstrapServerError,
    JoinInitReq, JoinReplyResp, OuterKind,
};
use nexus_discovery::auto_discovery::{
    AutoDiscoveryFrame, DiscoveredNode, decode_auto_frame, encode_auto_frame,
};
use nexus_discovery::bootstrap_join::{
    BootstrapErrorCode, BootstrapJoinFrame, decode_join_frame, encode_join_frame, split_outer,
};

/// 组合根 codec：connectivity 解耦类型 <-> discovery 字节。
#[derive(Debug, Default, Clone, Copy)]
pub struct DiscoveryBootstrapCodec;

impl DiscoveryBootstrapCodec {
    /// 创建空 codec（无状态；纯字节映射）。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn map_err(e: nexus_discovery::DiscoveryError) -> BootstrapServerError {
        BootstrapServerError::Malformed(e.to_string())
    }

    fn outer_code_to_discovery(code: BootstrapOuterCode) -> BootstrapErrorCode {
        match code {
            BootstrapOuterCode::AuthFailed => BootstrapErrorCode::AuthFailed,
            BootstrapOuterCode::BadVip => BootstrapErrorCode::BadVip,
            BootstrapOuterCode::VipConflict => BootstrapErrorCode::VipConflict,
            BootstrapOuterCode::NotBootstrap => BootstrapErrorCode::NotBootstrap,
            BootstrapOuterCode::RateLimited => BootstrapErrorCode::RateLimited,
            BootstrapOuterCode::MalformedFrame => BootstrapErrorCode::MalformedFrame,
        }
    }
}

impl BootstrapFrameCodec for DiscoveryBootstrapCodec {
    fn encode(&self, f: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapServerError> {
        let frame = match f {
            BootstrapCtrl::Register {
                node_id,
                virtual_ip,
                locator,
            } => AutoDiscoveryFrame::Register {
                node_id: node_id.clone(),
                virtual_ip: virtual_ip.clone(),
                locator: locator.clone(),
            },
            BootstrapCtrl::RegisterAck { accepted, ttl_secs } => AutoDiscoveryFrame::RegisterAck {
                accepted: *accepted,
                ttl_secs: *ttl_secs,
            },
            BootstrapCtrl::GetPeers { node_id } => AutoDiscoveryFrame::GetPeers {
                node_id: node_id.clone(),
            },
            BootstrapCtrl::PeerList { peers } => AutoDiscoveryFrame::PeerList {
                peers: peers
                    .iter()
                    .map(|p| DiscoveredNode {
                        node_id: p.node_id.clone(),
                        virtual_ip: p.virtual_ip.clone(),
                        locator: p.locator.clone(),
                        last_seen: 0,
                    })
                    .collect(),
            },
            BootstrapCtrl::Heartbeat { node_id, now } => AutoDiscoveryFrame::Heartbeat {
                node_id: node_id.clone(),
                now: *now,
            },
        };
        encode_auto_frame(&frame).map_err(Self::map_err)
    }

    fn decode(&self, b: &[u8]) -> Result<BootstrapCtrl, BootstrapServerError> {
        let frame = decode_auto_frame(b).map_err(Self::map_err)?;
        let ctrl = match frame {
            AutoDiscoveryFrame::Register {
                node_id,
                virtual_ip,
                locator,
            } => BootstrapCtrl::Register {
                node_id,
                virtual_ip,
                locator,
            },
            AutoDiscoveryFrame::RegisterAck { accepted, ttl_secs } => {
                BootstrapCtrl::RegisterAck { accepted, ttl_secs }
            }
            AutoDiscoveryFrame::GetPeers { node_id } => BootstrapCtrl::GetPeers { node_id },
            AutoDiscoveryFrame::PeerList { peers } => BootstrapCtrl::PeerList {
                peers: peers
                    .into_iter()
                    .map(|p| BootstrapPeer {
                        node_id: p.node_id,
                        virtual_ip: p.virtual_ip,
                        locator: p.locator,
                    })
                    .collect(),
            },
            AutoDiscoveryFrame::Heartbeat { node_id, now } => {
                BootstrapCtrl::Heartbeat { node_id, now }
            }
        };
        Ok(ctrl)
    }

    fn decode_join_init(&self, payload: &[u8]) -> Result<JoinInitReq, BootstrapServerError> {
        match decode_join_frame(payload).map_err(Self::map_err)? {
            BootstrapJoinFrame::JoinInit {
                eph_pub,
                static_pub,
                requested_vip,
                client_nonce,
            } => Ok(JoinInitReq {
                eph_pub,
                static_pub,
                requested_vip,
                client_nonce,
            }),
            _ => Err(BootstrapServerError::Malformed("not a JoinInit".into())),
        }
    }

    fn encode_join_reply(&self, r: &JoinReplyResp) -> Result<Vec<u8>, BootstrapServerError> {
        let frame = BootstrapJoinFrame::JoinReply {
            eph_pub: r.eph_pub,
            static_pub: r.static_pub,
            assigned_vip: r.assigned_vip.clone(),
            lease_secs: r.lease_secs,
            hb_interval_ms: r.hb_interval_ms,
            refresh_interval_ms: r.refresh_interval_ms,
            server_nonce: r.server_nonce,
        };
        encode_join_frame(&frame).map_err(Self::map_err)
    }

    fn encode_error(
        &self,
        code: BootstrapOuterCode,
        message: &str,
    ) -> Result<Vec<u8>, BootstrapServerError> {
        let frame = BootstrapJoinFrame::Error {
            code: Self::outer_code_to_discovery(code),
            message: message.to_string(),
        };
        encode_join_frame(&frame).map_err(Self::map_err)
    }

    fn split_outer<'a>(&self, payload: &'a [u8]) -> Result<OuterKind<'a>, BootstrapServerError> {
        match split_outer(payload).map_err(Self::map_err)? {
            nexus_discovery::bootstrap_join::OuterFrame::Secured(b) => Ok(OuterKind::Secured(b)),
            nexus_discovery::bootstrap_join::OuterFrame::Plain(BootstrapJoinFrame::JoinInit {
                eph_pub,
                static_pub,
                requested_vip,
                client_nonce,
            }) => Ok(OuterKind::JoinInit(JoinInitReq {
                eph_pub,
                static_pub,
                requested_vip,
                client_nonce,
            })),
            nexus_discovery::bootstrap_join::OuterFrame::Plain(_) => Ok(OuterKind::OtherPlain),
        }
    }

    fn encode_join_init(&self, req: &JoinInitReq) -> Result<Vec<u8>, BootstrapServerError> {
        let frame = BootstrapJoinFrame::JoinInit {
            eph_pub: req.eph_pub,
            static_pub: req.static_pub,
            requested_vip: req.requested_vip.clone(),
            client_nonce: req.client_nonce,
        };
        encode_join_frame(&frame).map_err(Self::map_err)
    }

    fn decode_join_reply(&self, body: &[u8]) -> Result<JoinReplyResp, BootstrapServerError> {
        match decode_join_frame(body).map_err(Self::map_err)? {
            BootstrapJoinFrame::JoinReply {
                eph_pub,
                static_pub,
                assigned_vip,
                lease_secs,
                hb_interval_ms,
                refresh_interval_ms,
                server_nonce,
            } => Ok(JoinReplyResp {
                eph_pub,
                static_pub,
                assigned_vip,
                lease_secs,
                hb_interval_ms,
                refresh_interval_ms,
                server_nonce,
            }),
            _ => Err(BootstrapServerError::Malformed("not a JoinReply".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_roundtrip_maps_both_directions() {
        let codec = DiscoveryBootstrapCodec::new();
        let cases = vec![
            BootstrapCtrl::Register {
                node_id: "n".into(),
                virtual_ip: "10.0.0.2".into(),
                locator: "udp://h:1".into(),
            },
            BootstrapCtrl::RegisterAck {
                accepted: true,
                ttl_secs: 60,
            },
            BootstrapCtrl::GetPeers {
                node_id: "n".into(),
            },
            BootstrapCtrl::PeerList {
                peers: vec![BootstrapPeer {
                    node_id: "n".into(),
                    virtual_ip: "10.0.0.2".into(),
                    locator: "udp://h:1".into(),
                }],
            },
            BootstrapCtrl::Heartbeat {
                node_id: "n".into(),
                now: 42,
            },
        ];
        for c in &cases {
            let bytes = codec.encode(c).expect("encode");
            let back = codec.decode(&bytes).expect("decode");
            assert_eq!(&back, c);
        }
    }

    #[test]
    fn outer_join_init_reply_and_error_roundtrip() {
        let codec = DiscoveryBootstrapCodec::new();
        // JoinReply encode + split_outer.
        let reply = JoinReplyResp {
            eph_pub: [1u8; 32],
            static_pub: [2u8; 32],
            assigned_vip: "10.0.0.5".into(),
            lease_secs: 60,
            hb_interval_ms: 1,
            refresh_interval_ms: 2,
            server_nonce: 9,
        };
        let body = codec.encode_join_reply(&reply).expect("reply body");
        // Error frame.
        let err = codec
            .encode_error(BootstrapOuterCode::RateLimited, "slow")
            .expect("err body");
        assert_eq!(err[0], 0x12);
        // split_outer: Secured probe.
        let mut secured = vec![0x01u8; 38];
        secured[1] = 0x03;
        match codec.split_outer(&secured).expect("split") {
            OuterKind::Secured(b) => assert_eq!(b.len(), 38),
            other => panic!("expected secured, got {other:?}"),
        }
        // split_outer: OtherPlain for error frame.
        match codec.split_outer(&err).expect("split err") {
            OuterKind::OtherPlain => {}
            other => panic!("expected other plain, got {other:?}"),
        }
        // split_outer: JoinInit.
        let init = BootstrapJoinFrame::JoinInit {
            eph_pub: [1u8; 32],
            static_pub: [2u8; 32],
            requested_vip: None,
            client_nonce: 5,
        };
        let init_body = encode_join_frame(&init).unwrap();
        match codec.split_outer(&init_body).expect("split init") {
            OuterKind::JoinInit(req) => {
                assert_eq!(req.client_nonce, 5);
                assert_eq!(req.static_pub, [2u8; 32]);
            }
            other => panic!("expected join init, got {other:?}"),
        }
        let _ = &body;
    }
}
