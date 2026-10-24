use nexus_connectivity::nat::NatType;
use nexus_nat_traversal::{
    CandidateKind, MAX_CANDIDATES, PredictionHint, PunchAnswer, PunchCandidate, PunchOffer,
    SIGNAL_VERSION, SignalError, decode_answer, decode_answer_v1, decode_offer, decode_offer_v1,
    encode_answer, encode_answer_v1, encode_offer, encode_offer_v1,
};

fn cand(port: u16) -> PunchCandidate {
    PunchCandidate {
        addr: format!("198.51.100.1:{port}").parse().unwrap(),
        kind: CandidateKind::Srflx,
    }
}

fn offer(prediction: Option<PredictionHint>) -> PunchOffer {
    PunchOffer {
        version: SIGNAL_VERSION,
        nonce: 0x1122334455667788,
        candidates: vec![cand(40000), cand(40001)],
        nat_type: NatType::PortRestrictedCone,
        start_at_ms: 1_700_000_000_123,
        prediction,
    }
}

fn ans(prediction: Option<PredictionHint>) -> PunchAnswer {
    PunchAnswer {
        version: SIGNAL_VERSION,
        nonce: 0x1122334455667788,
        candidates: vec![cand(50000)],
        nat_type: NatType::Symmetric,
        prediction,
    }
}

#[test]
fn g8_signal_v2_prediction_hint_roundtrip() {
    let hint = PredictionHint {
        base_port: 40002,
        delta: -3,
        samples: 4,
    };
    let o = offer(Some(hint));
    let enc = encode_offer(&o);
    assert_eq!(enc[0], 2, "v2 wire version");
    assert_eq!(decode_offer(&enc).unwrap(), o, "offer prediction roundtrip");

    let a = ans(Some(hint));
    let enc = encode_answer(&a);
    assert_eq!(
        decode_answer(&enc).unwrap(),
        a,
        "answer prediction roundtrip"
    );

    // version boundaries: v2 entry rejects 1 and 3, v1 entry rejects 2/3.
    let mut v1 = encode_offer_v1(&offer(None));
    assert_eq!(v1[0], 1);
    assert_eq!(decode_offer(&v1), Err(SignalError::Version));
    let mut v3 = encode_offer(&offer(None));
    v3[0] = 3;
    assert_eq!(decode_offer(&v3), Err(SignalError::Version));
    v1[0] = 1;
    assert_eq!(decode_offer_v1(&v1).unwrap().version, 1);
    assert_eq!(
        decode_offer_v1(&encode_offer(&offer(None))),
        Err(SignalError::Version)
    );

    // v1 layout bytes unchanged vs current baseline.
    let o_v1 = offer(None);
    let mut expected = vec![1u8];
    expected.extend_from_slice(&o_v1.nonce.to_be_bytes());
    expected.push(1u8); // PortRestrictedCone
    expected.extend_from_slice(&o_v1.start_at_ms.to_be_bytes());
    expected.push(2u8);
    for c in &o_v1.candidates {
        expected.push(1u8); // Srflx
        expected.push(4u8);
        expected.extend_from_slice(&[198, 51, 100, 1]);
        expected.extend_from_slice(&c.addr.port().to_be_bytes());
    }
    assert_eq!(encode_offer_v1(&o_v1), expected);

    // BadPrediction: samples < 3 and non-boolean flag.
    let mut bad = enc.clone();
    let n = bad.len();
    bad[n - 1] = 2; // samples byte
    assert_eq!(decode_offer(&bad), Err(SignalError::BadPrediction));
    let mut b = encode_offer(&offer(None));
    let flag_at = b.len() - 1;
    b[flag_at] = 2;
    assert_eq!(decode_offer(&b), Err(SignalError::BadPrediction));
}

#[test]
fn g18_encode_candidate_cap_16() {
    let o = PunchOffer {
        version: SIGNAL_VERSION,
        nonce: 9,
        candidates: (0..17).map(|i| cand(40000 + i)).collect(),
        nat_type: NatType::FullCone,
        start_at_ms: 0,
        prediction: None,
    };
    let enc = encode_offer(&o);
    let dec = decode_offer(&enc).unwrap();
    assert_eq!(dec.candidates.len(), MAX_CANDIDATES, "encoded capped to 16");

    // Decoder rejects >16 on the wire.
    let mut raw = enc.clone();
    // candidate count offset for offer: version(1)+nonce(8)+nat(1)+start(8) = 18
    raw[18] = 17;
    assert_eq!(decode_offer(&raw), Err(SignalError::TooMany));
}

#[test]
fn answer_v1_roundtrip_keeps_old_layout() {
    let a = ans(None);
    let enc = encode_answer_v1(&a);
    assert_eq!(enc[0], 1);
    let back = decode_answer_v1(&enc).unwrap();
    assert_eq!(back.nonce, a.nonce);
    assert_eq!(back.candidates, a.candidates);
    assert!(back.prediction.is_none());
}
