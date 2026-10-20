//! S5 permits loss: the formal example requires at least one received datagram.
use super::{DATAGRAMS, receive_example_datagrams};

fn one_then_error(error: &str) -> Result<usize, String> {
    let mut first = Some(vec![7; 200]);
    receive_example_datagrams(|| first.take().ok_or_else(|| error.to_string()))
}

#[test]
fn one_valid_datagram_then_timeout_satisfies_best_effort_example() {
    let result = one_then_error("dgram recv: timeout");
    assert!(
        matches!(result, Ok(count) if (1..=DATAGRAMS).contains(&count)),
        "S5 allows the remaining datagrams to be lost: {result:?}"
    );
}

#[test]
fn one_valid_datagram_then_closed_satisfies_best_effort_example() {
    let result = one_then_error("dgram recv: closed");
    assert!(
        matches!(result, Ok(count) if (1..=DATAGRAMS).contains(&count)),
        "a later close cannot erase the received datagram: {result:?}"
    );
}

#[test]
fn timeout_before_any_datagram_cannot_claim_a_received_datagram() {
    let result = receive_example_datagrams(|| Err("dgram recv: timeout".into()));
    assert!(
        !matches!(result, Ok(count) if count > 0),
        "no datagram arrived: {result:?}"
    );
}

#[test]
fn closed_before_any_datagram_cannot_claim_a_received_datagram() {
    let result = receive_example_datagrams(|| Err("dgram recv: closed".into()));
    assert!(
        !matches!(result, Ok(count) if count > 0),
        "no datagram arrived: {result:?}"
    );
}

#[test]
fn hundred_valid_datagrams_satisfy_example_without_requiring_all_reads() {
    let mut datagrams = std::iter::repeat_n(vec![7; 200], DATAGRAMS);
    let result =
        receive_example_datagrams(|| datagrams.next().ok_or_else(|| "dgram recv: timeout".into()));
    assert!(
        matches!(result, Ok(count) if (1..=DATAGRAMS).contains(&count)),
        "loss-free positive control must satisfy the example: {result:?}"
    );
}

#[test]
fn invalid_lengths_then_timeout_cannot_claim_a_valid_datagram() {
    for length in [0, 199, 201] {
        let mut first = Some(vec![7; length]);
        let result =
            receive_example_datagrams(|| first.take().ok_or_else(|| "dgram recv: timeout".into()));
        assert!(
            !matches!(result, Ok(count) if count > 0),
            "{length}B is not a valid 200B example datagram: {result:?}"
        );
    }
}

#[test]
fn invalid_lengths_then_closed_cannot_claim_a_valid_datagram() {
    for length in [0, 199, 201] {
        let mut first = Some(vec![7; length]);
        let result =
            receive_example_datagrams(|| first.take().ok_or_else(|| "dgram recv: closed".into()));
        assert!(
            !matches!(result, Ok(count) if count > 0),
            "{length}B is not a valid 200B example datagram: {result:?}"
        );
    }
}

#[test]
fn invalid_prefix_then_valid_datagram_satisfies_best_effort_example() {
    let mut datagrams = [vec![], vec![7; 199], vec![7; 201], vec![7; 200]].into_iter();
    let result =
        receive_example_datagrams(|| datagrams.next().ok_or_else(|| "dgram recv: timeout".into()));
    assert!(
        matches!(result, Ok(count) if (1..=DATAGRAMS).contains(&count)),
        "invalid prefixes cannot prevent a later valid datagram from satisfying the example: {result:?}"
    );
}

#[test]
fn hundred_invalid_datagrams_cannot_claim_a_valid_datagram() {
    let mut datagrams = (0..DATAGRAMS).map(|index| vec![7; [0, 199, 201][index % 3]]);
    let result =
        receive_example_datagrams(|| datagrams.next().ok_or_else(|| "dgram recv: timeout".into()));
    assert!(
        !matches!(result, Ok(count) if count > 0),
        "exhausting a bounded stream of invalid datagrams cannot fabricate valid receipt: {result:?}"
    );
}
