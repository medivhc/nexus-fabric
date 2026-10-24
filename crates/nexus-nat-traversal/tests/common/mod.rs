#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_nat_traversal::{
    LocalCandidates, PunchAnswer, PunchChannel, PunchClock, PunchOffer, PunchSocket,
};

#[derive(Default)]
pub struct ManualPunchClock {
    now: AtomicU64,
    sleeps: Mutex<Vec<u64>>,
}

impl ManualPunchClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn at(ms: u64) -> Arc<Self> {
        let c = Self::default();
        c.now.store(ms, Ordering::SeqCst);
        Arc::new(c)
    }
    pub fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    pub fn sleeps(&self) -> Vec<u64> {
        self.sleeps.lock().unwrap().clone()
    }
}

impl PunchClock for ManualPunchClock {
    fn now_ms(&self) -> u64 {
        self.now()
    }
    fn wall_ms(&self) -> u64 {
        1_700_000_000_000 + self.now()
    }
    fn sleep_until_ms(&self, deadline_ms: u64) {
        let now = self.now();
        if deadline_ms > now {
            self.sleeps.lock().unwrap().push(deadline_ms - now);
            self.now.store(deadline_ms, Ordering::SeqCst);
        }
    }
    fn sleep_ms(&self, ms: u64) {
        self.sleeps.lock().unwrap().push(ms);
        self.now.fetch_add(ms, Ordering::SeqCst);
    }
}

pub struct FakeChannel {
    pub offers: Mutex<Vec<PunchOffer>>,
    pub answers: Mutex<Vec<PunchAnswer>>,
    pub clock: Arc<ManualPunchClock>,
    /// Template answered with the nonce of the latest sent offer (None = no auto answer).
    pub auto_answer: Mutex<Option<PunchAnswer>>,
    /// When set, `recv_answer` consumes this much virtual time before answering.
    pub consume_before_answer_ms: AtomicU64,
    /// When no answer is queued, `recv_answer` consumes the whole timeout then times out.
    pub always_timeout: bool,
}

impl FakeChannel {
    pub fn new(clock: Arc<ManualPunchClock>, answers: Vec<PunchAnswer>) -> Arc<Self> {
        Arc::new(Self {
            offers: Mutex::new(Vec::new()),
            answers: Mutex::new(answers),
            clock,
            auto_answer: Mutex::new(None),
            consume_before_answer_ms: AtomicU64::new(0),
            always_timeout: false,
        })
    }
    pub fn timeout_only(clock: Arc<ManualPunchClock>) -> Arc<Self> {
        let mut c = Self {
            offers: Mutex::new(Vec::new()),
            answers: Mutex::new(Vec::new()),
            clock,
            auto_answer: Mutex::new(None),
            consume_before_answer_ms: AtomicU64::new(0),
            always_timeout: true,
        };
        c.always_timeout = true;
        Arc::new(c)
    }
}

impl PunchChannel for FakeChannel {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
        self.offers.lock().unwrap().push(offer.clone());
        Ok(())
    }
    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer> {
        if self.always_timeout {
            self.clock.sleep_ms(timeout.as_millis() as u64);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "no answer"));
        }
        let consume = self.consume_before_answer_ms.load(Ordering::SeqCst);
        if consume > 0 {
            self.clock.sleep_ms(consume);
        }
        if let Some(a) = self.answers.lock().unwrap().pop() {
            return Ok(a);
        }
        let template = self.auto_answer.lock().unwrap().clone();
        if let Some(t) = template {
            let nonce = self
                .offers
                .lock()
                .unwrap()
                .last()
                .map(|o| o.nonce)
                .unwrap_or(0);
            return Ok(PunchAnswer { nonce, ..t });
        }
        self.clock.sleep_ms(timeout.as_millis() as u64);
        Err(io::Error::new(io::ErrorKind::TimedOut, "no answer"))
    }
}

pub struct FakeSocket {
    pub sends: Mutex<Vec<(SocketAddr, u64)>>,
    pub clock: Arc<ManualPunchClock>,
    /// Virtual ms `await_direct` consumes before succeeding/timing out.
    pub await_consume_ms: AtomicU64,
    pub direct: Mutex<Option<SocketAddr>>,
}

impl FakeSocket {
    pub fn new(clock: Arc<ManualPunchClock>, direct: Option<SocketAddr>) -> Arc<Self> {
        Arc::new(Self {
            sends: Mutex::new(Vec::new()),
            clock,
            await_consume_ms: AtomicU64::new(0),
            direct: Mutex::new(direct),
        })
    }
    pub fn send_count(&self) -> usize {
        self.sends.lock().unwrap().len()
    }
    pub fn targets(&self) -> Vec<SocketAddr> {
        self.sends.lock().unwrap().iter().map(|(a, _)| *a).collect()
    }
    pub fn times(&self) -> Vec<u64> {
        self.sends.lock().unwrap().iter().map(|(_, t)| *t).collect()
    }
}

impl PunchSocket for FakeSocket {
    fn send_punch(&self, target: SocketAddr, _payload: &[u8]) -> io::Result<()> {
        let now = self.clock.now();
        self.sends.lock().unwrap().push((target, now));
        Ok(())
    }
    fn await_direct(&self, timeout: Duration) -> io::Result<SocketAddr> {
        let consume = self.await_consume_ms.load(Ordering::SeqCst);
        self.clock.sleep_ms(consume.min(timeout.as_millis() as u64));
        match *self.direct.lock().unwrap() {
            Some(a) => Ok(a),
            None => Err(io::Error::new(io::ErrorKind::TimedOut, "no direct")),
        }
    }
}

pub fn local_host(port: u16) -> LocalCandidates {
    use nexus_connectivity::nat::NatType;
    LocalCandidates {
        host: vec![format!("10.0.0.2:{port}").parse().unwrap()],
        srflx: None,
        srflx_stun: None,
        srflx_turn: None,
        nat_type: NatType::FullCone,
    }
}
