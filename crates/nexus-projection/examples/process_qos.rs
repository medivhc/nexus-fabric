//! E4: product.fabric-process-qos — process attribution + QoS marking (S26).
//!
//! Binds a loopback listener, connects from this process, attributes the
//! connection (expecting this example's own process name), classifies it
//! via a QosConfig rule, and checks the unknown-tuple case.
//! Uses only public API + observable output. Non-Linux prints
//! `{"verdict":"SKIP",...}` instead of failing.

use nexus_projection::{
    FlowLabels, PlatformAttributor, ProcessAttributor, Proto, QosClass, QosConfig,
};
use std::net::{SocketAddr, TcpListener, TcpStream};

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    if cfg!(not(target_os = "linux")) {
        println!(r#"{{"verdict":"SKIP","reason":"non-linux: NoopAttributor always unknown"}}"#);
        return;
    }

    // This process connects to its own listener: the attributed socket is
    // the client's (local=client addr, remote=listener addr).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let server_addr = listener.local_addr().expect("local_addr");
    let client = TcpStream::connect(server_addr).expect("connect");
    let client_addr = client.local_addr().expect("client local_addr");
    let (_srv, _) = listener.accept().expect("accept");

    let attributor = PlatformAttributor;
    let attr = attributor.attribute(client_addr, server_addr, Proto::Tcp);
    let name = attr.process_name.clone().expect("process_name resolved");
    assert!(attr.pid.is_some(), "pid resolved");

    // Classify the observed name as High via an exact-match rule.
    let qos = QosConfig::new().with_rule(&name, QosClass::High);
    let labels = FlowLabels::attribute(&attributor, &qos, client_addr, server_addr, Proto::Tcp);
    assert_eq!(labels.qos_class, QosClass::High);
    assert_eq!(labels.process_name.as_deref(), Some(name.as_str()));

    // Unknown tuple: no socket behind it → unknown → Normal.
    let unknown = attributor.attribute(
        SocketAddr::from(([127, 0, 0, 1], 1)),
        SocketAddr::from(([127, 0, 0, 1], 2)),
        Proto::Tcp,
    );
    assert_eq!(unknown.pid, None);
    assert_eq!(unknown.process_name, None);
    assert_eq!(
        qos.classify(unknown.process_name.as_deref()),
        QosClass::Normal
    );

    println!(
        r#"{{"verdict":"PASS","attribution":{{"process_name":"{}","qos_class":"High"}},"unknown_case":true}}"#,
        json_escape(&name)
    );
}
