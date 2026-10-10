//! 真实 TCP 交付 E4：直连不可达时回退真实 relay（DIAL + 双向字节中继）。
//!
//! 布局：host 线程（真实监听）+ relay 线程（真实监听）；直连候选指向
//! 一个已释放端口（与 NAT 候选地址对外不可达同构），请求方把 `target`
//!（relay 可达的真实 host 地址）交给 relay 拨号，经 relay 完成线上认证
//! 与 service ECHO 往返。
//!
//! 输出单个 JSON 对象（场景求值器要求）。

use nexus::{relay_serve_once, remote_host_serve_once, remote_real_flow_with_relay};

fn main() {
    let token = "nexus-preshared-token";

    let host_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind host");
    let host_addr = host_listener.local_addr().expect("host local addr");

    let relay_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay local addr");

    let host_listener_clone = host_listener.try_clone().expect("clone host listener");
    let relay_listener_clone = relay_listener.try_clone().expect("clone relay listener");

    let host =
        std::thread::spawn(move || remote_host_serve_once(&host_listener_clone, token, "service"));
    let relay = std::thread::spawn(move || relay_serve_once(&relay_listener_clone));

    // 直连候选：绑定后立即释放的端口 -> 真实 connect 必然失败（ConnectRefused）。
    let direct = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        probe.local_addr().expect("probe local addr")
    };

    let client = remote_real_flow_with_relay(&direct, &host_addr, &relay_addr, token, "service")
        .expect("real relay flow");

    let host_json = host
        .join()
        .expect("join host thread")
        .expect("host serve once");
    let relay_json = relay
        .join()
        .expect("join relay thread")
        .expect("relay serve once");

    let mut out = client;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("host".to_string(), host_json);
        obj.insert("relay".to_string(), relay_json);
    }
    println!("{out}");
}
