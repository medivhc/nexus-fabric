//! 真实 TCP 交付 E4：host 线程（服务端 AUTH 门控 + service ECHO 业务）
//! + 请求方真实闭环（真实 Endpoint 帧流 + 线上认证）。
//!
//! 输出单个 JSON 对象（场景求值器要求）。

use nexus::{remote_host_serve_once, remote_real_flow};

fn main() {
    let token = "nexus-preshared-token";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind host");
    let addr = listener.local_addr().expect("host local addr");
    let listener_clone = listener.try_clone().expect("clone host listener");

    let host =
        std::thread::spawn(move || remote_host_serve_once(&listener_clone, token, "service"));
    let client = remote_real_flow(&addr, token, "service").expect("real host flow");

    let host_json = host
        .join()
        .expect("join host thread")
        .expect("host serve once");

    let mut out = client;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("host".to_string(), host_json);
    }
    println!("{out}");
}
