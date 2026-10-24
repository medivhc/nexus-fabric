//! probe 自建 rustls 客户端（D-8）：本地 skip-verify verifier，不复用协议 crate 的 TLS helper。

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

#[derive(Debug)]
struct NoVerify {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构造客户端 TLS 配置（skip=true 时不做链/主机名校验）。
pub fn client_config(
    skip_verify: bool,
    alpn: &[String],
) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?;
    let mut cfg = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify { provider }))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(cfg))
}

/// TLS 连接（阻塞）；返回可读写流。
pub fn connect(
    host: &str,
    port: u16,
    sni: &str,
    skip_verify: bool,
    alpn: &[String],
    timeout: Duration,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let cfg = client_config(skip_verify, alpn)?;
    let name = ServerName::try_from(sni.to_string()).map_err(|_| format!("invalid sni {sni}"))?;
    let tcp =
        TcpStream::connect((host, port)).map_err(|e| format!("tcp connect {host}:{port}: {e}"))?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(cfg, name)
        .map_err(|e| format!("tls client connection: {e}"))?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    // 触发握手（写 0 字节即驱动；rustls 在首次 I/O 完成握手）。
    stream.flush().map_err(|e| format!("tls handshake: {e}"))?;
    Ok(stream)
}

/// 写全部字节（对 `rustls::StreamOwned` 使用）。
pub fn write_all(stream: &mut impl Write, bytes: &[u8]) -> Result<(), String> {
    stream.write_all(bytes).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}
