use crate::protocol::{DebugRequest, DebugResponse};
use crate::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
use tokio_rustls::TlsConnector;
use tracing::info;

pub struct RemoteClient {
    stream: Box<dyn AsyncReadWrite + Unpin + Send>,
}

trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

impl RemoteClient {
    pub async fn connect(addr: &str, token: String, use_tls: bool) -> Result<Self> {
        info!("Connecting to remote debugger at {}", addr);
        let stream = TcpStream::connect(addr).await?;

        let stream: Box<dyn AsyncReadWrite + Unpin + Send> = if use_tls {
            let root_cert_store = RootCertStore::empty();
            // In a real scenario, we might want to load system certs or a specific CA.
            // For now, let's assume the user might want a way to skip verification or provide a cert.
            let config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            
            let connector = TlsConnector::from(Arc::new(config));
            let domain = ServerName::try_from("localhost")?; // Should be parsed from addr
            let tls_stream = connector.connect(domain, stream).await?;
            Box::new(tls_stream)
        } else {
            Box::new(stream)
        };

        let mut client = Self { stream };

        // Perform handshake
        let handshake = DebugRequest::Handshake { token };
        let json = serde_json::to_vec(&handshake)?;
        client.stream.write_all(&json).await?;

        let mut buffer = vec![0u8; 8192];
        let n = client.stream.read(&mut buffer).await?;
        let response: DebugResponse = serde_json::from_slice(&buffer[..n])?;

        match response {
            DebugResponse::AuthSuccess => {
                info!("Authentication successful");
                Ok(client)
            }
            DebugResponse::AuthFailed => Err(anyhow::anyhow!("Authentication failed")),
            _ => Err(anyhow::anyhow!("Unexpected response during handshake")),
        }
    }

    pub async fn send_request(&mut self, request: DebugRequest) -> Result<DebugResponse> {
        let json = serde_json::to_vec(&request)?;
        self.stream.write_all(&json).await?;

        let mut buffer = vec![0u8; 8192];
        let n = self.stream.read(&mut buffer).await?;
        let response: DebugResponse = serde_json::from_slice(&buffer[..n])?;
        Ok(response)
    }
}
