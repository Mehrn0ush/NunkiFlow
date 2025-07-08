use rustls::{ClientConnection, ServerConnection};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use webpki_roots;


/// Represents a raw TLS record or handshake message.
///
/// Fields:
/// - `content_type`: The TLS ContentType byte (e.g., 0x16 = Handshake, 0x17 = ApplicationData).
/// - `version`: The 16-bit TLS version (e.g., 0x0303 for TLS 1.2, 0x0304 for TLS 1.3).
/// - `payload`: A slice pointing to the raw record payload (excluding the 5-byte TLS header).
/// - `is_handshake`: `true` if this record contains a handshake message (`content_type == 0x16`).
/// - `handshake_type`: If `is_handshake` is `true`, this holds the 1-byte HandshakeType (e.g., 0x01 = ClientHello, 0x02 = ServerHello). Otherwise `None`.

#[derive(Debug)]
pub struct TlsMessage<'a> {
    pub content_type: u8,
    pub version: u16,
    pub payload: &'a [u8],
    pub is_handshake: bool,
    pub handshake_type: Option<u8>,
}


/// Contains parsed TLS connection parameters extracted from a “Hello” message.
///
/// Fields:
/// - `protocol_version`: The negotiated TLS protocol version (`ProtocolVersion`).
/// - `cipher_suite`: The negotiated cipher suite (`SupportedCipherSuite`).
/// - `alpn_protocol`: The negotiated ALPN protocol (e.g., `b"http/1.1"`), if any.

#[derive(Debug)]
pub struct TlsInfo {
    pub protocol_version: rustls::ProtocolVersion,
    pub cipher_suite: rustls::SupportedCipherSuite,
    pub alpn_protocol: Option<Vec<u8>>,
}


/// A helper for parsing ClientHello or ServerHello messages using rustls’ handshake engine.
///
/// Internally holds:
/// - `client_config`: A `ClientConfig` with default root certificates (via webpki_roots).
/// - `server_config`: A minimal `ServerConfig` that resolves certificates based on SNI (no actual cert provided).

pub struct TlsParser {
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
}

impl TlsParser {
    /// Constructs a new `TlsParser` with default system roots (for client) and a placeholder server config.
    ///
    /// - The client side is configured with `webpki_roots::TLS_SERVER_ROOTS` as the trust anchors.
    /// - The server side uses `ResolvesServerCertUsingSni` so it can parse ServerHello messages
    ///   (but does not actually validate certificates or keys).
    ///
    /// # Example
    /// ```rust
    /// let parser = TlsParser::new();
    /// ``
    pub fn new() -> Self {
        // Create a client config with default root certificates
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Create a server config
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

        Self {
            client_config: Arc::new(client_config),
            server_config: Arc::new(server_config),
        }
    }

    /// Attempts to parse a raw ClientHello bytes and extract TLS connection parameters.
    ///
    /// The function:
    /// 1. Creates a `ClientConnection` using `self.client_config` and a placeholder server name (`"example.com"`).
    /// 2. Feeds the raw `data` into the client’s TLS engine via `read_tls`.
    /// 3. Calls `process_new_packets()` to let rustls parse the handshake up to the ClientHello.
    ///
    /// # Parameters
    /// - `data`: A byte slice containing the entire ClientHello record (including the 5-byte header).
    ///
    /// # Returns
    /// - `Some(TlsInfo)` if parsing succeeds and the ClientHello yields:
    ///     - A supported `protocol_version`.
    ///     - A negotiated `cipher_suite`.
    ///     - Any ALPN protocols proposed by the server (via `alpn_protocol`).
    /// - `None` if any step fails (e.g., invalid record, unsupported version, or rustls returns an error).
    ///
    /// # Example
    /// ```rust
    /// let parser = TlsParser::new();
    /// let client_hello_bytes: &[u8] = /* some captured handshake bytes */;
    /// if let Some(info) = parser.parse_client_hello(client_hello_bytes) {
    ///     println!("TLS version: {:?}", info.protocol_version);
    ///     println!("Cipher suite: {:?}", info.cipher_suite);
    ///     if let Some(alpn) = info.alpn_protocol {
    ///         println!("ALPN: {:?}", String::from_utf8(alpn).ok());
    ///     }
    /// }
    /// ```
    pub fn parse_client_hello(&self, data: &[u8]) -> Option<TlsInfo> {
        let server_name = ServerName::try_from("example.com").ok()?;
        let mut client = ClientConnection::new(self.client_config.clone(), server_name).ok()?;
        
        if client.wants_write() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).ok()?;
        }
        
        client.read_tls(&mut std::io::Cursor::new(data)).ok()?;
        client.process_new_packets().ok()?;
        
        Some(TlsInfo {
            protocol_version: client.protocol_version()?,
            cipher_suite: client.negotiated_cipher_suite()?,
            alpn_protocol: client.alpn_protocol().map(|p| p.to_vec()),
        })
    }

    /// Attempts to parse a raw ServerHello or subsequent handshake bytes and extract TLS info.
    ///
    /// This method:
    /// 1. Creates a `ServerConnection` using `self.server_config`.
    /// 2. Feeds the raw `data` into the server’s TLS engine via `read_tls`.
    /// 3. Calls `process_new_packets()` so rustls parses up to the ServerHello.
    ///
    /// # Parameters
    /// - `data`: A byte slice containing the entire ServerHello record(s) (including the 5-byte header).
    ///
    /// # Returns
    /// - `Some(TlsInfo)` if parsing succeeds and the ServerHello yields:
    ///     - A supported `protocol_version`.
    ///     - A negotiated `cipher_suite`.
    ///     - Any ALPN protocol the client requested (via `alpn_protocol`).
    /// - `None` if any step fails (e.g., invalid record, unsupported version, or rustls returns an error).
    ///
    /// # Example
    /// ```rust
    /// let parser = TlsParser::new();
    /// let server_hello_bytes: &[u8] = /* some captured handshake bytes */;
    /// if let Some(info) = parser.parse_server_hello(server_hello_bytes) {
    ///     println!("TLS version: {:?}", info.protocol_version);
    ///     println!("Cipher suite: {:?}", info.cipher_suite);
    ///     if let Some(alpn) = info.alpn_protocol {
    ///         println!("ALPN: {:?}", String::from_utf8(alpn).ok());
    ///     }
    /// }
    /// ```
    pub fn parse_server_hello(&self, data: &[u8]) -> Option<TlsInfo> {
        let mut server = ServerConnection::new(self.server_config.clone()).ok()?;
        
        server.read_tls(&mut std::io::Cursor::new(data)).ok()?;
        server.process_new_packets().ok()?;
        
        Some(TlsInfo {
            protocol_version: server.protocol_version()?,
            cipher_suite: server.negotiated_cipher_suite()?,
            alpn_protocol: server.alpn_protocol().map(|p| p.to_vec()),
        })
    }
} 