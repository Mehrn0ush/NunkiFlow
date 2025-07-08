use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::process;
use chrono;
use std::fs::File;
use std::io::Write;

mod pcap_reader;
mod packet_parser;
mod rustls_parser;
use x509_parser::parse_x509_certificate;
use crate::pcap_reader::read_all_packets;
use crate::packet_parser::{
    extract_tls_payload, TlsBuffer, extract_ip_addresses,
    extract_tcp_ports, extract_tcp_flags, extract_window_size, get_total_header_len
};
use crate::tls_parser::{parse_tls_record, HandshakeMessage};

// TLS Parser module
mod tls_parser {
    #[derive(Debug)]
    pub struct TlsRecord<'a> {
        pub content_type: u8,
        pub version: u16,
        pub length: u16,
        pub handshake: Option<HandshakeMessage<'a>>,
    }

    #[derive(Debug)]
    pub enum HandshakeMessage<'a> {
        ClientHello(ClientHello<'a>),
        ServerHello(ServerHello<'a>),
        Certificate(Vec<&'a [u8]>),
    }

    #[derive(Debug)]
    pub struct ClientHello<'a> {
        pub client_version: u16,
        pub random: &'a [u8],
        pub session_id: &'a [u8],
        pub cipher_suites: Vec<u16>,
        pub compression_methods: Vec<u8>,
        pub extensions: Vec<(u16, &'a [u8])>,
    }

    #[derive(Debug)]
    pub struct ServerHello<'a> {
        pub server_version: u16,
        pub cipher_suite: u16,
        pub extensions: Vec<(u16, &'a [u8])>,
    }

    pub fn parse_u16_be(data: &[u8]) -> Option<u16> {
        if data.len() < 2 { None } else { Some(((data[0] as u16) << 8) | (data[1] as u16)) }
    }

    pub fn parse_u24_be(data: &[u8]) -> Option<u32> {
        if data.len() < 3 { None } else { Some(((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32)) }
    }

    pub fn parse_tls_record<'a>(data: &'a [u8]) -> Option<TlsRecord<'a>> {
        if data.len() < 5 {
            return None;
        }

        let content_type = data[0];
        let version = parse_u16_be(&data[1..3])?;
        let length = parse_u16_be(&data[3..5])?;
        
        if data.len() < 5 + (length as usize) {
            return None;
        }

        match content_type {
            20 => { // Change Cipher Spec
                Some(TlsRecord {
                    content_type,
                    version,
                    length,
                    handshake: None,
                })
            },
            21 => { // Alert
                Some(TlsRecord {
                    content_type,
                    version,
                    length,
                    handshake: None,
                })
            },
            22 => { // Handshake
                let handshake_data = &data[5..5 + (length as usize)];
                if handshake_data.len() < 4 {
                    return None;
                }

                let handshake_type = handshake_data[0];
                let handshake_length = parse_u24_be(&handshake_data[1..4])? as usize;
                
                if handshake_data.len() < 4 + handshake_length {
                    return None;
                }

                match handshake_type {
                    1 => { // ClientHello
                        let client_hello_data = &handshake_data[4..4 + handshake_length];
                        if client_hello_data.len() < 2 + 32 + 1 { return None; }
                        let client_version = parse_u16_be(&client_hello_data[0..2])?;
                        let random = &client_hello_data[2..34];
                        let mut offset = 34;
                        if client_hello_data.len() < offset + 1 { return None; }
                        let session_id_len = client_hello_data[offset] as usize;
                        offset += 1;
                        if client_hello_data.len() < offset + session_id_len { return None; }
                        let session_id = &client_hello_data[offset..offset + session_id_len];
                        offset += session_id_len;
                        if client_hello_data.len() < offset + 2 { return None; }
                        let cipher_suites_len = parse_u16_be(&client_hello_data[offset..offset + 2])? as usize;
                        offset += 2;
                        let mut cipher_suites = Vec::new();
                        if client_hello_data.len() < offset + cipher_suites_len { return None; }
                        for _ in 0..(cipher_suites_len / 2) {
                            let cs = parse_u16_be(&client_hello_data[offset..offset + 2])?;
                            cipher_suites.push(cs);
                            offset += 2;
                        }
                        if client_hello_data.len() < offset + 1 { return None; }
                        let comp_methods_len = client_hello_data[offset] as usize;
                        offset += 1;
                        if client_hello_data.len() < offset + comp_methods_len { return None; }
                        let compression_methods = client_hello_data[offset..offset + comp_methods_len].to_vec();
                        offset += comp_methods_len;
                        let mut extensions = Vec::new();
                        if client_hello_data.len() >= offset + 2 {
                            let ext_total_len = parse_u16_be(&client_hello_data[offset..offset + 2])? as usize;
                            offset += 2;
                            let ext_end = offset + ext_total_len;
                            while offset + 4 <= ext_end && ext_end <= client_hello_data.len() {
                                let ext_type = parse_u16_be(&client_hello_data[offset..offset + 2])?;
                                let ext_len = parse_u16_be(&client_hello_data[offset + 2..offset + 4])? as usize;
                                offset += 4;
                                if client_hello_data.len() < offset + ext_len { break; }
                                let ext_data = &client_hello_data[offset..offset + ext_len];
                                extensions.push((ext_type, ext_data));
                                offset += ext_len;
                            }
                        }
                        Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::ClientHello(ClientHello {
                                client_version,
                                random,
                                session_id,
                                cipher_suites,
                                compression_methods,
                                extensions,
                            })),
                        })
                    },
                    2 => { // ServerHello
                        let server_hello_data = &handshake_data[4..4 + handshake_length];
                        if server_hello_data.len() < 2 + 32 + 1 { return None; }
                        let server_version = parse_u16_be(&server_hello_data[0..2])?;
                        let mut offset = 2 + 32;
                        if server_hello_data.len() < offset + 1 { return None; }
                        let session_id_len = server_hello_data[offset] as usize;
                        offset += 1;
                        if server_hello_data.len() < offset + session_id_len { return None; }
                        offset += session_id_len;
                        if server_hello_data.len() < offset + 2 { return None; }
                        let cipher_suite = parse_u16_be(&server_hello_data[offset..offset + 2])?;
                        offset += 2;
                        if server_hello_data.len() < offset + 1 { return None; }
                        let _comp_method = server_hello_data[offset];
                        offset += 1;
                        let mut extensions = Vec::new();
                        if server_hello_data.len() >= offset + 2 {
                            let ext_total_len = parse_u16_be(&server_hello_data[offset..offset + 2])? as usize;
                            offset += 2;
                            let ext_end = offset + ext_total_len;
                            while offset + 4 <= ext_end && ext_end <= server_hello_data.len() {
                                let ext_type = parse_u16_be(&server_hello_data[offset..offset + 2])?;
                                let ext_len = parse_u16_be(&server_hello_data[offset + 2..offset + 4])? as usize;
                                offset += 4;
                                if server_hello_data.len() < offset + ext_len { break; }
                                let ext_data = &server_hello_data[offset..offset + ext_len];
                                extensions.push((ext_type, ext_data));
                                offset += ext_len;
                            }
                        }
                        Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::ServerHello(ServerHello {
                                server_version,
                                cipher_suite,
                                extensions,
                            })),
                        })
                    },
                    11 => { // Certificate
                        let cert_msg_data = &handshake_data[4..4 + handshake_length];
                        
                        // Parse TLS Certificate message structure
                        let certificates = parse_tls_certificate_message(cert_msg_data);
                        
                        Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::Certificate(certificates)),
                        })
                    },
                    15 => { // CertificateVerify
                        let cert_verify_data = &handshake_data[4..4 + handshake_length];
                        Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::Certificate(vec![cert_verify_data])),
                        })
                    },
                    _ => {
                        Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: None,
                        })
                    }
                }
            },
            23 => { // Application Data
                Some(TlsRecord {
                    content_type,
                    version,
                    length,
                    handshake: None,
                })
            },
            _ => {
                if content_type >= 0x80 {
                    // Could be encrypted TLS 1.3 record
                    Some(TlsRecord {
                        content_type,
                        version,
                        length,
                        handshake: None,
                    })
                } else {
                    None
                }
            }
        }
    }

    // TLS Certificate message parsing
    pub fn parse_tls_certificate_message(cert_msg_data: &[u8]) -> Vec<&[u8]> {
        let mut certificates = Vec::new();
        let mut pos = 0;
        
        // Debug logging
        println!("Parsing TLS Certificate message of length: {}", cert_msg_data.len());
        
        if cert_msg_data.len() < 4 {
            println!("Certificate message too short: {} bytes", cert_msg_data.len());
            return certificates;
        }
        
        // Parse certificate_request_context (TLS 1.3)
        let context_len = cert_msg_data[pos] as usize;
        pos += 1;
        
        if pos + context_len > cert_msg_data.len() {
            println!("Invalid certificate request context length: {}", context_len);
            return certificates;
        }
        
        pos += context_len; // Skip context
        
        // Parse certificate_list length (3 bytes)
        if pos + 3 > cert_msg_data.len() {
            println!("Certificate message truncated at list length");
            return certificates;
        }
        
        let cert_list_len = ((cert_msg_data[pos] as usize) << 16) |
                            ((cert_msg_data[pos + 1] as usize) << 8) |
                            (cert_msg_data[pos + 2] as usize);
        pos += 3;
        
        println!("Certificate list length: {} bytes", cert_list_len);
        
        let cert_list_end = pos + cert_list_len;
        if cert_list_end > cert_msg_data.len() {
            println!("Certificate list extends beyond message: {} > {}", cert_list_end, cert_msg_data.len());
            return certificates;
        }
        
        // Parse individual CertificateEntry structures
        let mut cert_count = 0;
        while pos < cert_list_end && cert_count < 5 { // Limit to first 5 certificates
            if pos + 3 > cert_list_end {
                break;
            }
            
            // Parse cert_data length (3 bytes)
            let cert_data_len = ((cert_msg_data[pos] as usize) << 16) |
                               ((cert_msg_data[pos + 1] as usize) << 8) |
                               (cert_msg_data[pos + 2] as usize);
            pos += 3;
            
            if pos + cert_data_len > cert_list_end {
                println!("Certificate {} data extends beyond list", cert_count);
                break;
            }
            
            // Extract the actual X.509 certificate data
            let cert_data = &cert_msg_data[pos..pos + cert_data_len];
            certificates.push(cert_data);
            pos += cert_data_len;
            
            println!("Extracted certificate {}: {} bytes", cert_count, cert_data_len);
            
            // Parse extensions length (2 bytes)
            if pos + 2 > cert_list_end {
                break;
            }
            
            let ext_len = ((cert_msg_data[pos] as usize) << 8) | (cert_msg_data[pos + 1] as usize);
            pos += 2;
            
            if pos + ext_len > cert_list_end {
                println!("Certificate {} extensions extend beyond list", cert_count);
                break;
            }
            
            pos += ext_len; // Skip extensions
            cert_count += 1;
        }
        
        println!("Successfully parsed {} certificates from TLS message", certificates.len());
        certificates
    }
}

// Data structures
#[derive(Serialize, Debug)]
struct StaticConfig {
    tls_version: String,
    cipher_suites: Vec<String>,
    extensions: Vec<String>,
    pqc_key_exchange: Vec<String>,
    pqc_signature: Vec<String>,
    hybrid_scheme: Vec<String>,
    sni: Option<String>,
}

#[derive(Serialize, Debug)]
struct DynamicBehavior {
    handshake_duration: u64,
    client_hello_size: u32,
    server_hello_size: u32,
    retry_count: u32,
    encrypted_bytes: usize,
}

#[derive(Serialize, Debug)]
pub struct CertificateAnalysis {
    subject: Option<String>,
    issuer: Option<String>,
    validity_not_before: Option<String>,
    validity_not_after: Option<String>,
    pqc_certificate: Option<String>,
    certificate_transparency: bool,
    chain: Option<Vec<CertificateAnalysis>>,
}

#[derive(Serialize, Debug)]
struct ContextualData {
    client_ip: String,
    user_agent: Option<String>,
    fallback_behavior: bool,
    timestamp: String,
}

#[derive(Serialize, Debug)]
struct Fingerprint {
    version: String,
    hash_algorithm: String,
    static_hash: String,
    dynamic_hash: String,
    certificate_hash: String,
    contextual_hash: String,
    modular_fingerprint: String,
    primary_fingerprint: String,
    secondary_fingerprint: String,
}

#[derive(Serialize, Debug)]
pub struct FullRecord {
    static_config: StaticConfig,
    dynamic_behavior: DynamicBehavior,
    certificate_analysis: CertificateAnalysis,
    contextual_data: ContextualData,
    fingerprint: Fingerprint,
    ja3: Option<String>,
    ja4: Option<String>,
    ja4_r: Option<String>,
    sni: Option<String>,
}

struct SessionInfo {
    client_hello: Option<ClientHelloInfo>,
    server_hello: Option<ServerHelloInfo>,
    client_ip: String,
    timestamp: String,
}

struct ClientHelloInfo {
    version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
}

struct ServerHelloInfo {
    version: u16,
    cipher_suite: u16,
    extensions: Vec<u16>,
}

// CSV output structures
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq)]
struct FlowKey {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

// Helper function to convert IP bytes to string
fn ip_bytes_to_string(bytes: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

impl FlowKey {
    fn new(src_ip: String, dst_ip: String, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        // Convert string IPs to byte arrays
        let src_ip_bytes = ip_string_to_bytes(&src_ip);
        let dst_ip_bytes = ip_string_to_bytes(&dst_ip);
        
        // CICFlowMeter-style normalization: ensure consistent bidirectional flow keys
        // This ensures that flows A:B <-> C:D and C:D <-> A:B are treated as the same flow
        // The "smaller" IP:port combination is always used as the source
        if should_normalize_flow(&src_ip_bytes, &dst_ip_bytes, src_port, dst_port) {
            // Swap source and destination to normalize
            FlowKey {
                src_ip: dst_ip_bytes,
                dst_ip: src_ip_bytes,
                src_port: dst_port,
                dst_port: src_port,
                protocol,
            }
        } else {
            // Keep original order (already normalized)
            FlowKey {
                src_ip: src_ip_bytes,
                dst_ip: dst_ip_bytes,
                src_port,
                dst_port,
                protocol,
            }
        }
    }
    
    fn new_no_normalization(src_ip: String, dst_ip: String, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        // CICFlowMeter style: no normalization, preserve all flows as separate entries
        // This matches CICFlowMeter behavior where A:B->C:D and C:D->A:B are different flows
        let src_ip_bytes = ip_string_to_bytes(&src_ip);
        let dst_ip_bytes = ip_string_to_bytes(&dst_ip);
        
        FlowKey {
            src_ip: src_ip_bytes,
            dst_ip: dst_ip_bytes,
            src_port,
            dst_port,
            protocol,
        }
    }

    fn to_flow_id(&self) -> String {
        let src_ip = ip_bytes_to_string(self.src_ip);
        let dst_ip = ip_bytes_to_string(self.dst_ip);
        // Format: src_ip:src_port-dst_ip:dst_port (CICFlowMeter compatible)
        format!("{}-{}-{}-{}", src_ip, self.src_port, dst_ip, self.dst_port)
    }
    
    fn get_original_direction(&self, orig_src_ip: &[u8; 4], orig_dst_ip: &[u8; 4], orig_src_port: u16, orig_dst_port: u16) -> bool {
        // Returns true if the original packet direction matches the normalized flow direction
        orig_src_ip == &self.src_ip && orig_dst_ip == &self.dst_ip && 
        orig_src_port == self.src_port && orig_dst_port == self.dst_port
    }
}

fn should_normalize_flow(src_ip: &[u8; 4], dst_ip: &[u8; 4], src_port: u16, dst_port: u16) -> bool {
    // CICFlowMeter normalization: always put the "smaller" IP:port as source
    // This ensures bidirectional flows (A:B <-> C:D) are consistently represented
    // Compare IP addresses first (lexicographically)
    match src_ip.cmp(dst_ip) {
        std::cmp::Ordering::Greater => true,  // Swap if src_ip > dst_ip
        std::cmp::Ordering::Less => false,    // Keep if src_ip < dst_ip
        std::cmp::Ordering::Equal => src_port > dst_port, // If IPs equal, use ports
    }
}

fn ip_string_to_bytes(ip: &str) -> [u8; 4] {
    let mut bytes = [0u8; 4];
    let parts: Vec<&str> = ip.split('.').collect();
    
    if parts.len() != 4 {
        println!("Invalid IP address format: {}", ip);
        return bytes;
    }
    
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u8>() {
            Ok(num) => bytes[i] = num,
            Err(e) => {
                println!("Error parsing IP address part {}: {} - {}", i, part, e);
                bytes[i] = 0;
            }
        }
    }
    
    if bytes.iter().all(|&x| x == 0) {
        println!("Warning: All-zero IP address parsed from: {}", ip);
    }
    
    bytes
}

#[derive(Debug, Clone)]
struct PacketInfo {
    timestamp: u64,
    size: usize,
    header_len: usize,
    flags: packet_parser::TcpFlags,
    window_size: u32,
}

#[derive(Debug, Default)]
pub struct FlowStats {
    pub start_time: Option<u64>,
    pub last_time: Option<u64>,
    pub packet_times: Vec<u64>,
    pub fwd_packet_times: Vec<u64>, // Separate forward packet timestamps
    pub bwd_packet_times: Vec<u64>, // Separate backward packet timestamps
    pub fwd_packets: Vec<PacketInfo>,
    pub bwd_packets: Vec<PacketInfo>,
    pub tot_fwd_pkts: usize,
    pub tot_bwd_pkts: usize,
    pub totlen_fwd_pkts: usize,
    pub totlen_bwd_pkts: usize,
    pub fwd_pkt_len_max: usize,
    pub fwd_pkt_len_min: usize,
    pub fwd_pkt_len_mean: f64,
    pub fwd_pkt_len_std: f64,
    pub bwd_pkt_len_max: usize,
    pub bwd_pkt_len_min: usize,
    pub bwd_pkt_len_mean: f64,
    pub bwd_pkt_len_std: f64,
    pub flow_iat_mean: f64,
    pub flow_iat_std: f64,
    pub flow_iat_max: f64,
    pub flow_iat_min: f64,
    pub fwd_iat_mean: f64,
    pub fwd_iat_std: f64,
    pub bwd_iat_mean: f64,
    pub bwd_iat_std: f64,
    pub is_tls: bool,
    pub has_pqc: bool,
    pub pqc_counted: bool,
    pub has_kyber: bool,
    pub has_ml_dsa: bool,
    pub tls_version: String,
    pub tls_cipher_suite: String,
    pub tls_extensions: String,
    pub cert_algorithm: String,
    pub is_hybrid: bool,
    // TLS Extension Analysis fields
    pub critical_tls_extensions: String,
    pub pqc_relevant_extensions: String,
    pub tls13_features: String,
    pub supports_0rtt: String,
    pub extension_complexity: String,
    // Additional fields for flow statistics
    pub flow_byts_s: f64,
    pub flow_pkts_s: f64,
    pub pkt_len_max: usize,
    pub pkt_len_min: usize,
    pub pkt_len_mean: f64,
    pub pkt_len_std: f64,
    pub pkt_len_var: f64,
    pub fwd_header_len: usize,
    pub bwd_header_len: usize,
    pub fwd_seg_size_min: usize,
    pub fwd_act_data_pkts: usize,
    pub fwd_iat_tot: f64,
    pub fwd_iat_max: f64,
    pub fwd_iat_min: f64,
    pub bwd_iat_tot: f64,
    pub bwd_iat_max: f64,
    pub bwd_iat_min: f64,
    pub fwd_psh_flags: usize,
    pub bwd_psh_flags: usize,
    pub fwd_urg_flags: usize,
    pub bwd_urg_flags: usize,
    pub fin_flag_cnt: usize,
    pub syn_flag_cnt: usize,
    pub rst_flag_cnt: usize,
    pub psh_flag_cnt: usize,
    pub ack_flag_cnt: usize,
    pub urg_flag_cnt: usize,
    pub ece_flag_cnt: usize,
    pub down_up_ratio: f64,
    pub pkt_size_avg: f64,
    pub init_fwd_win_byts: u32,
    pub init_bwd_win_byts: u32,
    pub active_max: f64,
    pub active_min: f64,
    pub active_mean: f64,
    pub active_std: f64,
    pub idle_max: f64,
    pub idle_min: f64,
    pub idle_mean: f64,
    pub idle_std: f64,
    pub fwd_byts_b_avg: f64,
    pub fwd_pkts_b_avg: f64,
    pub bwd_byts_b_avg: f64,
    pub bwd_pkts_b_avg: f64,
    pub fwd_blk_rate_avg: f64,
    pub bwd_blk_rate_avg: f64,
    pub fwd_seg_size_avg: f64,
    pub bwd_seg_size_avg: f64,
    pub subflow_fwd_pkts: usize,
    pub subflow_bwd_pkts: usize,
    pub subflow_fwd_byts: usize,
    pub subflow_bwd_byts: usize,
    // PQC-specific fields
    pub pqc_key_exchanges: Vec<String>,
    pub key_shares: Vec<String>,
    pub pqc_signatures: Vec<String>,
    // Active/idle tracking
    pub last_activity_time: Option<u64>,
    pub current_active_period: Option<u64>,
    pub current_idle_period: Option<u64>,
    pub active_periods: Vec<f64>,
    pub idle_periods: Vec<f64>,
}

impl FlowStats {
    fn new() -> Self {
        FlowStats {
            start_time: None,
            last_time: None,
            packet_times: Vec::new(),
            fwd_packet_times: Vec::new(),
            bwd_packet_times: Vec::new(),
            fwd_packets: Vec::new(),
            bwd_packets: Vec::new(),
            tot_fwd_pkts: 0,
            tot_bwd_pkts: 0,
            totlen_fwd_pkts: 0,
            totlen_bwd_pkts: 0,
            fwd_pkt_len_max: 0,
            fwd_pkt_len_min: 0,
            fwd_pkt_len_mean: 0.0,
            fwd_pkt_len_std: 0.0,
            bwd_pkt_len_max: 0,
            bwd_pkt_len_min: 0,
            bwd_pkt_len_mean: 0.0,
            bwd_pkt_len_std: 0.0,
            flow_iat_mean: 0.0,
            flow_iat_std: 0.0,
            flow_iat_max: 0.0,
            flow_iat_min: 0.0,
            fwd_iat_mean: 0.0,
            fwd_iat_std: 0.0,
            bwd_iat_mean: 0.0,
            bwd_iat_std: 0.0,
            is_tls: false,
            has_pqc: false,
            pqc_counted: false,
            has_kyber: false,
            has_ml_dsa: false,
            tls_version: String::from("Unknown"),
            tls_cipher_suite: String::new(),
            tls_extensions: String::new(),
            cert_algorithm: String::from("Unknown"),
            is_hybrid: false,
            critical_tls_extensions: String::new(),
            pqc_relevant_extensions: String::new(),
            tls13_features: String::new(),
            supports_0rtt: String::new(),
            extension_complexity: String::new(),
            flow_byts_s: 0.0,
            flow_pkts_s: 0.0,
            pkt_len_max: 0,
            pkt_len_min: 0,
            pkt_len_mean: 0.0,
            pkt_len_std: 0.0,
            pkt_len_var: 0.0,
            fwd_header_len: 0,
            bwd_header_len: 0,
            fwd_seg_size_min: 0,
            fwd_act_data_pkts: 0,
            fwd_iat_tot: 0.0,
            fwd_iat_max: 0.0,
            fwd_iat_min: 0.0,
            bwd_iat_tot: 0.0,
            bwd_iat_max: 0.0,
            bwd_iat_min: 0.0,
            fwd_psh_flags: 0,
            bwd_psh_flags: 0,
            fwd_urg_flags: 0,
            bwd_urg_flags: 0,
            fin_flag_cnt: 0,
            syn_flag_cnt: 0,
            rst_flag_cnt: 0,
            psh_flag_cnt: 0,
            ack_flag_cnt: 0,
            urg_flag_cnt: 0,
            ece_flag_cnt: 0,
            down_up_ratio: 0.0,
            pkt_size_avg: 0.0,
            init_fwd_win_byts: 0,
            init_bwd_win_byts: 0,
            active_max: 0.0,
            active_min: 0.0,
            active_mean: 0.0,
            active_std: 0.0,
            idle_max: 0.0,
            idle_min: 0.0,
            idle_mean: 0.0,
            idle_std: 0.0,
            fwd_byts_b_avg: 0.0,
            fwd_pkts_b_avg: 0.0,
            bwd_byts_b_avg: 0.0,
            bwd_pkts_b_avg: 0.0,
            fwd_blk_rate_avg: 0.0,
            bwd_blk_rate_avg: 0.0,
            fwd_seg_size_avg: 0.0,
            bwd_seg_size_avg: 0.0,
            subflow_fwd_pkts: 0,
            subflow_bwd_pkts: 0,
            subflow_fwd_byts: 0,
            subflow_bwd_byts: 0,
            pqc_key_exchanges: Vec::new(),
            key_shares: Vec::new(),
            pqc_signatures: Vec::new(),
            last_activity_time: None,
            current_active_period: None,
            current_idle_period: None,
            active_periods: Vec::new(),
            idle_periods: Vec::new(),
        }
    }

    fn add_packet(&mut self, packet: PacketInfo, is_forward: bool, payload_size: usize) {
        if packet.timestamp == 0 {
            return;
        }

        if self.start_time.is_none() {
            self.start_time = Some(packet.timestamp);
            self.last_time = Some(packet.timestamp);
        }
        
        // Add debug logging for first 10 packets to understand the issue
        if self.tot_fwd_pkts + self.tot_bwd_pkts < 10 {
            println!("Packet debug: size={}, header_len={}, payload_size={}, direction={}", 
                    packet.size, packet.header_len, payload_size, 
                    if is_forward { "forward" } else { "backward" });
        }
        
        if is_forward {
            self.tot_fwd_pkts += 1;
            self.totlen_fwd_pkts += payload_size;
            self.fwd_packet_times.push(packet.timestamp);
            if payload_size > 0 {
                self.fwd_pkt_len_max = self.fwd_pkt_len_max.max(payload_size);
                if self.fwd_pkt_len_min == 0 || payload_size < self.fwd_pkt_len_min {
                    self.fwd_pkt_len_min = payload_size;
                }
                self.fwd_act_data_pkts += 1;
            }
            
            self.fwd_header_len += packet.header_len;
            
            if payload_size > 0 {
                if self.fwd_seg_size_min == 0 || payload_size < self.fwd_seg_size_min {
                    self.fwd_seg_size_min = payload_size;
                }
            }
            
            if self.fwd_packet_times.len() >= 2 {
                let prev_time = self.fwd_packet_times[self.fwd_packet_times.len() - 2];
                let curr_time = packet.timestamp;
                if curr_time >= prev_time {
                    let iat_seconds = (curr_time.saturating_sub(prev_time)) as f64 / 1_000_000.0;
                    self.fwd_iat_tot += iat_seconds;
                    
                    if self.fwd_iat_min == 0.0 || iat_seconds < self.fwd_iat_min {
                        self.fwd_iat_min = iat_seconds;
                    }
                    self.fwd_iat_max = self.fwd_iat_max.max(iat_seconds);
                    
                    let iat_count = (self.fwd_packet_times.len() - 1) as f64;
                    self.fwd_iat_mean = self.fwd_iat_tot / iat_count;
                }
            }
            
            if packet.flags.psh { self.fwd_psh_flags += 1; }
            if packet.flags.urg { self.fwd_urg_flags += 1; }
            
            self.fwd_packets.push(packet.clone());

            if self.init_fwd_win_byts == 0 {
                self.init_fwd_win_byts = packet.window_size;
            }
        } else {
            self.tot_bwd_pkts += 1;
            self.totlen_bwd_pkts += payload_size;
            self.bwd_packet_times.push(packet.timestamp);
            
            if payload_size > 0 {
                self.bwd_pkt_len_max = self.bwd_pkt_len_max.max(payload_size);
                if self.bwd_pkt_len_min == 0 || payload_size < self.bwd_pkt_len_min {
                    self.bwd_pkt_len_min = payload_size;
                }
            }
            
            self.bwd_header_len += packet.header_len;
            
            if self.bwd_packet_times.len() >= 2 {
                let prev_time = self.bwd_packet_times[self.bwd_packet_times.len() - 2];
                let curr_time = packet.timestamp;
                if curr_time >= prev_time {
                    let iat_seconds = (curr_time.saturating_sub(prev_time)) as f64 / 1_000_000.0;
                    self.bwd_iat_tot += iat_seconds;
                    
                    if self.bwd_iat_min == 0.0 || iat_seconds < self.bwd_iat_min {
                        self.bwd_iat_min = iat_seconds;
                    }
                    self.bwd_iat_max = self.bwd_iat_max.max(iat_seconds);
                    
                    let iat_count = (self.bwd_packet_times.len() - 1) as f64;
                    self.bwd_iat_mean = self.bwd_iat_tot / iat_count;
                }
            }
            
            if packet.flags.psh { self.bwd_psh_flags += 1; }
            if packet.flags.urg { self.bwd_urg_flags += 1; }
            
            self.bwd_packets.push(packet.clone());

            if self.init_bwd_win_byts == 0 {
                self.init_bwd_win_byts = packet.window_size;
            }
        }

        if packet.flags.fin { self.fin_flag_cnt += 1; }
        if packet.flags.syn { self.syn_flag_cnt += 1; }
        if packet.flags.rst { self.rst_flag_cnt += 1; }
        if packet.flags.psh { self.psh_flag_cnt += 1; }
        if packet.flags.ack { self.ack_flag_cnt += 1; }
        if packet.flags.urg { self.urg_flag_cnt += 1; }
        if packet.flags.ece { self.ece_flag_cnt += 1; }

        self.update_time(packet.timestamp);
        self.update_activity_tracking(packet.timestamp, payload_size > 0);
        self.calculate_flow_stats();
        self.calculate_burst_metrics();
    }

    fn update_from_client_hello(&mut self, ch: &tls_parser::ClientHello) {
        let mut is_tls13 = false;
        let mut found_pqc_features = false;
        let mut found_kyber = false;
        let mut found_ml_dsa = false;
        
        println!("Processing ClientHello with {} extensions", ch.extensions.len());
        
        // Set cipher suite from ClientHello (fallback if no ServerHello)
        if self.tls_cipher_suite.is_empty() && !ch.cipher_suites.is_empty() {
            // Use the first non-GREASE cipher suite
            for &cs in &ch.cipher_suites {
                if !is_grease_value(cs) {
                    self.tls_cipher_suite = classify_cipher_suite(cs);
                    println!("Set cipher suite from ClientHello: {}", self.tls_cipher_suite);
                    break;
                }
            }
        }
        
        // Filter out GREASE extensions for processing
        let non_grease_extensions: Vec<_> = ch.extensions.iter()
            .filter(|(ext_type, _)| !is_grease_extension(*ext_type))
            .collect();
        
        if non_grease_extensions.is_empty() {
            println!("Warning: No non-GREASE extensions in ClientHello");
        } else {
            println!("Found {} non-GREASE extensions", non_grease_extensions.len());
        }
        
        for (ext_type, ext_data) in &ch.extensions {
            if *ext_type == 0x002b {
                if ext_data.len() >= 1 {
                    let len = ext_data[0] as usize;
                    let mut i = 1;
                    while i + 1 < ext_data.len() && i <= len {
                        let version = ((ext_data[i] as u16) << 8) | ext_data[i + 1] as u16;
                        if version == 0x0304 {
                            is_tls13 = true;
                        }
                        i += 2;
                    }
                }
            }
        }

        for &cs in &ch.cipher_suites {
            if is_pqc_cipher_suite(cs) || is_classical_cipher_suite(cs) {
                if is_pqc_cipher_suite(cs) {
                    found_pqc_features = true;
                }
            }
        }

        for (ext_type, ext_data) in &ch.extensions {
            match *ext_type {
                0x000a => { // supported_groups - Check for Kyber only
                    if ext_data.len() >= 2 {
                        let groups_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                        let mut offset = 2;
                        while offset + 2 <= ext_data.len() && offset - 2 < groups_len {
                            let group = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                            
                            // Specifically check for Kyber algorithms in supported_groups
                            if is_kyber_key_exchange(group) {
                                found_kyber = true;
                                found_pqc_features = true;
                                let key_type = classify_key_exchange(group);
                                self.pqc_key_exchanges.push(key_type);
                                println!("Found Kyber in supported_groups: {}", classify_key_exchange(group));
                                
                                if is_hybrid_key_share(group) {
                                    self.is_hybrid = true;
                                }
                            } else if is_pqc_key_share(group) || is_hybrid_key_share(group) {
                                found_pqc_features = true;
                                let key_type = classify_key_exchange(group);
                                self.pqc_key_exchanges.push(key_type);
                                
                                if is_hybrid_key_share(group) {
                                    self.is_hybrid = true;
                                }
                            }
                            offset += 2;
                        }
                    }
                },
                0x0033 => { // key_share - Check for Kyber only
                    if ext_data.len() >= 2 {
                        let _shares_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                        let mut offset = 2;
                        while offset + 4 <= ext_data.len() {
                            let group = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                            let key_len = ((ext_data[offset + 2] as usize) << 8) | ext_data[offset + 3] as usize;
                            
                            // Specifically check for Kyber algorithms in key_share
                            if is_kyber_key_exchange(group) {
                                found_kyber = true;
                                found_pqc_features = true;
                                let key_type = classify_key_exchange(group);
                                self.key_shares.push(key_type);
                                println!("Found Kyber in key_share: {}", classify_key_exchange(group));
                                
                                if is_hybrid_key_share(group) {
                                    self.is_hybrid = true;
                                }
                            } else if is_pqc_key_share(group) || is_hybrid_key_share(group) {
                                found_pqc_features = true;
                                let key_type = classify_key_exchange(group);
                                self.key_shares.push(key_type);
                                
                                if is_hybrid_key_share(group) {
                                    self.is_hybrid = true;
                                }
                            }
                            offset += 4 + key_len;
                        }
                    }
                },
                0x000d => { // signature_algorithms - Check for ML-DSA only
                    if ext_data.len() >= 2 {
                        let sig_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                        let mut i = 2;
                        while i + 2 <= ext_data.len() && i - 2 < sig_len {
                            let sig_alg = ((ext_data[i] as u16) << 8) | ext_data[i + 1] as u16;
                            
                            // Specifically check for ML-DSA algorithms in signature_algorithms
                            if is_ml_dsa_signature_algorithm(sig_alg) {
                                found_ml_dsa = true;
                                found_pqc_features = true;
                                let sig_type = classify_signature_algorithm(sig_alg);
                                self.pqc_signatures.push(sig_type);
                                println!("Found ML-DSA in signature_algorithms: {}", classify_signature_algorithm(sig_alg));
                                
                                if is_hybrid_signature_algorithm(sig_alg) {
                                    self.is_hybrid = true;
                                }
                            } else if is_pqc_signature_algorithm(sig_alg) || is_hybrid_signature_algorithm(sig_alg) {
                                found_pqc_features = true;
                                let sig_type = classify_signature_algorithm(sig_alg);
                                self.pqc_signatures.push(sig_type);
                                
                                if is_hybrid_signature_algorithm(sig_alg) {
                                    self.is_hybrid = true;
                                }
                            }
                            i += 2;
                        }
                    }
                },
                _ => {}
            }
        }

        self.tls_extensions = format_extensions(&ch.extensions);

        // Perform detailed extension analysis
        let (critical_extensions, pqc_relevant, tls13_features, supports_0rtt, complexity) = 
            analyze_extensions(&ch.extensions);
        
        self.critical_tls_extensions = critical_extensions;
        self.pqc_relevant_extensions = pqc_relevant;
        self.tls13_features = tls13_features;
        self.supports_0rtt = supports_0rtt;
        self.extension_complexity = complexity;

        self.tls_version = if is_tls13 {
            "TLS 1.3".to_string()
        } else {
            format!("0x{:04x}", ch.client_version)
        };

        if found_pqc_features {
            self.has_pqc = true;
        }
        
        // Set specific algorithm detection flags
        self.has_kyber = found_kyber;
        self.has_ml_dsa = found_ml_dsa;
        
        // Log specific algorithm detections
        println!("Algorithm detection summary - Kyber: {}, ML-DSA: {}, General PQC: {}", 
                 found_kyber, found_ml_dsa, found_pqc_features);
    }

    fn update_from_certificate(&mut self, cert_data: &[u8]) {
        if let Some(sig_alg) = parse_certificate_signature_algorithm(cert_data) {
            self.cert_algorithm = sig_alg;
            
            if is_pqc_algorithm_name(&self.cert_algorithm) {
                self.has_pqc = true;
                if is_hybrid_algorithm_name(&self.cert_algorithm) {
                    self.is_hybrid = true;
                }
            }
        }
    }

    fn to_tsv_row(&self, key: &FlowKey) -> String {
        let timestamp = chrono::Local::now().naive_local().format("%Y-%m-%d %H:%M:%S").to_string();
        
        // Helper function to ensure numeric fields never return empty strings
        let safe_format = |val: f64| -> String {
            if val.is_finite() && val >= 0.0 {
                format!("{:.6}", val)
            } else {
                "0.000000".to_string()
            }
        };
        
        vec![
            key.to_flow_id(),
            ip_bytes_to_string(key.src_ip),
            ip_bytes_to_string(key.dst_ip),
            key.src_port.to_string(),
            key.dst_port.to_string(),
            key.protocol.to_string(),
            timestamp,
            safe_format(self.flow_duration()),
            safe_format(self.flow_byts_s),
            safe_format(self.flow_pkts_s),
            safe_format(if self.tot_fwd_pkts > 0 { self.tot_fwd_pkts as f64 / self.flow_duration() } else { 0.0 }),
            safe_format(if self.tot_bwd_pkts > 0 { self.tot_bwd_pkts as f64 / self.flow_duration() } else { 0.0 }),
            self.tot_fwd_pkts.to_string(),
            self.tot_bwd_pkts.to_string(),
            self.totlen_fwd_pkts.to_string(),
            self.totlen_bwd_pkts.to_string(),
            self.fwd_pkt_len_max.to_string(),
            self.fwd_pkt_len_min.to_string(),
            safe_format(self.fwd_pkt_len_mean),
            safe_format(self.fwd_pkt_len_std),
            self.bwd_pkt_len_max.to_string(),
            self.bwd_pkt_len_min.to_string(),
            safe_format(self.bwd_pkt_len_mean),
            safe_format(self.bwd_pkt_len_std),
            self.pkt_len_max.to_string(),
            self.pkt_len_min.to_string(),
            safe_format(self.pkt_len_mean),
            safe_format(self.pkt_len_std),
            safe_format(self.pkt_len_var),
            self.fwd_header_len.to_string(),
            self.bwd_header_len.to_string(),
            self.fwd_seg_size_min.to_string(),
            self.fwd_act_data_pkts.to_string(),
            safe_format(self.flow_iat_mean),
            safe_format(self.flow_iat_max),
            safe_format(self.flow_iat_min),
            safe_format(self.flow_iat_std),
            safe_format(self.fwd_iat_tot),
            safe_format(self.fwd_iat_max),
            safe_format(self.fwd_iat_min),
            safe_format(self.fwd_iat_mean),
            safe_format(self.fwd_iat_std),
            safe_format(self.bwd_iat_tot),
            safe_format(self.bwd_iat_max),
            safe_format(self.bwd_iat_min),
            safe_format(self.bwd_iat_mean),
            safe_format(self.bwd_iat_std),
            self.fwd_psh_flags.to_string(),
            self.bwd_psh_flags.to_string(),
            self.fwd_urg_flags.to_string(),
            self.bwd_urg_flags.to_string(),
            self.fin_flag_cnt.to_string(),
            self.syn_flag_cnt.to_string(),
            self.rst_flag_cnt.to_string(),
            self.psh_flag_cnt.to_string(),
            self.ack_flag_cnt.to_string(),
            self.urg_flag_cnt.to_string(),
            self.ece_flag_cnt.to_string(),
            safe_format(self.down_up_ratio),
            safe_format(self.pkt_size_avg),
            self.init_fwd_win_byts.to_string(),
            self.init_bwd_win_byts.to_string(),
            safe_format(self.active_max),
            safe_format(self.active_min),
            safe_format(self.active_mean),
            safe_format(self.active_std),
            safe_format(self.idle_max),
            safe_format(self.idle_min),
            safe_format(self.idle_mean),
            safe_format(self.idle_std),
            safe_format(self.fwd_byts_b_avg),
            safe_format(self.fwd_pkts_b_avg),
            safe_format(self.bwd_byts_b_avg),
            safe_format(self.bwd_pkts_b_avg),
            safe_format(self.fwd_blk_rate_avg),
            safe_format(self.bwd_blk_rate_avg),
            safe_format(self.fwd_seg_size_avg),
            safe_format(self.bwd_seg_size_avg),
            "0".to_string(), // cwr_flag_count
            self.subflow_fwd_pkts.to_string(),
            self.subflow_bwd_pkts.to_string(),
            self.subflow_fwd_byts.to_string(),
            self.subflow_bwd_byts.to_string(),
            if self.is_tls && self.has_pqc { "true" } else { "false" }.to_string(),
            if self.is_tls && self.has_kyber { "true" } else { "false" }.to_string(),
            if self.is_tls && self.has_ml_dsa { "true" } else { "false" }.to_string(),
            if self.is_tls && self.is_hybrid { "true" } else { "false" }.to_string(),
            if self.is_tls { self.cert_algorithm.clone() } else { String::new() },
            if self.is_tls { self.tls_cipher_suite.clone() } else { String::new() },
            if self.is_tls { self.tls_extensions.clone() } else { String::new() },
            if self.is_tls { self.critical_tls_extensions.clone() } else { String::new() },
            if self.is_tls { self.pqc_relevant_extensions.clone() } else { String::new() },
            if self.is_tls { self.tls13_features.clone() } else { String::new() },
            if self.is_tls { self.supports_0rtt.clone() } else { "false".to_string() },
            if self.is_tls { self.extension_complexity.clone() } else { "none".to_string() },
        ].join("\t")
    }

    // Additional helper methods needed for compilation
    fn update_time(&mut self, timestamp: u64) {
        if self.start_time.is_none() {
            self.start_time = Some(timestamp);
        }
        
        self.packet_times.push(timestamp);
        self.last_time = Some(timestamp);
        
        if self.packet_times.len() >= 2 {
            let prev = self.packet_times[self.packet_times.len() - 2];
            let curr = self.packet_times[self.packet_times.len() - 1];
            
            if curr >= prev {
                let iat = (curr.saturating_sub(prev)) as f64 / 1_000_000.0;
                
                if self.flow_iat_min == 0.0 || iat < self.flow_iat_min {
                    self.flow_iat_min = iat;
                }
                self.flow_iat_max = self.flow_iat_max.max(iat);
                
                let n = (self.packet_times.len() - 1) as f64;
                let old_mean = self.flow_iat_mean;
                self.flow_iat_mean = (old_mean * (n - 1.0) + iat) / n;
                
                if n > 1.0 {
                    let delta = iat - old_mean;
                    let delta2 = iat - self.flow_iat_mean;
                    self.flow_iat_std = ((self.flow_iat_std * self.flow_iat_std * (n - 1.0) + 
                                        delta * delta2) / n).sqrt();
                }
            }
        }
    }

    fn flow_duration(&self) -> f64 {
        match (self.start_time, self.last_time) {
            (Some(start), Some(end)) if start <= end => {
                let duration = end.saturating_sub(start);
                (duration.min(120_000_000) as f64) / 1_000_000.0
            },
            _ => 0.0
        }
    }

    fn update_activity_tracking(&mut self, timestamp: u64, has_data: bool) {
    const ACTIVITY_THRESHOLD_US: u64 = 1_000_000;
    if self.last_activity_time.is_none() {
        self.last_activity_time = Some(timestamp);
        if has_data {
            self.current_active_period = Some(timestamp);
        } else {
            self.current_idle_period = Some(timestamp);
        }
        return;
    }

    let last_time = self.last_activity_time.unwrap();
    let time_diff = timestamp.saturating_sub(last_time);

    if has_data {
        if let Some(idle_start) = self.current_idle_period {
            let idle_duration = (timestamp.saturating_sub(idle_start)) as f64 / 1_000_000.0;
            if idle_duration > 0.0 {
                self.idle_periods.push(idle_duration);
            }
            self.current_idle_period = None;
        }
        if self.current_active_period.is_none() {
            self.current_active_period = Some(last_time);
        }
    } else if time_diff > ACTIVITY_THRESHOLD_US {
        if let Some(active_start) = self.current_active_period {
            let active_duration = (last_time.saturating_sub(active_start)) as f64 / 1_000_000.0;
            if active_duration > 0.0 {
                self.active_periods.push(active_duration);
            }
            self.current_active_period = None;
        }
        if self.current_idle_period.is_none() {
            self.current_idle_period = Some(last_time);
        }
    }

    self.last_activity_time = Some(timestamp);
    self.calculate_active_idle_stats();
}

    fn calculate_flow_stats(&mut self) {
        let duration = self.flow_duration();
        if duration > 0.0 {
            // Calculate throughput in bytes per second (total packet sizes, not just payload)
            let total_bytes = (self.totlen_fwd_pkts + self.totlen_bwd_pkts) as f64;
            self.flow_byts_s = total_bytes / duration;
            self.flow_pkts_s = (self.tot_fwd_pkts + self.tot_bwd_pkts) as f64 / duration;
        }

        // Calculate packet length statistics for forward direction (payload only)
        if self.tot_fwd_pkts > 0 {
            // FIXED: fwd_pkt_len_mean should be payload only (without headers)
            self.fwd_pkt_len_mean = self.totlen_fwd_pkts as f64 / self.tot_fwd_pkts as f64;
            
            let variance = self.fwd_packets.iter()
                .filter(|p| p.size > p.header_len)
                .map(|p| {
                    let size = p.size.saturating_sub(p.header_len);
                    let diff = size as f64 - self.fwd_pkt_len_mean;
                    diff * diff
                })
                .sum::<f64>() / self.tot_fwd_pkts as f64;
            self.fwd_pkt_len_std = variance.sqrt();
        }

        // Calculate packet length statistics for backward direction (payload only)
        if self.tot_bwd_pkts > 0 {
            // FIXED: bwd_pkt_len_mean should be payload only (without headers)
            self.bwd_pkt_len_mean = self.totlen_bwd_pkts as f64 / self.tot_bwd_pkts as f64;
            
            let variance = self.bwd_packets.iter()
                .filter(|p| p.size > p.header_len)
                .map(|p| {
                    let size = p.size.saturating_sub(p.header_len);
                    let diff = size as f64 - self.bwd_pkt_len_mean;
                    diff * diff
                })
                .sum::<f64>() / self.tot_bwd_pkts as f64;
            self.bwd_pkt_len_std = variance.sqrt();
        }

        // Calculate overall packet length statistics
        if self.fwd_act_data_pkts > 0 || self.tot_bwd_pkts > 0 {
            self.pkt_len_max = self.fwd_pkt_len_max.max(self.bwd_pkt_len_max);
            self.pkt_len_min = if self.fwd_pkt_len_min == 0 {
                self.bwd_pkt_len_min
            } else if self.bwd_pkt_len_min == 0 {
                self.fwd_pkt_len_min
            } else {
                self.fwd_pkt_len_min.min(self.bwd_pkt_len_min)
            };
        }

        // Calculate pkt_size_avg and pkt_len_mean (both should be identical for CICFlowMeter compatibility)
        let total_packets = self.tot_fwd_pkts + self.tot_bwd_pkts;
        if total_packets > 0 {
            // FIXED: pkt_len_mean should be payload-based (like CICFlowMeter), pkt_size_avg includes headers
            // Calculate total packet sizes including headers for pkt_size_avg
            let total_packet_sizes: usize = self.fwd_packets.iter().map(|p| p.size).sum::<usize>() + 
                                           self.bwd_packets.iter().map(|p| p.size).sum::<usize>();
            self.pkt_size_avg = total_packet_sizes as f64 / total_packets as f64;
            
            // Calculate pkt_len_mean from payload only (like CICFlowMeter)
            let total_payload_bytes = self.totlen_fwd_pkts + self.totlen_bwd_pkts;
            self.pkt_len_mean = total_payload_bytes as f64 / total_packets as f64;
        } else {
            self.pkt_size_avg = 0.0;
            self.pkt_len_mean = 0.0;
        }
        
        // Calculate pkt_len_std based on payload sizes (consistent with pkt_len_mean)
        let total_packets = self.tot_fwd_pkts + self.tot_bwd_pkts;
        if total_packets > 0 {
            let variance = self.fwd_packets.iter()
                .chain(self.bwd_packets.iter())
                .map(|p| {
                    let payload_size = if p.size > p.header_len {
                        p.size - p.header_len
                    } else {
                        0
                    };
                    let diff = payload_size as f64 - self.pkt_len_mean;
                    diff * diff
                })
                .sum::<f64>() / total_packets as f64;
            self.pkt_len_std = variance.sqrt();
            self.pkt_len_var = variance;
        } else {
            self.pkt_len_std = 0.0;
            self.pkt_len_var = 0.0;
        }

        self.subflow_fwd_pkts = self.tot_fwd_pkts;
        self.subflow_bwd_pkts = self.tot_bwd_pkts;
        self.subflow_fwd_byts = self.totlen_fwd_pkts;
        self.subflow_bwd_byts = self.totlen_bwd_pkts;

        if self.totlen_fwd_pkts > 0 {
            self.down_up_ratio = self.totlen_bwd_pkts as f64 / self.totlen_fwd_pkts as f64;
        }

        if self.tot_fwd_pkts > 0 {
            self.fwd_seg_size_avg = (self.totlen_fwd_pkts) as f64 / self.tot_fwd_pkts as f64;
        }
        if self.tot_bwd_pkts > 0 {
            self.bwd_seg_size_avg = (self.totlen_bwd_pkts) as f64 / self.tot_bwd_pkts as f64;
        }
        
        self.calculate_active_idle_stats();
    }

    fn calculate_burst_metrics(&mut self) {
        const BURST_WINDOW_US: u64 = 100_000;
        
        if !self.fwd_packet_times.is_empty() {
            let mut bursts = Vec::new();
            let mut current_burst_bytes = 0;
            let mut current_burst_packets = 0;
            let mut burst_start_time = self.fwd_packet_times[0];
            
            for (i, &timestamp) in self.fwd_packet_times.iter().enumerate() {
                let time_since_burst_start = timestamp.saturating_sub(burst_start_time);
                
                if time_since_burst_start <= BURST_WINDOW_US {
                    current_burst_packets += 1;
                    if i < self.fwd_packets.len() {
                        let payload_size = self.fwd_packets[i].size.saturating_sub(self.fwd_packets[i].header_len);
                        current_burst_bytes += payload_size;
                    }
                } else {
                    if current_burst_packets > 0 {
                        bursts.push((current_burst_bytes, current_burst_packets));
                    }
                    current_burst_bytes = 0;
                    current_burst_packets = 1;
                    burst_start_time = timestamp;
                }
            }
            
            if current_burst_packets > 0 {
                bursts.push((current_burst_bytes, current_burst_packets));
            }
            
            if !bursts.is_empty() {
                let total_burst_bytes: usize = bursts.iter().map(|(bytes, _)| bytes).sum();
                let total_burst_packets: usize = bursts.iter().map(|(_, packets)| packets).sum();
                
                self.fwd_byts_b_avg = total_burst_bytes as f64 / bursts.len() as f64;
                self.fwd_pkts_b_avg = total_burst_packets as f64 / bursts.len() as f64;
                
                let burst_duration_total = bursts.len() as f64 * (BURST_WINDOW_US as f64 / 1_000_000.0);
                if burst_duration_total > 0.0 {
                    self.fwd_blk_rate_avg = total_burst_packets as f64 / burst_duration_total;
                }
            }
        }
        
        if !self.bwd_packet_times.is_empty() {
            let mut bursts = Vec::new();
            let mut current_burst_bytes = 0;
            let mut current_burst_packets = 0;
            let mut burst_start_time = self.bwd_packet_times[0];
            
            for (i, &timestamp) in self.bwd_packet_times.iter().enumerate() {
                let time_since_burst_start = timestamp.saturating_sub(burst_start_time);
                
                if time_since_burst_start <= BURST_WINDOW_US {
                    current_burst_packets += 1;
                    if i < self.bwd_packets.len() {
                        let payload_size = self.bwd_packets[i].size.saturating_sub(self.bwd_packets[i].header_len);
                        current_burst_bytes += payload_size;
                    }
                } else {
                    if current_burst_packets > 0 {
                        bursts.push((current_burst_bytes, current_burst_packets));
                    }
                    current_burst_bytes = 0;
                    current_burst_packets = 1;
                    burst_start_time = timestamp;
                }
            }
            
            if current_burst_packets > 0 {
                bursts.push((current_burst_bytes, current_burst_packets));
            }
            
            if !bursts.is_empty() {
                let total_burst_bytes: usize = bursts.iter().map(|(bytes, _)| bytes).sum();
                let total_burst_packets: usize = bursts.iter().map(|(_, packets)| packets).sum();
                
                self.bwd_byts_b_avg = total_burst_bytes as f64 / bursts.len() as f64;
                self.bwd_pkts_b_avg = total_burst_packets as f64 / bursts.len() as f64;
                
                let burst_duration_total = bursts.len() as f64 * (BURST_WINDOW_US as f64 / 1_000_000.0);
                if burst_duration_total > 0.0 {
                    self.bwd_blk_rate_avg = total_burst_packets as f64 / burst_duration_total;
                }
            }
        }
    }

    fn calculate_active_idle_stats(&mut self) {
        // Finalize any current active or idle period
        if let Some(last_time) = self.last_activity_time {
            if let Some(active_start) = self.current_active_period {
                let active_duration = (last_time.saturating_sub(active_start)) as f64 / 1_000_000.0;
                if active_duration > 0.0 {
                    self.active_periods.push(active_duration);
                }
                self.current_active_period = None;
            }
            
            if let Some(idle_start) = self.current_idle_period {
                let idle_duration = (last_time.saturating_sub(idle_start)) as f64 / 1_000_000.0;
                if idle_duration > 0.0 {
                    self.idle_periods.push(idle_duration);
                }
                self.current_idle_period = None;
            }
        }
        
        // Calculate statistics for active periods
        if !self.active_periods.is_empty() {
            self.active_max = self.active_periods.iter().fold(0.0f64, |a, &b| a.max(b));
            self.active_min = self.active_periods.iter().fold(f64::INFINITY, |a, &b| a.min(b));
            if self.active_min == f64::INFINITY {
                self.active_min = 0.0;
            }
            self.active_mean = self.active_periods.iter().sum::<f64>() / self.active_periods.len() as f64;
            
            let variance = self.active_periods.iter()
                .map(|&x| (x - self.active_mean).powi(2))
                .sum::<f64>() / self.active_periods.len() as f64;
            self.active_std = variance.sqrt();
        }
        
        // Calculate statistics for idle periods
        if !self.idle_periods.is_empty() {
            self.idle_max = self.idle_periods.iter().fold(0.0f64, |a, &b| a.max(b));
            self.idle_min = self.idle_periods.iter().fold(f64::INFINITY, |a, &b| a.min(b));
            if self.idle_min == f64::INFINITY {
                self.idle_min = 0.0;
            }
            self.idle_mean = self.idle_periods.iter().sum::<f64>() / self.idle_periods.len() as f64;
            
            let variance = self.idle_periods.iter()
                .map(|&x| (x - self.idle_mean).powi(2))
                .sum::<f64>() / self.idle_periods.len() as f64;
            self.idle_std = variance.sqrt();
        }
    }
}

fn main() {
    println!("Starting uranmehr application.");

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input.pcap> <output.tsv>", args[0]);
        process::exit(1);
    }
    let input_filename = &args[1];
    let output_filename = &args[2];

    println!("Reading PCAP file: {}", input_filename);
    let packets = match read_all_packets(input_filename) {
        Ok(pkts) => {
            println!("Successfully read {} packets from PCAP", pkts.len());
            pkts
        }
        Err(e) => {
            eprintln!("Error reading pcap file: {}", e);
            process::exit(1);
        }
    };

    let mut flows: HashMap<FlowKey, FlowStats> = HashMap::new();
    let mut tls_buffers: HashMap<FlowKey, TlsBuffer> = HashMap::new();
    let mut total_flows = 0;
    let mut tls_flows = 0;
    let bot_flows = 0;
    let mut pqc_flows = 0;
    let mut flow_timeouts = 0;
    let duplicate_flows = 0;
    let mut ip_stats: HashMap<String, usize> = HashMap::new();
    let mut bidirectional_flows = 0;
    let mut unidirectional_flows = 0;

    // Process each packet
    for (packet_index, packet) in packets.iter().enumerate() {
        if packet_index % 50000 == 0 {
            println!("Processing packet {}/{}", packet_index, packets.len());
        }

        // Extract IP addresses and validate packet
        let (src_ip, dst_ip) = match extract_ip_addresses(&packet.data) {
            Some((src_bytes, dst_bytes)) => {
                let src_ip = ip_bytes_to_string(src_bytes);
                let dst_ip = ip_bytes_to_string(dst_bytes);
                (src_ip, dst_ip)
            },
            None => {
                continue;
            }
        };

        // Extract TCP ports
        let (src_port, dst_port) = match extract_tcp_ports(&packet.data) {
            Some(ports) => ports,
            None => {
                continue;
            }
        };

        // Create flow key with normalization for bidirectional flows (like Wireshark)
        let flow_key = FlowKey::new(src_ip.clone(), dst_ip.clone(), src_port, dst_port, 6);

        // Check for flow timeout (120 seconds for proper flow aggregation)
        if let Some(stats) = flows.get(&flow_key) {
            if let Some(start_time) = stats.start_time {
                if packet.timestamp.saturating_sub(start_time) > 120_000_000 {
                    flow_timeouts += 1;
                    flows.remove(&flow_key);
                }
            }
        }

        // Get or create flow stats
        let flow_stats = flows.entry(flow_key.clone()).or_insert_with(|| {
            total_flows += 1;
            if total_flows <= 10 {
                println!("Created flow #{}: {}", total_flows, flow_key.to_flow_id());
            }
            FlowStats::new()
        });

        // Initialize start time if not set
        if flow_stats.start_time.is_none() {
            flow_stats.start_time = Some(packet.timestamp);
        }

        // Determine packet direction based on original packet IPs vs normalized flow key
        let orig_src_ip = ip_string_to_bytes(&src_ip);
        let orig_dst_ip = ip_string_to_bytes(&dst_ip);
        let is_forward = flow_key.get_original_direction(&orig_src_ip, &orig_dst_ip, src_port, dst_port);
        
        // Debug logging for first few flows to verify normalization
        if total_flows <= 10 {
            let normalized_src = ip_bytes_to_string(flow_key.src_ip);
            let normalized_dst = ip_bytes_to_string(flow_key.dst_ip);
            println!("Flow normalization: {}:{} -> {}:{} -> normalized: {}:{} -> {}:{} (direction: {})", 
                    src_ip, src_port, dst_ip, dst_port,
                    normalized_src, flow_key.src_port, normalized_dst, flow_key.dst_port,
                    if is_forward { "forward" } else { "backward" });
        }
        
        if total_flows <= 10 {
            println!("Packet direction for flow {}: {} (orig: {}:{} -> {}:{})", 
                    flow_key.to_flow_id(), 
                    if is_forward { "forward" } else { "backward" },
                    src_ip, src_port, dst_ip, dst_port);
        }

        // Extract TCP flags and window size
        if let Some(tcp_flags) = extract_tcp_flags(&packet.data) {
            if let Some(window_size) = extract_window_size(&packet.data) {
                // Create packet info
                let header_len = get_total_header_len(&packet.data).unwrap_or(54);
                
                // Use a more conservative approach for payload size calculation
                let payload_size = if packet.data.len() > header_len {
                    let calculated_payload = packet.data.len() - header_len;
                    // Cap payload size at 1500 bytes (standard MTU)
                    calculated_payload.min(1500)
                } else {
                    0
                };
                
                let packet_info = PacketInfo {
                    timestamp: packet.timestamp,
                    size: packet.data.len(),
                    header_len: header_len,
                    flags: tcp_flags,
                    window_size,
                };

                // Update flow statistics
                flow_stats.add_packet(packet_info, is_forward, payload_size);
            }
        }

        // Process TLS if present
        if let Some(tls_payload) = extract_tls_payload(&packet.data) {
            // Get or create TLS buffer for this flow
            let tls_buffer = tls_buffers.entry(flow_key.clone()).or_insert_with(TlsBuffer::new);
            
            // Add data to buffer
            if tls_buffer.add_data(&tls_payload) {
                // Process complete TLS records
                while let Some(record_data) = tls_buffer.get_record() {
                    if let Some(tls_record) = parse_tls_record(&record_data) {
                        if !flow_stats.is_tls {
                            // Only mark as TLS if we successfully process a handshake message
                            // TLS flag will be set when we process Client Hello
                        }
                        flow_stats.tls_version = format!("0x{:04x}", tls_record.version);

                        if let Some(ref hs) = tls_record.handshake {
                            match hs {
                                HandshakeMessage::ClientHello(ch) => {
                                    println!("Processing ClientHello for flow {}", flow_key.to_flow_id());
                                    
                                    // Mark that this flow has a Client Hello and count TLS flows
                                    if !flow_stats.is_tls {
                                        tls_flows += 1;
                                        flow_stats.is_tls = true;
                                    }
                                    
                                    flow_stats.update_from_client_hello(ch);
                                    
                                    // FIXED: Only count PQC flows with specific Kyber or ML-DSA algorithms
                                    if flow_stats.is_tls && (flow_stats.has_kyber || flow_stats.has_ml_dsa) && !flow_stats.pqc_counted {
                                        pqc_flows += 1;
                                        flow_stats.pqc_counted = true;
                                        println!("✓ Counted PQC flow: {} (Kyber: {}, ML-DSA: {})", 
                                                flow_key.to_flow_id(), flow_stats.has_kyber, flow_stats.has_ml_dsa);
                                    }
                                },
                                HandshakeMessage::ServerHello(sh) => {
                                    println!("Processing ServerHello for flow {} with {} extensions", 
                                            flow_key.to_flow_id(), sh.extensions.len());
                                    
                                    flow_stats.tls_cipher_suite = classify_cipher_suite(sh.cipher_suite);
                                    
                                    // NOTE: In TLS 1.3, cipher suites are typically classical (like TLS_AES_256_GCM_SHA384)
                                    // even when PQC algorithms are used. PQC is implemented via extensions.
                                    // Only set PQC flag for explicitly PQC cipher suites, not classical ones.
                                    if is_pqc_cipher_suite(sh.cipher_suite) && !flow_stats.pqc_counted {
                                        flow_stats.has_pqc = true;
                                        // FIXED: Only count if we detect specific Kyber or ML-DSA in cipher suite
                                        if (sh.cipher_suite == 0x023A || sh.cipher_suite == 0x023C || sh.cipher_suite == 0x023D) { // Kyber
                                            flow_stats.has_kyber = true;
                                        }
                                        if (sh.cipher_suite == 0xFEA0 || sh.cipher_suite == 0xFEA3 || sh.cipher_suite == 0xFEA5) { // ML-DSA
                                            flow_stats.has_ml_dsa = true;
                                        }
                                        if flow_stats.has_kyber || flow_stats.has_ml_dsa {
                                            pqc_flows += 1;
                                            flow_stats.pqc_counted = true;
                                        }
                                    }
                                    
                                    // ALWAYS process ServerHello extensions - even if empty
                                    let server_extensions = format_extensions(&sh.extensions);
                                    if !server_extensions.is_empty() {
                                        if flow_stats.tls_extensions.is_empty() {
                                            flow_stats.tls_extensions = server_extensions.clone();
                                        } else {
                                            flow_stats.tls_extensions = format!("{},{}", flow_stats.tls_extensions, server_extensions);
                                        }
                                        
                                        println!("ServerHello extensions added: {}", server_extensions);
                                    } else {
                                        println!("ServerHello has no extensions to format");
                                    }
                                    
                                    // Process extensions for PQC analysis
                                    if !sh.extensions.is_empty() {
                                        // Analyze ServerHello extensions for PQC features
                                        let (server_critical, server_pqc_relevant, server_tls13_features, server_supports_0rtt, server_complexity) = 
                                            analyze_extensions(&sh.extensions);
                                        
                                        println!("ServerHello analysis - PQC relevant: '{}', 0-RTT: '{}'", 
                                                server_pqc_relevant, server_supports_0rtt);
                                        
                                        // Update critical extensions
                                        if !server_critical.is_empty() {
                                            if flow_stats.critical_tls_extensions.is_empty() {
                                                flow_stats.critical_tls_extensions = server_critical;
                                            } else {
                                                flow_stats.critical_tls_extensions = format!("{},{}", flow_stats.critical_tls_extensions, server_critical);
                                            }
                                        }
                                        
                                        // Update PQC relevant extensions and set PQC flag if server has PQC extensions
                                        if !server_pqc_relevant.is_empty() {
                                            if flow_stats.pqc_relevant_extensions.is_empty() {
                                                flow_stats.pqc_relevant_extensions = server_pqc_relevant.clone();
                                            } else {
                                                flow_stats.pqc_relevant_extensions = format!("{},{}", flow_stats.pqc_relevant_extensions, server_pqc_relevant);
                                            }
                                            
                                            // Set PQC flag if server has PQC algorithms in extensions
                                            flow_stats.has_pqc = true;
                                            if !flow_stats.pqc_counted {
                                                pqc_flows += 1;
                                                flow_stats.pqc_counted = true;
                                            }
                                        }
                                        
                                        // Update TLS 1.3 features
                                        if !server_tls13_features.is_empty() {
                                            if flow_stats.tls13_features.is_empty() {
                                                flow_stats.tls13_features = server_tls13_features.clone();
                                            } else {
                                                flow_stats.tls13_features = format!("{},{}", flow_stats.tls13_features, server_tls13_features);
                                            }
                                        }
                                        
                                        // Fix 0-RTT detection - check for early_data or psk_key_exchange_modes
                                        if server_supports_0rtt == "true" || 
                                           server_tls13_features.contains("ED") ||
                                           flow_stats.tls_extensions.contains("early_data") ||
                                           flow_stats.tls_extensions.contains("psk_key_exchange_modes") {
                                            flow_stats.supports_0rtt = "true".to_string();
                                            println!("0-RTT support detected for flow {}", flow_key.to_flow_id());
                                        }
                                        
                                        // Update extension complexity (use highest complexity)
                                        if server_complexity == "high" {
                                            flow_stats.extension_complexity = "high".to_string();
                                        } else if server_complexity == "medium" && flow_stats.extension_complexity == "low" {
                                            flow_stats.extension_complexity = "medium".to_string();
                                        }
                                    }
                                },
                                HandshakeMessage::Certificate(cert_list) => {
                                    println!("Processing Certificate message for flow {} with {} certificates", 
                                            flow_key.to_flow_id(), cert_list.len());
                                    
                                    // Add debug info about certificate data
                                    for (i, cert_data) in cert_list.iter().enumerate() {
                                        println!("Certificate {} raw data: {} bytes, first 16 bytes: {:02x?}", 
                                                i, cert_data.len(), 
                                                &cert_data[..cert_data.len().min(16)]);
                                    }
                                    
                                    // Process each certificate in the chain
                                    for (i, cert_data) in cert_list.iter().enumerate() {
                                        println!("Processing certificate {} of {} certificates (size: {} bytes)", 
                                                i, cert_list.len(), cert_data.len());
                                        
                                        if let Some(sig_alg) = parse_certificate_signature_algorithm(cert_data) {
                                            flow_stats.cert_algorithm = sig_alg.clone();
                                            
                                            if is_pqc_algorithm_name(&sig_alg) {
                                                flow_stats.has_pqc = true;
                                                
                                                // FIXED: Set specific algorithm flags
                                                if sig_alg.contains("ML-DSA") || sig_alg.contains("Dilithium") {
                                                    flow_stats.has_ml_dsa = true;
                                                }
                                                if sig_alg.contains("Kyber") {
                                                    flow_stats.has_kyber = true;
                                                }
                                                
                                                if is_hybrid_algorithm_name(&sig_alg) {
                                                    flow_stats.is_hybrid = true;
                                                }
                                                
                                                if (flow_stats.has_kyber || flow_stats.has_ml_dsa) && !flow_stats.pqc_counted {
                                                    pqc_flows += 1;
                                                    flow_stats.pqc_counted = true;
                                                }
                                            }
                                            
                                            println!("Certificate {} algorithm detected: {} for flow {}", 
                                                    i, sig_alg, flow_key.to_flow_id());
                                            break; // Use the first successfully parsed certificate
                                        } else {
                                            println!("Failed to parse certificate {} signature algorithm", i);
                                        }
                                    }
                                    
                                    // ENHANCED FALLBACK: If no certificate was successfully parsed, use better fallbacks
                                    if flow_stats.cert_algorithm == "Unknown" {
                                        println!("Certificate parsing failed, attempting fallback for flow {}", flow_key.to_flow_id());
                                        
                                        // Try fallback based on PQC extensions detected
                                        if flow_stats.has_pqc {
                                            // Use signature algorithms from extensions as fallback
                                            if !flow_stats.pqc_signatures.is_empty() {
                                                flow_stats.cert_algorithm = flow_stats.pqc_signatures[0].clone();
                                                println!("Using signature algorithm fallback: {}", flow_stats.cert_algorithm);
                                            } else if flow_stats.pqc_relevant_extensions.contains("ML-DSA-44") {
                                                flow_stats.cert_algorithm = "ML-DSA-44".to_string();
                                                println!("Using ML-DSA-44 fallback from extensions");
                                            } else if flow_stats.pqc_relevant_extensions.contains("ML-DSA-65") {
                                                flow_stats.cert_algorithm = "ML-DSA-65".to_string();
                                                println!("Using ML-DSA-65 fallback from extensions");
                                            } else if flow_stats.pqc_relevant_extensions.contains("ML-DSA-87") {
                                                flow_stats.cert_algorithm = "ML-DSA-87".to_string();
                                                println!("Using ML-DSA-87 fallback from extensions");
                                            } else if flow_stats.pqc_relevant_extensions.contains("Dilithium") {
                                                flow_stats.cert_algorithm = "Dilithium".to_string();
                                                println!("Using Dilithium fallback from extensions");
                                            } else if flow_stats.is_hybrid {
                                                flow_stats.cert_algorithm = "Hybrid-PQC".to_string();
                                                println!("Using Hybrid-PQC fallback");
                                            } else {
                                                flow_stats.cert_algorithm = "PQC-Unknown".to_string();
                                                println!("Using PQC-Unknown fallback");
                                            }
                                        } else {
                                            // For non-PQC flows, try to detect classical algorithms
                                            if flow_stats.tls_extensions.contains("ECDSA") {
                                                flow_stats.cert_algorithm = "ECDSA".to_string();
                                                println!("Using ECDSA fallback");
                                            } else if flow_stats.tls_extensions.contains("RSA") {
                                                flow_stats.cert_algorithm = "RSA".to_string();
                                                println!("Using RSA fallback");
                                            } else if flow_stats.tls_extensions.contains("Ed25519") {
                                                flow_stats.cert_algorithm = "Ed25519".to_string();
                                                println!("Using Ed25519 fallback");
                                            } else {
                                                flow_stats.cert_algorithm = "Classical-Unknown".to_string();
                                                println!("Using Classical-Unknown fallback");
                                            }
                                        }
                                    }
                                },
                            }
                        }
                    }
                }
            }
        } else {
            // Always check if this is likely a TLS flow based on port numbers
            let src_port = flow_key.src_port;
            let dst_port = flow_key.dst_port;
            // Only mark as TLS if we have actual TLS handshake data or strong evidence
            // Don't use port-based fallback as it creates inconsistent flows
            // Note: TLS flows are already counted when ClientHello is processed
            // No need to count again here
        }

        // Update IP statistics
        *ip_stats.entry(src_ip.clone()).or_insert(0) += 1;
        *ip_stats.entry(dst_ip.clone()).or_insert(0) += 1;
    }

    println!("\nProcessing summary:");
    println!("Total packets processed: {}", packets.len());
    println!("Total flows found: {}", total_flows);
    println!("Flow timeouts: {}", flow_timeouts);
    println!("Duplicate flows: {}", duplicate_flows);
    println!("TLS flows: {}", tls_flows);
    println!("Bot flows: {}", bot_flows);
    println!("PQC flows: {}", pqc_flows);

    // Log bidirectional packet statistics
    let mut fwd_packets_total = 0;
    let mut bwd_packets_total = 0;
    for stats in flows.values() {
        fwd_packets_total += stats.tot_fwd_pkts;
        bwd_packets_total += stats.tot_bwd_pkts;
        if stats.tot_fwd_pkts > 0 && stats.tot_bwd_pkts > 0 {
            bidirectional_flows += 1;
        } else {
            unidirectional_flows += 1;
        }
    }
    println!("Forward packets total: {}", fwd_packets_total);
    println!("Backward packets total: {}", bwd_packets_total);
    println!("Bidirectional flows: {} ({:.2}%)", bidirectional_flows, 
             if total_flows > 0 { (bidirectional_flows as f64 / total_flows as f64) * 100.0 } else { 0.0 });
    println!("Unidirectional flows: {} ({:.2}%)", unidirectional_flows,
             if total_flows > 0 { (unidirectional_flows as f64 / total_flows as f64) * 100.0 } else { 0.0 });

    println!("\nIP address statistics:");
    let mut ip_stats_vec: Vec<_> = ip_stats.iter().collect();
    ip_stats_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (ip, count) in ip_stats_vec.iter().take(20) {
        println!("{}: {} packets", ip, count);
    }

    // Write TSV output
    let mut output_file = match File::create(output_filename) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error creating output file: {}", e);
            process::exit(1);
        }
    };

    // Write TSV header with all CICFlowMeter fields - FIXED to remove duplicates
    let header = "flow_id\tsrc_ip\tdst_ip\tsrc_port\tdst_port\tprotocol\ttimestamp\tflow_duration\tflow_byts_s\tflow_pkts_s\tfwd_pkts_s\tbwd_pkts_s\ttot_fwd_pkts\ttot_bwd_pkts\ttotlen_fwd_pkts\ttotlen_bwd_pkts\tfwd_pkt_len_max\tfwd_pkt_len_min\tfwd_pkt_len_mean\tfwd_pkt_len_std\tbwd_pkt_len_max\tbwd_pkt_len_min\tbwd_pkt_len_mean\tbwd_pkt_len_std\tpkt_len_max\tpkt_len_min\tpkt_len_mean\tpkt_len_std\tpkt_len_var\tfwd_header_len\tbwd_header_len\tfwd_seg_size_min\tfwd_act_data_pkts\tflow_iat_mean\tflow_iat_max\tflow_iat_min\tflow_iat_std\tfwd_iat_tot\tfwd_iat_max\tfwd_iat_min\tfwd_iat_mean\tfwd_iat_std\tbwd_iat_tot\tbwd_iat_max\tbwd_iat_min\tbwd_iat_mean\tbwd_iat_std\tfwd_psh_flags\tbwd_psh_flags\tfwd_urg_flags\tbwd_urg_flags\tfin_flag_cnt\tsyn_flag_cnt\trst_flag_cnt\tpsh_flag_cnt\tack_flag_cnt\turg_flag_cnt\tece_flag_cnt\tdown_up_ratio\tpkt_size_avg\tinit_fwd_win_byts\tinit_bwd_win_byts\tactive_max\tactive_min\tactive_mean\tactive_std\tidle_max\tidle_min\tidle_mean\tidle_std\tfwd_byts_b_avg\tfwd_pkts_b_avg\tbwd_byts_b_avg\tbwd_pkts_b_avg\tfwd_blk_rate_avg\tbwd_blk_rate_avg\tfwd_seg_size_avg\tbwd_seg_size_avg\tcwr_flag_count\tsubflow_fwd_pkts\tsubflow_bwd_pkts\tsubflow_fwd_byts\tsubflow_bwd_byts\thas_pqc\thas_kyber\thas_ml_dsa\tis_hybrid\tcert_algorithm\ttls_cipher_suite\ttls_extensions\tcritical_tls_extensions\tpqc_relevant_extensions\ttls13_features\tsupports_0rtt\textension_complexity\n";
    
    if let Err(e) = output_file.write_all(header.as_bytes()) {
        eprintln!("Error writing TSV header: {}", e);
        process::exit(1);
    }

    // Write flow records
    for (key, stats) in flows.iter_mut() {
        // Finalize flow statistics before output
        stats.calculate_active_idle_stats();
        
        // FINAL CONSISTENCY CHECK: Ensure PQC flags are consistent with extensions
        let has_pqc_extensions = stats.pqc_relevant_extensions.contains("Kyber") ||
                                stats.pqc_relevant_extensions.contains("ML-DSA") ||
                                stats.pqc_relevant_extensions.contains("Dilithium") ||
                                stats.tls_extensions.contains("Kyber") ||
                                stats.tls_extensions.contains("ML-DSA") ||
                                stats.tls_extensions.contains("Dilithium");
        
        // Ensure TLS features are only present for flows that actually processed Client Hello
        if !stats.is_tls && (!stats.tls_extensions.is_empty() || 
                            !stats.pqc_relevant_extensions.is_empty() ||
                            stats.has_pqc) {
            println!("Warning: Flow {} has TLS features but no Client Hello processed - clearing TLS data", 
                     key.to_flow_id());
            stats.tls_extensions = String::new();
            stats.pqc_relevant_extensions = String::new();
            stats.critical_tls_extensions = String::new();
            stats.tls13_features = String::new();
            stats.supports_0rtt = "false".to_string();
            stats.has_pqc = false;
            stats.is_hybrid = false;
            stats.cert_algorithm = String::new();
            stats.tls_cipher_suite = String::new();
        }
        
        // Fix PQC flag consistency
        if has_pqc_extensions && !stats.has_pqc {
            stats.has_pqc = true;
            println!("Fixed has_pqc flag for flow {} based on extensions", key.to_flow_id());
        } else if !has_pqc_extensions && stats.has_pqc && stats.cert_algorithm.starts_with("Classical") {
            stats.has_pqc = false;
            println!("Cleared has_pqc flag for flow {} - no PQC extensions found", key.to_flow_id());
        }
        
        // Fix 0-RTT detection based on final extension state
        if (stats.tls_extensions.contains("early_data") || 
            stats.tls_extensions.contains("psk_key_exchange_modes")) && 
            stats.supports_0rtt == "false" {
            stats.supports_0rtt = "true".to_string();
            println!("Fixed 0-RTT support for flow {} based on extensions", key.to_flow_id());
        }
        
        // Only set TLS fields for flows that are actually TLS
        if !stats.is_tls {
            // Clear all TLS-related fields for non-TLS flows
            stats.tls_cipher_suite = String::new();
            stats.tls_version = String::new();
            stats.cert_algorithm = String::new();
            stats.tls_extensions = String::new();
            stats.critical_tls_extensions = String::new();
            stats.pqc_relevant_extensions = String::new();
            stats.tls13_features = String::new();
            stats.supports_0rtt = String::new();
            stats.extension_complexity = String::new();
        }
        
        let row = stats.to_tsv_row(key);
        if let Err(e) = output_file.write_all(format!("{}\n", row).as_bytes()) {
            eprintln!("Error writing flow record: {}", e);
            process::exit(1);
        }
    }

    println!("Successfully wrote {} flow records to {}", flows.len(), output_filename);
    println!("Fields per record: {}", header.split('\t').count());
}

// Helper functions
pub fn is_grease_value(value: u16) -> bool {
    (value & 0x0F0F) == 0x0A0A
}

// Enhanced format_extensions function - now extracts actual extension values
fn format_extensions(extensions: &[(u16, &[u8])]) -> String {
    let mut formatted = Vec::new();
    
    for &(ext_type, ext_data) in extensions {
        // Skip GREASE values
        if is_grease_extension(ext_type) {
            continue;
        }
        
        let ext_name = extension_id_to_name(ext_type);
        
        // Extract specific values for important extensions
        match ext_type {
            0x000a => { // supported_groups
                if ext_data.len() >= 2 {
                    let groups_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                    let mut offset = 2;
                    let mut groups = Vec::new();
                    while offset + 2 <= ext_data.len() && offset - 2 < groups_len {
                        let group = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                        if !is_grease_value(group) {
                            groups.push(classify_key_exchange(group));
                        }
                        offset += 2;
                    }
                    if !groups.is_empty() {
                        formatted.push(format!("{}({})", ext_name, groups.join("|")));
                    } else {
                        formatted.push(ext_name);
                    }
                } else {
                    formatted.push(ext_name);
                }
            },
            0x000d => { // signature_algorithms
                if ext_data.len() >= 2 {
                    let sig_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                    let mut i = 2;
                    let mut algorithms = Vec::new();
                    while i + 2 <= ext_data.len() && i - 2 < sig_len {
                        let sig_alg = ((ext_data[i] as u16) << 8) | ext_data[i + 1] as u16;
                        algorithms.push(classify_signature_algorithm(sig_alg));
                        i += 2;
                    }
                    if !algorithms.is_empty() {
                        // Limit to first 5 algorithms to avoid very long strings
                        let display_algs: Vec<String> = algorithms.into_iter().take(5).collect();
                        formatted.push(format!("{}({})", ext_name, display_algs.join("|")));
                    } else {
                        formatted.push(ext_name);
                    }
                } else {
                    formatted.push(ext_name);
                }
            },
            0x0033 => { // key_share
                if ext_data.len() >= 2 {
                    let _shares_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                    let mut offset = 2;
                    let mut key_shares = Vec::new();
                    while offset + 4 <= ext_data.len() {
                        let group = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                        let key_len = ((ext_data[offset + 2] as usize) << 8) | ext_data[offset + 3] as usize;
                        
                        if !is_grease_value(group) {
                            key_shares.push(classify_key_exchange(group));
                        }
                        offset += 4 + key_len;
                    }
                    if !key_shares.is_empty() {
                        formatted.push(format!("{}({})", ext_name, key_shares.join("|")));
                    } else {
                        formatted.push(ext_name);
                    }
                } else {
                    formatted.push(ext_name);
                }
            },
            0x0010 => { // ALPN
                if ext_data.len() >= 2 {
                    let protocols_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                    let mut offset = 2;
                    let mut protocols = Vec::new();
                    while offset < ext_data.len() && offset - 2 < protocols_len {
                        if offset < ext_data.len() {
                            let proto_len = ext_data[offset] as usize;
                            offset += 1;
                            if offset + proto_len <= ext_data.len() {
                                let protocol = String::from_utf8_lossy(&ext_data[offset..offset + proto_len]);
                                protocols.push(protocol.to_string());
                                offset += proto_len;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    if !protocols.is_empty() {
                        formatted.push(format!("{}({})", ext_name, protocols.join("|")));
                    } else {
                        formatted.push(ext_name);
                    }
                } else {
                    formatted.push(ext_name);
                }
            },
            0x002b => { // supported_versions
                if ext_data.len() >= 1 {
                    let versions_len = ext_data[0] as usize;
                    let mut offset = 1;
                    let mut versions = Vec::new();
                    while offset + 2 <= ext_data.len() && offset - 1 < versions_len {
                        let version = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                        match version {
                            0x0304 => versions.push("TLS1.3".to_string()),
                            0x0303 => versions.push("TLS1.2".to_string()),
                            0x0302 => versions.push("TLS1.1".to_string()),
                            0x0301 => versions.push("TLS1.0".to_string()),
                            _ => {
                                if !is_grease_value(version) {
                                    versions.push(format!("0x{:04x}", version));
                                }
                            },
                        }
                        offset += 2;
                    }
                    if !versions.is_empty() {
                        formatted.push(format!("{}({})", ext_name, versions.join("|")));
                    } else {
                        formatted.push(ext_name);
                    }
                } else {
                    formatted.push(ext_name);
                }
            },
            _ => {
                // For other extensions, just show the name
                formatted.push(ext_name);
            }
        }
    }
    
    formatted.join(",")
}

// Extract detailed extension information with actual values
fn analyze_extensions(extensions: &[(u16, &[u8])]) -> (String, String, String, String, String) {
    let non_grease_extensions: Vec<_> = extensions.iter().filter(|(id, _)| !is_grease_extension(*id)).collect();
    let mut has_supported_groups = false;
    let mut has_key_share = false;
    let mut has_signature_algorithms = false;
    let mut has_early_data = false;
    let mut has_session_ticket = false;
    let mut has_supported_versions = false;
    let mut has_psk_key_exchange_modes = false;
    let mut critical_extensions = Vec::new();
    let mut pqc_extensions = Vec::new();
    let mut pqc_algorithms_found = Vec::new();
    
    // FIXED: Check if this is actually TLS 1.3 first
    let mut is_tls13_flow = false;
    for &(ext_type, ext_data) in &non_grease_extensions {
        if *ext_type == 0x002b { // supported_versions extension
            if ext_data.len() >= 1 {
                let versions_len = ext_data[0] as usize;
                let mut offset = 1;
                while offset + 1 < ext_data.len() && offset - 1 < versions_len {
                    let version = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                    if version == 0x0304 { // TLS 1.3
                        is_tls13_flow = true;
                        break;
                    }
                    offset += 2;
                }
            }
            break;
        }
    }
    
    println!("Analyzing {} extensions - TLS 1.3: {}", non_grease_extensions.len(), is_tls13_flow);
    
    for &(ext_type, ext_data) in &non_grease_extensions {
        let ext_name = extension_id_to_name(*ext_type);
        
        match *ext_type {
            0x000a => { // supported_groups
                has_supported_groups = true;
                critical_extensions.push("supported_groups".to_string());
                
                // Extract and analyze groups for PQC
                if ext_data.len() >= 2 {
                    let groups_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                    let mut offset = 2;
                    while offset + 2 <= ext_data.len() && offset - 2 < groups_len {
                        let group = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                        if is_pqc_key_share(group) || is_hybrid_key_share(group) {
                            let key_type = classify_key_exchange(group);
                            pqc_algorithms_found.push(key_type);
                            println!("Found PQC key exchange: {}", classify_key_exchange(group));
                        }
                        offset += 2;
                    }
                }
            },
            0x000d => { // signature_algorithms
                has_signature_algorithms = true;
                critical_extensions.push("signature_algorithms".to_string());
                
                // Extract and analyze signature algorithms for PQC
                if ext_data.len() >= 2 {
                    let sig_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                    let mut i = 2;
                    while i + 2 <= ext_data.len() && i - 2 < sig_len {
                        let sig_alg = ((ext_data[i] as u16) << 8) | ext_data[i + 1] as u16;
                        if is_pqc_signature_algorithm(sig_alg) || is_hybrid_signature_algorithm(sig_alg) {
                            let sig_type = classify_signature_algorithm(sig_alg);
                            pqc_algorithms_found.push(sig_type);
                            println!("Found PQC signature: {}", classify_signature_algorithm(sig_alg));
                        }
                        i += 2;
                    }
                }
            },
            0x0033 => { // key_share
                has_key_share = true;
                critical_extensions.push("key_share".to_string());
                
                // Extract and analyze key shares for PQC
                if ext_data.len() >= 2 {
                    let _shares_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                    let mut offset = 2;
                    while offset + 4 <= ext_data.len() {
                        let group = ((ext_data[offset] as u16) << 8) | ext_data[offset + 1] as u16;
                        let key_len = ((ext_data[offset + 2] as usize) << 8) | ext_data[offset + 3] as usize;
                        
                        if is_pqc_key_share(group) || is_hybrid_key_share(group) {
                            let key_type = classify_key_exchange(group);
                            pqc_algorithms_found.push(key_type);
                            println!("Found PQC key share: {}", classify_key_exchange(group));
                        }
                        offset += 4 + key_len;
                    }
                }
            },
            0x002a => { // early_data
                has_early_data = true;
                critical_extensions.push("early_data".to_string());
            },
            0x002d => { // psk_key_exchange_modes - ALSO indicates 0-RTT capability
                has_psk_key_exchange_modes = true;
                has_early_data = true; // Set the same flag for 0-RTT detection
                critical_extensions.push("psk_key_exchange_modes".to_string());
            },
            0x0023 => { // session_ticket
                has_session_ticket = true;
                critical_extensions.push("session_ticket".to_string());
            },
            0x002b => { // supported_versions
                has_supported_versions = true;
                critical_extensions.push("supported_versions".to_string());
            },
            _ => {
                // Add all other extensions to critical list for complete counting
                critical_extensions.push(ext_name);
            }
        }
        
        if is_pqc_relevant_extension(*ext_type) {
            pqc_extensions.push(extension_id_to_name(*ext_type));
        }
    }
    
    // Build specific PQC algorithm list instead of just extension names
    let pqc_relevant_with_values = if !pqc_algorithms_found.is_empty() {
        pqc_algorithms_found.join(",")
    } else {
        pqc_extensions.join(",")
    };
    
    // FIXED: Only create TLS 1.3 features for actual TLS 1.3 flows
    let tls13_features = if is_tls13_flow {
        let mut features = Vec::new();
        if has_supported_groups { features.push("SG"); }
        if has_signature_algorithms { features.push("SA"); }
        if has_supported_versions { features.push("SV"); }
        if has_key_share { features.push("KS"); }
        if has_psk_key_exchange_modes { features.push("PSK"); }
        if has_early_data && !has_psk_key_exchange_modes { features.push("ED"); }
        if has_session_ticket { features.push("ST"); }
        
        features.join(",")
    } else {
        String::new() // Empty for non-TLS 1.3 flows
    };
    
    let extension_complexity = if non_grease_extensions.len() > 10 {
        "high"
    } else if non_grease_extensions.len() > 5 {
        "medium"
    } else {
        "low"
    }.to_string();
    
    println!("Extension analysis complete: {} total, TLS 1.3: {}, {} PQC algorithms found", 
             non_grease_extensions.len(), is_tls13_flow, pqc_algorithms_found.len());
    
    (
        critical_extensions.join(","),               // critical_tls_extensions
        pqc_relevant_with_values,                    // pqc_relevant_extensions (now with actual algorithm names)
        tls13_features,                              // tls13_features (FIXED: only for TLS 1.3, no duplicates)
        if has_early_data || has_psk_key_exchange_modes { "true" } else { "false" }.to_string(), // supports_0rtt
        extension_complexity                         // extension_complexity
    )
}

// Bot detection helper
fn is_bot_ip(ip: &str) -> bool {
    const BOT_SERVERS: [&str; 3] = [
        "23.100.86.75",
        "172.173.65.147",
        "40.83.0.196"
    ];
    BOT_SERVERS.iter().any(|&server| ip == server)
}


fn extract_key_share_groups(ext_data: &[u8]) -> Vec<u16> {
    let mut groups = Vec::new();
    let mut i = 2; // Skip length field
    while i + 4 <= ext_data.len() {
        let group = ((ext_data[i] as u16) << 8) | (ext_data[i + 1] as u16);
        groups.push(group);
        let len = ((ext_data[i + 2] as usize) << 8) | (ext_data[i + 3] as usize);
        i += 4 + len;
    }
    groups
}

// Enhanced PQC detection functions
pub fn detect_pqc_key_exchanges(extensions: &[(u16, &[u8])]) -> Vec<String> {
    let mut pqc_key_exchanges = Vec::new();
    for &(ext_type, ext_data) in extensions {
        if ext_type == 0x0033 {
            for group in extract_key_share_groups(ext_data) {
                pqc_key_exchanges.push(format!("0x{:04x}", group));
            }
        }
    }
    pqc_key_exchanges
}

// Update PQC detection constants
const PQC_CIPHER_SUITES: &[u16] = &[
    // Currently no standardized PQC-only cipher suites in IANA registry
    // Most PQC is implemented via extensions (key_share, signature_algorithms)
    // TLS 1.3 standard suites (0x1301-0x1307) are NOT PQC by themselves
];

const PQC_KEY_EXCHANGE_GROUPS: &[u16] = &[
    // ML-KEM (Kyber) Groups - Standardized
    0x0200, // MLKEM512  
    0x0201, // MLKEM768
    0x0202, // MLKEM1024
    // Legacy Kyber (draft implementations)
    0x023A, // Kyber512
    0x023C, // Kyber768  
    0x023D, // Kyber1024
];

const HYBRID_KEY_EXCHANGE_GROUPS: &[u16] = &[
    // IANA Registered Hybrid Key Exchange Groups
    0x2F39, // X25519Kyber768
    0x2F3A, // X448Kyber768  
    0x2F3B, // P256Kyber768
    0x2F3C, // P384Kyber768
    0x2F3D, // P521Kyber768
    0x2F3E, // X25519ML-KEM-512
    0x2F3F, // X25519ML-KEM-768
];

const PQC_SIGNATURE_ALGORITHMS: &[u16] = &[
    // ML-DSA (Dilithium) - Standardized
    0xFEA0, // ML-DSA-44 (Dilithium2)
    0xFEA3, // ML-DSA-65 (Dilithium3)  
    0xFEA5, // ML-DSA-87 (Dilithium5)
    // SLH-DSA (SPHINCS+)
    0xFEA9, // SLH-DSA
];

const HYBRID_SIGNATURE_ALGORITHMS: &[u16] = &[
    // IANA Registered Hybrid Signature Schemes
    0xFEA1, // P256_Dilithium2
    0xFEA2, // RSA3072_Dilithium2
    0xFEA4, // P384_Dilithium3  
    0xFEA6, // P521_Dilithium5
];

// Classical cipher suites (comprehensive list from IANA)
const CLASSICAL_CIPHER_SUITES: &[u16] = &[
    // TLS 1.3 Standard Cipher Suites (these are classical, not PQC)
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1304, // TLS_AES_128_CCM_SHA256
    0x1305, // TLS_AES_128_CCM_8_SHA256
    0x1306, // TLS_AEGIS_256_SHA512
    0x1307, // TLS_AEGIS_128L_SHA256
    
    // RSA Cipher Suites
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A,
    0x002F, 0x0035, 0x003B, 0x003C, 0x003D, 0x0067, 0x006B, 0x009C, 0x009D,
    
    // ECDHE Cipher Suites  
    0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028, 0xC02B, 0xC02C,
    0xC02F, 0xC030, 0xC048, 0xC049, 0xC04C, 0xC04D, 0xC05C, 0xC05D, 0xC060, 0xC061,
    0xC072, 0xC073, 0xC076, 0xC077, 0xC086, 0xC087, 0xC08A, 0xC08B, 0xC0AC, 0xC0AD,
    0xC0AE, 0xC0AF,
    
    // ChaCha20-Poly1305
    0xCCA8, 0xCCA9, 0xCCAA, 0xCCAB, 0xCCAC, 0xCCAD, 0xCCAE,
    
    // Additional common suites (abbreviated for space - full list available)
    // AES-GCM, AES-CBC, Camellia, ARIA, etc.
];

pub fn is_pqc_cipher_suite(cipher: u16) -> bool {
    PQC_CIPHER_SUITES.contains(&cipher)
}

pub fn is_classical_cipher_suite(cipher: u16) -> bool {
    CLASSICAL_CIPHER_SUITES.contains(&cipher)
}

pub fn is_pqc_key_share(group: u16) -> bool {
    PQC_KEY_EXCHANGE_GROUPS.contains(&group)
}

pub fn is_hybrid_key_share(group: u16) -> bool {
    HYBRID_KEY_EXCHANGE_GROUPS.contains(&group)
}

pub fn is_pqc_signature_algorithm(sig_alg: u16) -> bool {
    PQC_SIGNATURE_ALGORITHMS.contains(&sig_alg)
}

pub fn is_hybrid_signature_algorithm(sig_alg: u16) -> bool {
    HYBRID_SIGNATURE_ALGORITHMS.contains(&sig_alg)
}

// Comprehensive cipher suite classification
pub fn classify_cipher_suite(cipher: u16) -> String {
    if is_pqc_cipher_suite(cipher) {
        "PQC".to_string()
    } else if is_classical_cipher_suite(cipher) {
        match cipher {
            0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
            0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            0x1304 => "TLS_AES_128_CCM_SHA256".to_string(),
            0x1305 => "TLS_AES_128_CCM_8_SHA256".to_string(),
            0x1306 => "TLS_AEGIS_256_SHA512".to_string(),
            0x1307 => "TLS_AEGIS_128L_SHA256".to_string(),
            _ => "Classical".to_string(),
        }
    } else {
        format!("Unknown-0x{:04x}", cipher)
    }
}

pub fn classify_key_exchange(group: u16) -> String {
    if is_pqc_key_share(group) {
        match group {
            0x0200 => "MLKEM512".to_string(),
            0x0201 => "MLKEM768".to_string(), 
            0x0202 => "MLKEM1024".to_string(),
            0x023A => "Kyber512".to_string(),
            0x023C => "Kyber768".to_string(),
            0x023D => "Kyber1024".to_string(),
            _ => "PQC-KEM".to_string(),
        }
    } else if is_hybrid_key_share(group) {
        match group {
            0x2F39 => "X25519Kyber768".to_string(),
            0x2F3A => "X448Kyber768".to_string(),
            0x2F3B => "P256Kyber768".to_string(),
            0x2F3C => "P384Kyber768".to_string(),
            0x2F3D => "P521Kyber768".to_string(),
            0x2F3E => "X25519ML-KEM-512".to_string(),
            0x2F3F => "X25519ML-KEM-768".to_string(),
            _ => "Hybrid-KEM".to_string(),
        }
    } else {
        match group {
            0x0017 => "secp256r1".to_string(),
            0x0018 => "secp384r1".to_string(),
            0x0019 => "secp521r1".to_string(),
            0x001D => "x25519".to_string(),
            0x001E => "x448".to_string(),
            _ => format!("Unknown-0x{:04x}", group),
        }
    }
}

pub fn classify_signature_algorithm(sig_alg: u16) -> String {
    if is_pqc_signature_algorithm(sig_alg) {
        match sig_alg {
            0xFEA0 => "ML-DSA-44".to_string(),
            0xFEA3 => "ML-DSA-65".to_string(),
            0xFEA5 => "ML-DSA-87".to_string(),
            0xFEA9 => "SLH-DSA".to_string(),
            _ => "PQC-Signature".to_string(),
        }
    } else if is_hybrid_signature_algorithm(sig_alg) {
        match sig_alg {
            0xFEA1 => "P256_Dilithium2".to_string(),
            0xFEA2 => "RSA3072_Dilithium2".to_string(),
            0xFEA4 => "P384_Dilithium3".to_string(),
            0xFEA6 => "P521_Dilithium5".to_string(),
            _ => "Hybrid-Signature".to_string(),
        }
    } else {
        match sig_alg {
            0x0401 => "RSA-PKCS1-SHA256".to_string(),
            0x0501 => "RSA-PKCS1-SHA384".to_string(),
            0x0601 => "RSA-PKCS1-SHA512".to_string(),
            0x0403 => "ECDSA-secp256r1-SHA256".to_string(),
            0x0503 => "ECDSA-secp384r1-SHA384".to_string(),
            0x0603 => "ECDSA-secp521r1-SHA512".to_string(),
            0x0807 => "Ed25519".to_string(),
            0x0808 => "Ed448".to_string(),
            _ => format!("Unknown-0x{:04x}", sig_alg),
        }
    }
}



// Enhanced certificate parsing functions
fn parse_certificate_signature_algorithm(cert_data: &[u8]) -> Option<String> {
    println!("Parsing certificate, length: {}", cert_data.len());
    
    // Input validation
    if cert_data.len() < 10 {
        println!("Certificate data too short: {} bytes", cert_data.len());
        return None;
    }
    
    // Validate that it starts with a SEQUENCE tag (0x30)
    if cert_data[0] != 0x30 {
        println!("Certificate data doesn't start with SEQUENCE tag: 0x{:02x}", cert_data[0]);
        // Try to find a valid certificate in the data
        if let Some(offset) = find_certificate_start(cert_data) {
            println!("Found potential certificate at offset {}", offset);
            return parse_certificate_signature_algorithm(&cert_data[offset..]);
        }
        return None;
    }
    
    // Try x509-parser first
    match parse_x509_certificate(cert_data) {
        Ok((_, cert)) => {
            // Get the signature algorithm OID directly
            let oid = &cert.signature_algorithm.algorithm;
            let oid_str = oid.to_string();
            
            let alg_name = oid_to_algorithm_name(&oid_str)
                .unwrap_or_else(|| format!("Unknown-{}", oid_str));
            
            println!("Certificate algorithm: {} (OID: {})", alg_name, oid_str);
            return Some(alg_name);
        },
        Err(e) => {
            println!("X.509 parse error: {:?}", e);
            
            // Enhanced fallback - try to find any recognizable OID pattern
            if let Some(classical_alg) = detect_classical_signature_algorithm(cert_data) {
                println!("Using classical algorithm fallback: {}", classical_alg);
                return Some(classical_alg);
            }
            
            if let Some(pqc_oid) = find_any_pqc_oid(cert_data) {
                let alg_name = get_pqc_algorithm_name(&pqc_oid);
                println!("Using PQC fallback: {} (OID: {})", alg_name, pqc_oid);
                return Some(alg_name);
            }
            
            // Last resort - try manual OID search
            if let Some(oid) = find_signature_algorithm_oid(cert_data) {
                let alg_name = oid_to_algorithm_name(&oid)
                    .unwrap_or_else(|| format!("Unknown-{}", oid));
                println!("Using manual OID fallback: {} (OID: {})", alg_name, oid);
                return Some(alg_name);
            }
        }
    }
    
    println!("Failed to parse certificate signature algorithm");
    None
}

fn find_certificate_start(data: &[u8]) -> Option<usize> {
    // Look for SEQUENCE tag (0x30) followed by reasonable length
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0x30 {
            // Check if this looks like a valid certificate start
            if let Some((length, _)) = parse_asn1_length(&data[i+1..]) {
                if length > 100 && length < data.len() - i {
                    return Some(i);
                }
            }
        }
    }
    None
}

fn find_signature_algorithm_oid(cert_data: &[u8]) -> Option<String> {
    // Parse the outer SEQUENCE of the certificate
    let mut pos = 0;
    
    // Skip outer SEQUENCE tag and length
    if cert_data.len() < 2 || cert_data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    
    // Skip length field
    let (_length, new_pos) = parse_asn1_length(&cert_data[pos..])?;
    pos += new_pos;
    
    // Parse the TBSCertificate SEQUENCE
    if pos >= cert_data.len() || cert_data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    
    let (tbs_length, new_pos) = parse_asn1_length(&cert_data[pos..])?;
    pos += new_pos;
    let tbs_end = pos + tbs_length;
    
    // Skip TBSCertificate content
    pos = tbs_end;
    
    // Now we should be at the signatureAlgorithm field
    if pos >= cert_data.len() || cert_data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    
    let (_sig_alg_length, _new_pos) = parse_asn1_length(&cert_data[pos..])?;
    
    // Look for OID in the signature algorithm
    if pos >= cert_data.len() || cert_data[pos] != 0x06 {
        return None;
    }
    pos += 1;
    
    let oid_length = *cert_data.get(pos)? as usize;
    pos += 1;
    
    if pos + oid_length <= cert_data.len() {
        return parse_oid(&cert_data[pos..pos + oid_length]);
    }
    
    None
}

fn find_any_pqc_oid(cert_data: &[u8]) -> Option<String> {
    let mut pos = 0;
    let mut oid_count = 0;
    
    while pos + 1 < cert_data.len() {
        if cert_data[pos] == 0x06 { // OID tag
            oid_count += 1;
            pos += 1;
            if pos >= cert_data.len() {
                break;
            }
            
            let oid_length = cert_data[pos] as usize;
            pos += 1;
            
            if pos + oid_length <= cert_data.len() {
                if let Some(oid) = parse_oid(&cert_data[pos..pos + oid_length]) {
                    // Debug: print first few OIDs found
                    if oid_count <= 5 {
                        println!("Found OID #{}: {}", oid_count, oid);
                    }
                    
                    if is_pqc_oid(&oid) {
                        println!("PQC OID match: {}", oid);
                        return Some(oid);
                    }
                }
            }
            pos += oid_length;
        } else {
            pos += 1;
        }
    }
    
    println!("Scanned {} OIDs, no PQC matches found", oid_count);
    None
}

fn detect_classical_signature_algorithm(cert_data: &[u8]) -> Option<String> {
    // Look for common classical signature algorithm OIDs
    let classical_oids = [
        ("1.2.840.113549.1.1.1", "RSA"),
        ("1.2.840.113549.1.1.5", "RSA-SHA1"),
        ("1.2.840.113549.1.1.11", "RSA-SHA256"),
        ("1.2.840.113549.1.1.12", "RSA-SHA384"),
        ("1.2.840.113549.1.1.13", "RSA-SHA512"),
        ("1.2.840.10045.2.1", "ECDSA"),
        ("1.2.840.10045.4.3.2", "ECDSA-SHA256"),
        ("1.2.840.10045.4.3.3", "ECDSA-SHA384"),
        ("1.2.840.10045.4.3.4", "ECDSA-SHA512"),
        ("1.3.101.112", "Ed25519"),
        ("1.3.101.113", "Ed448"),
    ];
    
    let mut pos = 0;
    while pos + 1 < cert_data.len() {
        if cert_data[pos] == 0x06 { // OID tag
            pos += 1;
            if pos >= cert_data.len() {
                break;
            }
            
            let oid_length = cert_data[pos] as usize;
            pos += 1;
            
            if pos + oid_length <= cert_data.len() {
                if let Some(oid) = parse_oid(&cert_data[pos..pos + oid_length]) {
                    for (target_oid, name) in &classical_oids {
                        if oid == *target_oid {
                            return Some(name.to_string());
                        }
                    }
                }
            }
            pos += oid_length;
        } else {
            pos += 1;
        }
    }
    
    None
}

fn parse_asn1_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    
    let first_byte = data[0];
    if first_byte & 0x80 == 0 {
        // Short form
        Some((first_byte as usize, 1))
    } else {
        // Long form
        let length_bytes = (first_byte & 0x7F) as usize;
        if length_bytes == 0 || length_bytes > 4 || data.len() < 1 + length_bytes {
            return None;
        }
        
        let mut length = 0;
        for i in 0..length_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }
        
        Some((length, 1 + length_bytes))
    }
}

fn oid_to_algorithm_name(oid: &str) -> Option<String> {
    match oid {
        // PQC algorithms
        "2.16.840.1.101.3.4.3.17" => Some("ML-DSA-44".to_string()),
        "2.16.840.1.101.3.4.3.18" => Some("ML-DSA-65".to_string()),
        "2.16.840.1.101.3.4.3.19" => Some("ML-DSA-87".to_string()),
        "2.16.840.1.101.3.4.3.20" => Some("SLH-DSA-SHA2-128s".to_string()),
        "2.16.840.1.101.3.4.3.21" => Some("SLH-DSA-SHA2-128f".to_string()),
        "2.16.840.1.101.3.4.3.22" => Some("SLH-DSA-SHA2-192s".to_string()),
        "2.16.840.1.101.3.4.3.23" => Some("SLH-DSA-SHA2-192f".to_string()),
        "2.16.840.1.101.3.4.3.24" => Some("SLH-DSA-SHA2-256s".to_string()),
        "2.16.840.1.101.3.4.3.25" => Some("SLH-DSA-SHA2-256f".to_string()),
        "1.3.6.1.4.1.2.267.7.4.4" => Some("Dilithium2".to_string()),
        "1.3.6.1.4.1.2.267.7.6.5" => Some("Dilithium3".to_string()),
        "1.3.6.1.4.1.2.267.7.8.7" => Some("Dilithium5".to_string()),
        // Hybrid algorithms
        "2.16.840.1.114027.80.8.1.21" => Some("MLDSA44-RSA2048-PSS".to_string()),
        "2.16.840.1.114027.80.8.1.23" => Some("MLDSA44-Ed25519".to_string()),
        "2.16.840.1.114027.80.8.1.24" => Some("MLDSA44-ECDSA-P256".to_string()),
        "2.16.840.1.114027.80.8.1.28" => Some("MLDSA65-ECDSA-P384".to_string()),
        // Classical algorithms
        "1.2.840.113549.1.1.1" => Some("RSA".to_string()),
        "1.2.840.113549.1.1.5" => Some("RSA-SHA1".to_string()),
        "1.2.840.113549.1.1.11" => Some("RSA-SHA256".to_string()),
        "1.2.840.113549.1.1.12" => Some("RSA-SHA384".to_string()),
        "1.2.840.113549.1.1.13" => Some("RSA-SHA512".to_string()),
        "1.2.840.10045.2.1" => Some("ECDSA".to_string()),
        "1.2.840.10045.4.3.2" => Some("ECDSA-SHA256".to_string()),
        "1.2.840.10045.4.3.3" => Some("ECDSA-SHA384".to_string()),
        "1.2.840.10045.4.3.4" => Some("ECDSA-SHA512".to_string()),
        "1.3.101.112" => Some("Ed25519".to_string()),
        "1.3.101.113" => Some("Ed448".to_string()),
        _ => None,
    }
}

fn is_pqc_algorithm_name(name: &str) -> bool {
    matches!(name,
        "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" |
        "SLH-DSA-SHA2-128s" | "SLH-DSA-SHA2-128f" |
        "SLH-DSA-SHA2-192s" | "SLH-DSA-SHA2-192f" |
        "SLH-DSA-SHA2-256s" | "SLH-DSA-SHA2-256f" |
        "Dilithium2" | "Dilithium3" | "Dilithium5" |
        "MLDSA44-RSA2048-PSS" | "MLDSA44-Ed25519" |
        "MLDSA44-ECDSA-P256" | "MLDSA65-ECDSA-P384"
    )
}

fn is_hybrid_algorithm_name(name: &str) -> bool {
    matches!(name,
        "MLDSA44-RSA2048-PSS" | "MLDSA44-Ed25519" |
        "MLDSA44-ECDSA-P256" | "MLDSA65-ECDSA-P384"
    )
}

fn get_pqc_algorithm_name(oid: &str) -> String {
    match oid {
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44".to_string(),
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65".to_string(),
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87".to_string(),
        "2.16.840.1.101.3.4.3.20" => "SLH-DSA-SHA2-128s".to_string(),
        "2.16.840.1.101.3.4.3.21" => "SLH-DSA-SHA2-128f".to_string(),
        "2.16.840.1.101.3.4.3.22" => "SLH-DSA-SHA2-192s".to_string(),
        "2.16.840.1.101.3.4.3.23" => "SLH-DSA-SHA2-192f".to_string(),
        "2.16.840.1.101.3.4.3.24" => "SLH-DSA-SHA2-256s".to_string(),
        "2.16.840.1.101.3.4.3.25" => "SLH-DSA-SHA2-256f".to_string(),
        "1.3.6.1.4.1.2.267.7.4.4" => "Dilithium2".to_string(),
        "1.3.6.1.4.1.2.267.7.6.5" => "Dilithium3".to_string(),
        "1.3.6.1.4.1.2.267.7.8.7" => "Dilithium5".to_string(),
        "2.16.840.1.114027.80.8.1.21" => "MLDSA44-RSA2048-PSS".to_string(),
        "2.16.840.1.114027.80.8.1.23" => "MLDSA44-Ed25519".to_string(),
        "2.16.840.1.114027.80.8.1.24" => "MLDSA44-ECDSA-P256".to_string(),
        "2.16.840.1.114027.80.8.1.28" => "MLDSA65-ECDSA-P384".to_string(),
        _ => format!("PQC-Unknown-{}", oid),
    }
}

fn parse_oid(oid_bytes: &[u8]) -> Option<String> {
    if oid_bytes.is_empty() {
        return None;
    }
    
    let mut result = Vec::new();
    let mut pos = 0;
    
    // First byte encodes the first two sub-identifiers
    if pos >= oid_bytes.len() {
        return None;
    }
    
    let first_byte = oid_bytes[pos] as u32;
    pos += 1;
    
    let first_sub = first_byte / 40;
    let second_sub = first_byte % 40;
    
    result.push(first_sub.to_string());
    result.push(second_sub.to_string());
    
    // Parse remaining sub-identifiers
    while pos < oid_bytes.len() {
        let mut value = 0u32;
        let mut has_more = true;
        
        while has_more && pos < oid_bytes.len() {
            let byte = oid_bytes[pos] as u32;
            pos += 1;
            
            has_more = (byte & 0x80) != 0;
            value = (value << 7) | (byte & 0x7F);
            
            // Prevent overflow
            if value > 0x7FFFFFFF {
                return None;
            }
        }
        
        result.push(value.to_string());
    }
    
    if result.len() >= 2 {
        Some(result.join("."))
    } else {
        None
    }
}

fn is_pqc_oid(oid: &str) -> bool {
    // NIST standardized PQC OIDs
    matches!(oid,
        // ML-DSA (Dilithium)
        "2.16.840.1.101.3.4.3.17" | // ML-DSA-44
        "2.16.840.1.101.3.4.3.18" | // ML-DSA-65
        "2.16.840.1.101.3.4.3.19" | // ML-DSA-87
        // SLH-DSA (SPHINCS+)
        "2.16.840.1.101.3.4.3.20" | // SLH-DSA-SHA2-128s
        "2.16.840.1.101.3.4.3.21" | // SLH-DSA-SHA2-128f
        "2.16.840.1.101.3.4.3.22" | // SLH-DSA-SHA2-192s
        "2.16.840.1.101.3.4.3.23" | // SLH-DSA-SHA2-192f
        "2.16.840.1.101.3.4.3.24" | // SLH-DSA-SHA2-256s
        "2.16.840.1.101.3.4.3.25" | // SLH-DSA-SHA2-256f
        // Draft Dilithium OIDs
        "1.3.6.1.4.1.2.267.7.4.4" | // Dilithium2
        "1.3.6.1.4.1.2.267.7.6.5" | // Dilithium3
        "1.3.6.1.4.1.2.267.7.8.7" | // Dilithium5
        // Hybrid algorithms
        "2.16.840.1.114027.80.8.1.21" | // MLDSA44-RSA2048-PSS
        "2.16.840.1.114027.80.8.1.23" | // MLDSA44-Ed25519
        "2.16.840.1.114027.80.8.1.24" | // MLDSA44-ECDSA-P256
        "2.16.840.1.114027.80.8.1.28"   // MLDSA65-ECDSA-P384
    ) || oid.starts_with("2.16.840.1.101.3.4.3.") // NIST PQC range
      || oid.starts_with("1.3.6.1.4.1.2.267.7.") // Draft Dilithium range
      || oid.starts_with("2.16.840.1.114027.80.8.1.") // Hybrid range
}


// TLS Extension ID to name mapping based on IANA registry
fn extension_id_to_name(id: u16) -> String {
    match id {
        0x0000 => "server_name".to_string(),
        0x0001 => "max_fragment_length".to_string(),
        0x0002 => "client_certificate_url".to_string(),
        0x0003 => "trusted_ca_keys".to_string(),
        0x0004 => "truncated_hmac".to_string(),
        0x0005 => "status_request".to_string(),
        0x0006 => "user_mapping".to_string(),
        0x0007 => "client_authz".to_string(),
        0x0008 => "server_authz".to_string(),
        0x0009 => "cert_type".to_string(),
        0x000a => "supported_groups".to_string(),
        0x000b => "ec_point_formats".to_string(),
        0x000c => "srp".to_string(),
        0x000d => "signature_algorithms".to_string(),
        0x000e => "use_srtp".to_string(),
        0x000f => "heartbeat".to_string(),
        0x0010 => "application_layer_protocol_negotiation".to_string(),
        0x0011 => "status_request_v2".to_string(),
        0x0012 => "signed_certificate_timestamp".to_string(),
        0x0013 => "client_certificate_type".to_string(),
        0x0014 => "server_certificate_type".to_string(),
        0x0015 => "padding".to_string(),
        0x0016 => "encrypt_then_mac".to_string(),
        0x0017 => "extended_master_secret".to_string(),
        0x0018 => "token_binding".to_string(),
        0x0019 => "cached_info".to_string(),
        0x001a => "tls_lts".to_string(),
        0x001b => "compress_certificate".to_string(),
        0x001c => "record_size_limit".to_string(),
        0x001d => "pwd_protect".to_string(),
        0x001e => "pwd_clear".to_string(),
        0x001f => "password_salt".to_string(),
        0x0020 => "ticket_pinning".to_string(),
        0x0021 => "tls_cert_with_extern_psk".to_string(),
        0x0022 => "delegated_credential".to_string(),
        0x0023 => "session_ticket".to_string(),
        0x0024 => "TLMSP".to_string(),
        0x0025 => "TLMSP_proxying".to_string(),
        0x0026 => "TLMSP_delegate".to_string(),
        0x0027 => "supported_ekt_ciphers".to_string(),
        0x0029 => "pre_shared_key".to_string(),
        0x002a => "early_data".to_string(),
        0x002b => "supported_versions".to_string(),
        0x002c => "cookie".to_string(),
        0x002d => "psk_key_exchange_modes".to_string(),
        0x002f => "certificate_authorities".to_string(),
        0x0030 => "oid_filters".to_string(),
        0x0031 => "post_handshake_auth".to_string(),
        0x0032 => "signature_algorithms_cert".to_string(),
        0x0033 => "key_share".to_string(),
        0x0034 => "transparency_info".to_string(),
        0x0036 => "connection_id".to_string(),
        0x0037 => "external_id_hash".to_string(),
        0x0038 => "external_session_id".to_string(),
        0x0039 => "quic_transport_parameters".to_string(),
        0x003a => "ticket_request".to_string(),
        0x003b => "dnssec_chain".to_string(),
        0x003c => "sequence_number_encryption_algorithms".to_string(),
        0x003d => "rrc".to_string(),
        0xfd00 => "ech_outer_extensions".to_string(),
        0xfe0d => "encrypted_client_hello".to_string(),
        0xff01 => "renegotiation_info".to_string(),
        _ => format!("unknown_0x{:04x}", id),
    }
}

// Check if an extension ID is a GREASE value (RFC 8701)
fn is_grease_extension(id: u16) -> bool {
    // GREASE values have the pattern 0xXAXA where X is any nibble
    (id & 0x0F0F) == 0x0A0A
}

// Identify PQC-relevant extensions
fn is_pqc_relevant_extension(id: u16) -> bool {
    matches!(id, 
        0x000a | // supported_groups (may contain PQC KEMs)
        0x000d | // signature_algorithms (may contain PQC signatures)
        0x0032 | // signature_algorithms_cert (may contain PQC signatures)
        0x0033   // key_share (may contain PQC key exchanges)
    )
}


// Specific detection functions for Kyber and ML-DSA
pub fn is_kyber_key_exchange(group: u16) -> bool {
    matches!(group,
        0x023A | // Kyber512
        0x023C | // Kyber768  
        0x023D | // Kyber1024
        0x0200 | // MLKEM512 (standardized Kyber)
        0x0201 | // MLKEM768
        0x0202   // MLKEM1024
    )
}

pub fn is_ml_dsa_signature_algorithm(sig_alg: u16) -> bool {
    matches!(sig_alg,
        0xFEA0 | // ML-DSA-44 (Dilithium2)
        0xFEA3 | // ML-DSA-65 (Dilithium3)  
        0xFEA5   // ML-DSA-87 (Dilithium5)
    )
}



