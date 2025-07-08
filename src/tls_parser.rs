pub fn parse_tls_record<'a>(data: &'a [u8]) -> Option<TlsRecord<'a>> {
    println!("\nParsing TLS record of size {}", data.len());
    
    if data.len() < 5 {
        println!("Record too short for header (need 5, got {})", data.len());
        return None;
    }

    let content_type = data[0];
    let version = parse_u16_be(&data[1..3])?;
    let length = parse_u16_be(&data[3..5])?;
    
    println!("Record header:");
    println!("Content type: {} ({})", content_type, match content_type {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application",
        _ if content_type >= 0x80 => "Encrypted",
        _ => "Unknown"
    });
    println!("Version: 0x{:04x}", version);
    println!("Length: {}", length);
    
    if data.len() < 5 + (length as usize) {
        println!("Incomplete record: need {}, got {}", 5 + length, data.len());
        return None;
    }

    match content_type {
        20 => { // Change Cipher Spec
            println!("Change Cipher Spec record");
            Some(TlsRecord {
                content_type,
                version,
                length,
                handshake: None,
            })
        },
        21 => { // Alert
            println!("Alert record");
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
                println!("Handshake record too short");
                return None;
            }

            let handshake_type = handshake_data[0];
            let handshake_length = parse_u24_be(&handshake_data[1..4])? as usize;
            
            println!("Handshake message:");
            println!("Type: {} ({})", handshake_type, match handshake_type {
                1 => "ClientHello",
                2 => "ServerHello",
                11 => "Certificate",
                15 => "CertificateVerify",
                _ => "Other"
            });
            println!("Length: {}", handshake_length);
            
            if handshake_data.len() < 4 + handshake_length {
                println!("Incomplete handshake message");
                return None;
            }

            match handshake_type {
                1 => { // ClientHello
                    println!("\nProcessing ClientHello");
                    let client_hello_data = &handshake_data[4..4 + handshake_length];
                    if client_hello_data.len() < 2 + 32 + 1 {
                        println!("ClientHello too short");
                        return None;
                    }
                    
                    let client_version = parse_u16_be(&client_hello_data[0..2])?;
                    println!("Client version: 0x{:04x}", client_version);
                    
                    let random = &client_hello_data[2..34];
                    println!("Random data length: {}", random.len());
                    
                    let mut offset = 34;
                    if client_hello_data.len() < offset + 1 {
                        println!("No room for session ID");
                        return None;
                    }
                    
                    let session_id_len = client_hello_data[offset] as usize;
                    offset += 1;
                    println!("Session ID length: {}", session_id_len);
                    
                    if client_hello_data.len() < offset + session_id_len {
                        println!("Incomplete session ID");
                        return None;
                    }
                    let session_id = &client_hello_data[offset..offset + session_id_len];
                    offset += session_id_len;
                    
                    if client_hello_data.len() < offset + 2 {
                        println!("No room for cipher suites");
                        return None;
                    }
                    
                    let cipher_suites_len = parse_u16_be(&client_hello_data[offset..offset + 2])? as usize;
                    offset += 2;
                    println!("Cipher suites length: {}", cipher_suites_len);
                    
                    let mut cipher_suites = Vec::new();
                    if client_hello_data.len() < offset + cipher_suites_len {
                        println!("Incomplete cipher suites");
                        return None;
                    }
                    
                    for _ in 0..(cipher_suites_len / 2) {
                        let cs = parse_u16_be(&client_hello_data[offset..offset + 2])?;
                        println!("Cipher suite: 0x{:04x}", cs);
                        cipher_suites.push(cs);
                        offset += 2;
                    }
                    
                    if client_hello_data.len() < offset + 1 {
                        println!("No room for compression methods");
                        return None;
                    }
                    
                    let comp_methods_len = client_hello_data[offset] as usize;
                    offset += 1;
                    println!("Compression methods length: {}", comp_methods_len);
                    
                    if client_hello_data.len() < offset + comp_methods_len {
                        println!("Incomplete compression methods");
                        return None;
                    }
                    let compression_methods = client_hello_data[offset..offset + comp_methods_len].to_vec();
                    offset += comp_methods_len;
                    
                    let mut extensions = Vec::new();
                    if client_hello_data.len() >= offset + 2 {
                        let ext_total_len = parse_u16_be(&client_hello_data[offset..offset + 2])? as usize;
                        println!("Extensions total length: {}", ext_total_len);
                        offset += 2;
                        
                        let ext_end = offset + ext_total_len;
                        while offset + 4 <= ext_end && ext_end <= client_hello_data.len() {
                            let ext_type = parse_u16_be(&client_hello_data[offset..offset + 2])?;
                            let ext_len = parse_u16_be(&client_hello_data[offset + 2..offset + 4])? as usize;
                            println!("\nExtension type: 0x{:04x}, length: {}", ext_type, ext_len);
                            
                            offset += 4;
                            if client_hello_data.len() < offset + ext_len {
                                println!("Incomplete extension data");
                                break;
                            }
                            
                            let ext_data = &client_hello_data[offset..offset + ext_len];
                            
                            // Special handling for important extensions
                            match ext_type {
                                0x000a => { // supported_groups
                                    if ext_data.len() >= 2 {
                                        let groups_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                                        println!("Supported groups:");
                                        let mut i = 2;
                                        while i + 2 <= ext_data.len() && i - 2 < groups_len {
                                            let group = ((ext_data[i] as u16) << 8) | ext_data[i + 1] as u16;
                                            println!("  Group: 0x{:04x}", group);
                                            i += 2;
                                        }
                                    }
                                },
                                0x002b => { // supported_versions
                                    if ext_data.len() >= 1 {
                                        let versions_len = ext_data[0] as usize;
                                        println!("Supported versions:");
                                        let mut i = 1;
                                        while i + 2 <= ext_data.len() && i <= versions_len {
                                            let version = ((ext_data[i] as u16) << 8) | ext_data[i + 1] as u16;
                                            println!("  Version: 0x{:04x}", version);
                                            i += 2;
                                        }
                                    }
                                },
                                0x0033 => { // key_share
                                    if ext_data.len() >= 2 {
                                        let shares_len = ((ext_data[0] as usize) << 8) | ext_data[1] as usize;
                                        println!("Key shares:");
                                        let mut i = 2;
                                        while i + 4 <= ext_data.len() {
                                            let group = ((ext_data[i] as u16) << 8) | ext_data[i + 1] as u16;
                                            let key_len = ((ext_data[i + 2] as usize) << 8) | ext_data[i + 3] as usize;
                                            println!("  Group: 0x{:04x}, key length: {}", group, key_len);
                                            i += 4 + key_len;
                                        }
                                    }
                                },
                                _ => {}
                            }
                            
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
                    println!("\nProcessing ServerHello");
                    let server_hello_data = &handshake_data[4..4 + handshake_length];
                    if server_hello_data.len() < 2 + 32 + 1 {
                        println!("ServerHello too short");
                        return None;
                    }
                    
                    let server_version = parse_u16_be(&server_hello_data[0..2])?;
                    println!("Server version: 0x{:04x}", server_version);
                    
                    let mut offset = 2 + 32; // Skip random
                    if server_hello_data.len() < offset + 1 {
                        println!("No room for session ID");
                        return None;
                    }
                    
                    let session_id_len = server_hello_data[offset] as usize;
                    offset += 1;
                    println!("Session ID length: {}", session_id_len);
                    
                    if server_hello_data.len() < offset + session_id_len {
                        println!("Incomplete session ID");
                        return None;
                    }
                    offset += session_id_len;
                    
                    if server_hello_data.len() < offset + 2 {
                        println!("No room for cipher suite");
                        return None;
                    }
                    
                    let cipher_suite = parse_u16_be(&server_hello_data[offset..offset + 2])?;
                    println!("Selected cipher suite: 0x{:04x}", cipher_suite);
                    offset += 2;
                    
                    if server_hello_data.len() < offset + 1 {
                        println!("No room for compression method");
                        return None;
                    }
                    offset += 1;
                    
                    let mut extensions = Vec::new();
                    if server_hello_data.len() >= offset + 2 {
                        let ext_total_len = parse_u16_be(&server_hello_data[offset..offset + 2])? as usize;
                        println!("Extensions total length: {}", ext_total_len);
                        offset += 2;
                        
                        let ext_end = offset + ext_total_len;
                        while offset + 4 <= ext_end && ext_end <= server_hello_data.len() {
                            let ext_type = parse_u16_be(&server_hello_data[offset..offset + 2])?;
                            let ext_len = parse_u16_be(&server_hello_data[offset + 2..offset + 4])? as usize;
                            println!("\nExtension type: 0x{:04x}, length: {}", ext_type, ext_len);
                            
                            offset += 4;
                            if server_hello_data.len() < offset + ext_len {
                                println!("Incomplete extension data");
                                break;
                            }
                            
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
                    println!("\nProcessing Certificate");
                    let cert_msg_data = &handshake_data[4..4 + handshake_length];
                    
                    // Parse certificate message structure
                    let mut certificates = Vec::new();
                    let mut pos = 0;
                    
                    if cert_msg_data.len() < 4 {
                        println!("Certificate message too short: {} bytes", cert_msg_data.len());
                        return Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::Certificate(certificates)),
                        });
                    }
                    
                    // Parse certificate_request_context (TLS 1.3)
                    let context_len = cert_msg_data[pos] as usize;
                    pos += 1;
                    
                    if pos + context_len > cert_msg_data.len() {
                        println!("Invalid certificate request context length: {}", context_len);
                        return Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::Certificate(certificates)),
                        });
                    }
                    
                    pos += context_len; // Skip context
                    
                    // Parse certificate_list length (3 bytes)
                    if pos + 3 > cert_msg_data.len() {
                        println!("Certificate message truncated at list length");
                        return Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::Certificate(certificates)),
                        });
                    }
                    
                    let cert_list_len = ((cert_msg_data[pos] as usize) << 16) |
                                        ((cert_msg_data[pos + 1] as usize) << 8) |
                                        (cert_msg_data[pos + 2] as usize);
                    pos += 3;
                    
                    println!("Certificate list length: {} bytes", cert_list_len);
                    
                    let cert_list_end = pos + cert_list_len;
                    if cert_list_end > cert_msg_data.len() {
                        println!("Certificate list extends beyond message: {} > {}", cert_list_end, cert_msg_data.len());
                        return Some(TlsRecord {
                            content_type,
                            version,
                            length,
                            handshake: Some(HandshakeMessage::Certificate(certificates)),
                        });
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
                    
                    Some(TlsRecord {
                        content_type,
                        version,
                        length,
                        handshake: Some(HandshakeMessage::Certificate(certificates)),
                    })
                },
                _ => {
                    println!("Unhandled handshake type: {}", handshake_type);
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
            println!("Application Data record");
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
                println!("Possible encrypted TLS 1.3 record (type >= 0x80)");
                Some(TlsRecord {
                    content_type,
                    version,
                    length,
                    handshake: None,
                })
            } else {
                println!("Unknown record type: {}", content_type);
                None
            }
        }
    }
}                      

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TlsRecord, HandshakeMessage, ClientHello, ServerHello, parse_u16_be, parse_u24_be};

    // Helper function to create test data
    fn create_u16_be(value: u16) -> [u8; 2] {
        [(value >> 8) as u8, (value & 0xFF) as u8]
    }

    fn create_u24_be(value: u32) -> [u8; 3] {
        [(value >> 16) as u8, (value >> 8) as u8, (value & 0xFF) as u8]
    }

    #[test]
    fn test_parse_u16_be() {
        assert_eq!(parse_u16_be(&[0x12, 0x34]), Some(0x1234));
        assert_eq!(parse_u16_be(&[0x00, 0x00]), Some(0x0000));
        assert_eq!(parse_u16_be(&[0xFF, 0xFF]), Some(0xFFFF));
        assert_eq!(parse_u16_be(&[0x12]), None); // Too short
        assert_eq!(parse_u16_be(&[]), None); // Empty
    }

    #[test]
    fn test_parse_u24_be() {
        assert_eq!(parse_u24_be(&[0x12, 0x34, 0x56]), Some(0x123456));
        assert_eq!(parse_u24_be(&[0x00, 0x00, 0x00]), Some(0x000000));
        assert_eq!(parse_u24_be(&[0xFF, 0xFF, 0xFF]), Some(0xFFFFFF));
        assert_eq!(parse_u24_be(&[0x12, 0x34]), None); // Too short
        assert_eq!(parse_u24_be(&[]), None); // Empty
    }

    #[test]
    fn test_parse_tls_record_too_short() {
        // Test with data too short for TLS record header
        assert_eq!(parse_tls_record(&[0x16]), None); // Only content type
        assert_eq!(parse_tls_record(&[0x16, 0x03, 0x01]), None); // Missing length
        assert_eq!(parse_tls_record(&[]), None); // Empty data
    }

    #[test]
    fn test_parse_tls_record_change_cipher_spec() {
        // Change Cipher Spec record
        let data = vec![
            0x14, // Content type: Change Cipher Spec
            0x03, 0x01, // Version: TLS 1.0
            0x00, 0x01, // Length: 1
            0x01, // Change Cipher Spec message
        ];

        let result = parse_tls_record(&data);
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.content_type, 0x14);
        assert_eq!(record.version, 0x0301);
        assert_eq!(record.length, 1);
        assert!(record.handshake.is_none());
    }

    #[test]
    fn test_parse_tls_record_alert() {
        // Alert record
        let data = vec![
            0x15, // Content type: Alert
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x02, // Length: 2
            0x02, 0x28, // Alert: fatal, handshake failure
        ];

        let result = parse_tls_record(&data);
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.content_type, 0x15);
        assert_eq!(record.version, 0x0303);
        assert_eq!(record.length, 2);
        assert!(record.handshake.is_none());
    }

    #[test]
    fn test_parse_tls_record_application_data() {
        // Application Data record
        let data = vec![
            0x17, // Content type: Application Data
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x04, // Length: 4
            0x01, 0x02, 0x03, 0x04, // Application data
        ];

        let result = parse_tls_record(&data);
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.content_type, 0x17);
        assert_eq!(record.version, 0x0303);
        assert_eq!(record.length, 4);
        assert!(record.handshake.is_none());
    }

    #[test]
    fn test_parse_tls_record_encrypted() {
        // Encrypted record (TLS 1.3)
        let data = vec![
            0x80, // Content type: Encrypted
            0x03, 0x04, // Version: TLS 1.3
            0x00, 0x08, // Length: 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Encrypted data
        ];

        let result = parse_tls_record(&data);
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.content_type, 0x80);
        assert_eq!(record.version, 0x0304);
        assert_eq!(record.length, 8);
        assert!(record.handshake.is_none());
    }

    #[test]
    fn test_parse_tls_record_unknown_type() {
        // Unknown record type
        let data = vec![
            0x99, // Unknown content type
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x01, // Length: 1
            0x01, // Data
        ];

        let result = parse_tls_record(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_tls_record_incomplete_handshake() {
        // Handshake record with incomplete data
        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x10, // Length: 16 (but we only have 4 bytes)
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x0C, // Handshake length: 12
            // Missing handshake data
        ];

        let result = parse_tls_record(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_tls_record_client_hello_minimal() {
        // Minimal ClientHello
        let client_version = create_u16_be(0x0303); // TLS 1.2
        let random = [0x01; 32]; // 32 bytes of random data
        let session_id_len = [0x00]; // No session ID
        let cipher_suites_len = create_u16_be(2); // One cipher suite
        let cipher_suite = create_u16_be(0xC02F); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        let comp_methods_len = [0x01]; // One compression method
        let comp_method = [0x00]; // No compression
        let extensions_len = create_u16_be(0); // No extensions

        let handshake_data = vec![
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x2A, // Handshake length: 42
        ];

        let client_hello_data = vec![
            client_version[0], client_version[1], // Client version
            random.to_vec(), // Random
            session_id_len[0], // Session ID length
            cipher_suites_len[0], cipher_suites_len[1], // Cipher suites length
            cipher_suite[0], cipher_suite[1], // Cipher suite
            comp_methods_len[0], // Compression methods length
            comp_method[0], // Compression method
            extensions_len[0], extensions_len[1], // Extensions length
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x2E, // Length: 46 (4 + 42)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(client_hello_data);

        let result = parse_tls_record(&full_data);
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.content_type, 0x16);
        assert_eq!(record.version, 0x0303);
        assert_eq!(record.length, 0x2E);

        if let Some(HandshakeMessage::ClientHello(client_hello)) = record.handshake {
            assert_eq!(client_hello.client_version, 0x0303);
            assert_eq!(client_hello.random.len(), 32);
            assert_eq!(client_hello.session_id.len(), 0);
            assert_eq!(client_hello.cipher_suites.len(), 1);
            assert_eq!(client_hello.cipher_suites[0], 0xC02F);
            assert_eq!(client_hello.compression_methods.len(), 1);
            assert_eq!(client_hello.compression_methods[0], 0x00);
            assert_eq!(client_hello.extensions.len(), 0);
        } else {
            panic!("Expected ClientHello handshake message");
        }
    }

    #[test]
    fn test_parse_tls_record_client_hello_with_extensions() {
        // ClientHello with extensions
        let client_version = create_u16_be(0x0304); // TLS 1.3
        let random = [0x02; 32]; // 32 bytes of random data
        let session_id_len = [0x00]; // No session ID
        let cipher_suites_len = create_u16_be(4); // Two cipher suites
        let cipher_suite1 = create_u16_be(0x1301); // TLS_AES_128_GCM_SHA256
        let cipher_suite2 = create_u16_be(0x1302); // TLS_AES_256_GCM_SHA384
        let comp_methods_len = [0x01]; // One compression method
        let comp_method = [0x00]; // No compression

        // Extensions
        let extensions_len = create_u16_be(8); // Total extensions length
        let ext1_type = create_u16_be(0x000A); // supported_groups
        let ext1_len = create_u16_be(2); // Extension length
        let ext1_data = [0x00, 0x02]; // Two groups
        let group1 = create_u16_be(0x0017); // secp256r1
        let group2 = create_u16_be(0x0018); // secp384r1

        let handshake_data = vec![
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x3A, // Handshake length: 58
        ];

        let client_hello_data = vec![
            client_version[0], client_version[1], // Client version
            random.to_vec(), // Random
            session_id_len[0], // Session ID length
            cipher_suites_len[0], cipher_suites_len[1], // Cipher suites length
            cipher_suite1[0], cipher_suite1[1], // First cipher suite
            cipher_suite2[0], cipher_suite2[1], // Second cipher suite
            comp_methods_len[0], // Compression methods length
            comp_method[0], // Compression method
            extensions_len[0], extensions_len[1], // Extensions length
            ext1_type[0], ext1_type[1], // Extension type
            ext1_len[0], ext1_len[1], // Extension length
            ext1_data[0], ext1_data[1], // Extension data
            group1[0], group1[1], // First group
            group2[0], group2[1], // Second group
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x04, // Version: TLS 1.3
            0x00, 0x3E, // Length: 62 (4 + 58)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(client_hello_data);

        let result = parse_tls_record(&full_data);
        assert!(result.is_some());
        let record = result.unwrap();

        if let Some(HandshakeMessage::ClientHello(client_hello)) = record.handshake {
            assert_eq!(client_hello.client_version, 0x0304);
            assert_eq!(client_hello.cipher_suites.len(), 2);
            assert_eq!(client_hello.cipher_suites[0], 0x1301);
            assert_eq!(client_hello.cipher_suites[1], 0x1302);
            assert_eq!(client_hello.extensions.len(), 1);
            assert_eq!(client_hello.extensions[0].0, 0x000A); // supported_groups
        } else {
            panic!("Expected ClientHello handshake message");
        }
    }

    #[test]
    fn test_parse_tls_record_server_hello() {
        // ServerHello
        let server_version = create_u16_be(0x0303); // TLS 1.2
        let random = [0x03; 32]; // 32 bytes of random data
        let session_id_len = [0x00]; // No session ID
        let cipher_suite = create_u16_be(0xC02F); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        let comp_method = [0x00]; // No compression
        let extensions_len = create_u16_be(0); // No extensions

        let handshake_data = vec![
            0x02, // Handshake type: ServerHello
            0x00, 0x00, 0x25, // Handshake length: 37
        ];

        let server_hello_data = vec![
            server_version[0], server_version[1], // Server version
            random.to_vec(), // Random
            session_id_len[0], // Session ID length
            cipher_suite[0], cipher_suite[1], // Selected cipher suite
            comp_method[0], // Compression method
            extensions_len[0], extensions_len[1], // Extensions length
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x29, // Length: 41 (4 + 37)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(server_hello_data);

        let result = parse_tls_record(&full_data);
        assert!(result.is_some());
        let record = result.unwrap();

        if let Some(HandshakeMessage::ServerHello(server_hello)) = record.handshake {
            assert_eq!(server_hello.server_version, 0x0303);
            assert_eq!(server_hello.cipher_suite, 0xC02F);
            assert_eq!(server_hello.extensions.len(), 0);
        } else {
            panic!("Expected ServerHello handshake message");
        }
    }

    #[test]
    fn test_parse_tls_record_certificate() {
        // Certificate message
        let cert_data = [0x04, 0x05, 0x06, 0x07]; // Dummy certificate data
        let cert_len = create_u24_be(4); // Certificate length

        let handshake_data = vec![
            0x0B, // Handshake type: Certificate
            0x00, 0x00, 0x04, // Handshake length: 4
        ];

        let cert_message_data = vec![
            cert_len[0], cert_len[1], cert_len[2], // Certificate length
            cert_data[0], cert_data[1], cert_data[2], cert_data[3], // Certificate data
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x08, // Length: 8 (4 + 4)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(cert_message_data);

        let result = parse_tls_record(&full_data);
        assert!(result.is_some());
        let record = result.unwrap();

        if let Some(HandshakeMessage::Certificate(certificates)) = record.handshake {
            assert_eq!(certificates.len(), 1);
            assert_eq!(certificates[0], &[0x04, 0x05, 0x06, 0x07]);
        } else {
            panic!("Expected Certificate handshake message");
        }
    }

    #[test]
    fn test_parse_tls_record_unknown_handshake() {
        // Unknown handshake type
        let handshake_data = vec![
            0x99, // Unknown handshake type
            0x00, 0x00, 0x01, // Handshake length: 1
            0x01, // Some data
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x05, // Length: 5 (4 + 1)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);

        let result = parse_tls_record(&full_data);
        assert!(result.is_some());
        let record = result.unwrap();
        assert!(record.handshake.is_none()); // Unknown handshake types return None
    }

    #[test]
    fn test_parse_tls_record_client_hello_incomplete() {
        // ClientHello with incomplete data
        let handshake_data = vec![
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x10, // Handshake length: 16
        ];

        let incomplete_client_hello = vec![
            0x03, 0x03, // Client version
            // Missing random data, session ID, etc.
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x14, // Length: 20 (4 + 16)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(incomplete_client_hello);

        let result = parse_tls_record(&full_data);
        assert!(result.is_none()); // Should fail due to incomplete data
    }

    #[test]
    fn test_parse_tls_record_server_hello_incomplete() {
        // ServerHello with incomplete data
        let handshake_data = vec![
            0x02, // Handshake type: ServerHello
            0x00, 0x00, 0x10, // Handshake length: 16
        ];

        let incomplete_server_hello = vec![
            0x03, 0x03, // Server version
            // Missing random data, session ID, etc.
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x14, // Length: 20 (4 + 16)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(incomplete_server_hello);

        let result = parse_tls_record(&full_data);
        assert!(result.is_none()); // Should fail due to incomplete data
    }

    #[test]
    fn test_parse_tls_record_with_session_id() {
        // ClientHello with session ID
        let client_version = create_u16_be(0x0303); // TLS 1.2
        let random = [0x04; 32]; // 32 bytes of random data
        let session_id_len = [0x04]; // Session ID length: 4
        let session_id = [0xAA, 0xBB, 0xCC, 0xDD]; // Session ID data
        let cipher_suites_len = create_u16_be(2); // One cipher suite
        let cipher_suite = create_u16_be(0xC02F); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        let comp_methods_len = [0x01]; // One compression method
        let comp_method = [0x00]; // No compression
        let extensions_len = create_u16_be(0); // No extensions

        let handshake_data = vec![
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x2E, // Handshake length: 46
        ];

        let client_hello_data = vec![
            client_version[0], client_version[1], // Client version
            random.to_vec(), // Random
            session_id_len[0], // Session ID length
            session_id.to_vec(), // Session ID
            cipher_suites_len[0], cipher_suites_len[1], // Cipher suites length
            cipher_suite[0], cipher_suite[1], // Cipher suite
            comp_methods_len[0], // Compression methods length
            comp_method[0], // Compression method
            extensions_len[0], extensions_len[1], // Extensions length
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x32, // Length: 50 (4 + 46)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(client_hello_data);

        let result = parse_tls_record(&full_data);
        assert!(result.is_some());
        let record = result.unwrap();

        if let Some(HandshakeMessage::ClientHello(client_hello)) = record.handshake {
            assert_eq!(client_hello.session_id.len(), 4);
            assert_eq!(client_hello.session_id, &[0xAA, 0xBB, 0xCC, 0xDD]);
        } else {
            panic!("Expected ClientHello handshake message");
        }
    }

    #[test]
    fn test_parse_tls_record_multiple_cipher_suites() {
        // ClientHello with multiple cipher suites
        let client_version = create_u16_be(0x0303); // TLS 1.2
        let random = [0x05; 32]; // 32 bytes of random data
        let session_id_len = [0x00]; // No session ID
        let cipher_suites_len = create_u16_be(6); // Three cipher suites
        let cipher_suite1 = create_u16_be(0xC02F); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        let cipher_suite2 = create_u16_be(0xC030); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        let cipher_suite3 = create_u16_be(0x009C); // TLS_RSA_WITH_AES_128_GCM_SHA256
        let comp_methods_len = [0x01]; // One compression method
        let comp_method = [0x00]; // No compression
        let extensions_len = create_u16_be(0); // No extensions

        let handshake_data = vec![
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x2E, // Handshake length: 46
        ];

        let client_hello_data = vec![
            client_version[0], client_version[1], // Client version
            random.to_vec(), // Random
            session_id_len[0], // Session ID length
            cipher_suites_len[0], cipher_suites_len[1], // Cipher suites length
            cipher_suite1[0], cipher_suite1[1], // First cipher suite
            cipher_suite2[0], cipher_suite2[1], // Second cipher suite
            cipher_suite3[0], cipher_suite3[1], // Third cipher suite
            comp_methods_len[0], // Compression methods length
            comp_method[0], // Compression method
            extensions_len[0], extensions_len[1], // Extensions length
        ];

        let data = vec![
            0x16, // Content type: Handshake
            0x03, 0x03, // Version: TLS 1.2
            0x00, 0x32, // Length: 50 (4 + 46)
        ];

        let mut full_data = data;
        full_data.extend(handshake_data);
        full_data.extend(client_hello_data);

        let result = parse_tls_record(&full_data);
        assert!(result.is_some());
        let record = result.unwrap();

        if let Some(HandshakeMessage::ClientHello(client_hello)) = record.handshake {
            assert_eq!(client_hello.cipher_suites.len(), 3);
            assert_eq!(client_hello.cipher_suites[0], 0xC02F);
            assert_eq!(client_hello.cipher_suites[1], 0xC030);
            assert_eq!(client_hello.cipher_suites[2], 0x009C);
        } else {
            panic!("Expected ClientHello handshake message");
        }
    }
}                      