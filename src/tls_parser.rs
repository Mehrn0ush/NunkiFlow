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
                    let cert_data = &handshake_data[4..4 + handshake_length];
                    Some(TlsRecord {
                        content_type,
                        version,
                        length,
                        handshake: Some(HandshakeMessage::Certificate(vec![cert_data])),
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