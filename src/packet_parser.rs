#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl Default for TcpFlags {
    fn default() -> Self {
        TcpFlags {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
            ece: false,
            cwr: false,
        }
    }
}



/// A small buffer that accumulates raw bytes until a complete TLS record is available.
/// Internally holds a `Vec<u8>`; on each call to `add_data` you append new bytes and then
/// check `has_complete_record`. If it returns `true`, `get_record` will extract exactly one
/// TLS record (header + payload) and remove it from the internal buffer.

pub struct TlsBuffer {
    data: Vec<u8>,
}

impl TlsBuffer {
    pub fn new() -> Self {
        TlsBuffer {
            data: Vec::new(),
        }
    }


    /// Appends `new_data` to the internal buffer and returns `true` if, after appending,
    /// a complete TLS record is available. Otherwise returns `false`.
    ///
    /// # Parameters
    /// - `new_data`: A slice of bytes received from the TCP stream.
    ///
    /// # Returns
    /// - `true` if a complete TLS record (i.e., 5-byte header + record_length) is fully present.
    /// - `false` otherwise.

    pub fn add_data(&mut self, new_data: &[u8]) -> bool {
        self.data.extend_from_slice(new_data);
        self.has_complete_record()
    }

        /// Checks whether the internal buffer currently holds at least one complete TLS record.
    ///
    /// A TLS record is considered “complete” if:
    /// 1. There are at least 5 bytes available (TLS header), and
    /// 2. The 3rd and 4th bytes of the header (bytes[3..5]) form a length field,
    ///    and `buffer.len() >= 5 + record_length`.
    ///
    /// # Returns
    /// - `true` if at least one full TLS record is in `self.data`.
    /// - `false` otherwise.
    
    pub fn has_complete_record(&self) -> bool {
        if self.data.len() < 5 {
            return false;
        }
        
        let record_length = ((self.data[3] as usize) << 8) | self.data[4] as usize;
        self.data.len() >= 5 + record_length
    }

        /// If `has_complete_record` returns `true`, this method extracts exactly one complete
    /// TLS record (header + payload) from the front of the buffer, removing it from `self.data`,
    /// and returns that record as a `Vec<u8>`.
    ///
    /// # Returns
    /// - `Some(Vec<u8>)` containing one full TLS record, if available.
    /// - `None` if no complete record is present.
    
    pub fn get_record(&mut self) -> Option<Vec<u8>> {
        if !self.has_complete_record() {
            return None;
        }

        let record_length = ((self.data[3] as usize) << 8) | self.data[4] as usize;
        let total_length = 5 + record_length;
        
        if self.data.len() >= total_length {
            let record: Vec<u8> = self.data.drain(..total_length).collect();
            Some(record)
        } else {
            None
        }
    }
}


/// Returns the byte offset at which the IPv4 header begins within `data`.
///
/// Many link-layer headers precede the IPv4 header; this function:
/// 1. Checks if the first two bytes look like an Ethernet header (0xFF:0xFF or similar).  
/// 2. If it appears to be Ethernet (the “EtherType” field at offset 12–13 is 0x0800), returns 14.  
/// 3. Otherwise, if the very first byte is 0x45–0x4F (IPv4 version + header length), assumes no Ethernet/AWI header
///    and returns 0.  
///
/// # Parameters
/// - `data`: A raw packet buffer (Ethernet + IP + TCP/UDP payload).
///
/// # Returns
/// - `Some(usize)` with the index at which the IPv4 header starts (usually 14 or 0).
/// - `None` if `data` is too short to contain an IPv4 header or does not match known patterns.

// Helper function to find IPv4 header offset
fn find_ip_header_offset(data: &[u8]) -> Option<usize> {
    // Standard Ethernet header is 14 bytes, but some networks might use different sizes
    // Try the most common offsets first
    let possible_offsets = [14, 16, 18, 20];
    
    for &offset in &possible_offsets {
        if data.len() < offset + 20 {
            continue;
        }
        
        let version_ihl = data[offset];
        let version = version_ihl >> 4;
        let ihl = (version_ihl & 0x0F) * 4;
        
        // Validate IPv4 header
        if version == 4 && ihl >= 20 && ihl <= 60 && data.len() >= offset + (ihl as usize) {
            // Additional validation: check that the next byte after IP header looks like TCP
            if data.len() >= offset + ihl as usize + 1 {
                let protocol = data[offset + 9];
                if protocol == 6 { // TCP
                    return Some(offset);
                }
            }
        }
    }
    
    // Fallback: try other offsets only if standard ones failed
    let fallback_offsets = [0, 4, 8, 12];
    for &offset in &fallback_offsets {
        if data.len() < offset + 20 {
            continue;
        }
        
        let version_ihl = data[offset];
        let version = version_ihl >> 4;
        let ihl = (version_ihl & 0x0F) * 4;
        
        if version == 4 && ihl >= 20 && ihl <= 60 && data.len() >= offset + (ihl as usize) {
            if data.len() >= offset + ihl as usize + 1 {
                let protocol = data[offset + 9];
                if protocol == 6 { // TCP
                    return Some(offset);
                }
            }
        }
    }
    
    None
}

/// Extracts IPv4 source and destination addresses from a raw packet.
///
/// # Parameters
/// - `data`: A raw packet buffer (Ethernet + IPv4 + TCP/UDP payload).
///
/// # Returns
/// - `Some((src_ip, dst_ip))`, where each IP is a `[u8; 4]` (e.g. `[192, 168, 1, 10]`), if parsing succeeds.
/// - `None` if the packet is too short, missing an IPv4 header, or addresses are invalid (all zeros).


pub fn extract_ip_addresses(data: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    let ip_offset = find_ip_header_offset(data)?;
    
    // Extract source IP
    let src_ip_start = ip_offset + 12;
    let src_ip = [
        data[src_ip_start],
        data[src_ip_start + 1],
        data[src_ip_start + 2],
        data[src_ip_start + 3],
    ];

    // Extract destination IP
    let dst_ip_start = ip_offset + 16;
    let dst_ip = [
        data[dst_ip_start],
        data[dst_ip_start + 1],
        data[dst_ip_start + 2],
        data[dst_ip_start + 3],
    ];

    // Validate IP addresses
    if src_ip.iter().all(|&x| x == 0) || dst_ip.iter().all(|&x| x == 0) {
        return None;
    }

    Some((src_ip, dst_ip))
}

/// Extracts source and destination TCP ports from a raw packet.
///
/// # Parameters
/// - `data`: A raw packet buffer (Ethernet + IPv4 + TCP payload).
///
/// # Returns
/// - `Some((src_port, dst_port))` if the packet is at least large enough to contain an IP header and TCP header.
/// - `None` if parsing fails (e.g., not IPv4, not TCP, or truncated).

pub fn extract_tcp_ports(data: &[u8]) -> Option<(u16, u16)> {
    let ip_offset = find_ip_header_offset(data)?;
    
    // Get IP header length
    let ihl = (data[ip_offset] & 0x0F) * 4;
    
    // Verify protocol is TCP
    let protocol = data[ip_offset + 9];
    if protocol != 6 {
        return None;
    }

    let tcp_header_start = ip_offset + ihl as usize;
    if data.len() < tcp_header_start + 4 {
        return None;
    }

    let src_port = ((data[tcp_header_start] as u16) << 8) | data[tcp_header_start + 1] as u16;
    let dst_port = ((data[tcp_header_start + 2] as u16) << 8) | data[tcp_header_start + 3] as u16;

    Some((src_port, dst_port))
}

/// Extracts the TCP flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR) from a raw packet.
///
/// # Parameters
/// - `data`: A raw packet buffer (Ethernet + IPv4 + TCP payload).
///
/// # Returns
/// - `Some(TcpFlags)` if we successfully locate and parse a TCP header.
/// - `None` if the packet is not large enough or not TCP.
/// 
/// The resulting `TcpFlags` has each boolean field set according to the corresponding bit
/// in the TCP flags byte.

pub fn extract_tcp_flags(data: &[u8]) -> Option<TcpFlags> {
    let ip_offset = find_ip_header_offset(data)?;
    
    // Get IP header length
    let ihl = (data[ip_offset] & 0x0F) * 4;

    let tcp_header_start = ip_offset + ihl as usize;
    if data.len() < tcp_header_start + 14 {
        return None;
    }

    let flags = data[tcp_header_start + 13];
    Some(TcpFlags {
        fin: flags & 0x01 != 0,
        syn: flags & 0x02 != 0,
        rst: flags & 0x04 != 0,
        psh: flags & 0x08 != 0,
        ack: flags & 0x10 != 0,
        urg: flags & 0x20 != 0,
        ece: flags & 0x40 != 0,
        cwr: flags & 0x80 != 0,
    })
}

/// Extracts the TCP window size from a raw packet.
///
/// # Parameters
/// - `data`: A raw packet buffer (Ethernet + IPv4 + TCP payload).
///
/// # Returns
/// - `Some(window_size)` if found, interpreted as a 16-bit field in network byte order.
/// - `None` if the packet is too short or not a TCP packet.

pub fn extract_window_size(data: &[u8]) -> Option<u32> {
    let ip_offset = find_ip_header_offset(data)?;
    
    // Get IP header length
    let ihl = (data[ip_offset] & 0x0F) * 4;

    let tcp_header_start = ip_offset + ihl as usize;
    if data.len() < tcp_header_start + 16 {
        return None;
    }

    let window_size = ((data[tcp_header_start + 14] as u32) << 8) | 
                      (data[tcp_header_start + 15] as u32);
    Some(window_size)
}

/// Computes the total header length (IP header + TCP header) in bytes for a raw packet.
///
/// # Parameters
/// - `data`: A raw packet buffer (Ethernet + IPv4 + TCP payload).
///
/// # Returns
/// - `Some(total_len)` = IP header length + TCP header length, if parsing succeeds.
/// - `None` otherwise (e.g., not IPv4 or not TCP or truncated).

pub fn get_total_header_len(data: &[u8]) -> Option<usize> {
    let ip_offset = find_ip_header_offset(data)?;
    
    // Get IP header length
    let ihl = (data[ip_offset] & 0x0F) * 4;

    let tcp_header_start = ip_offset + ihl as usize;
    if data.len() < tcp_header_start + 20 {
        return None;
    }

    let tcp_header_len = (((data[tcp_header_start + 12] & 0xf0) >> 4) * 4) as usize;
    Some(ip_offset + ihl as usize + tcp_header_len)
}


/// If this packet contains a TLS record, extracts its payload (full TLS record: 
/// 5-byte TLS header + record_length) and returns it as a `Vec<u8>`.
///
/// # Parameters
/// - `data`: A raw packet buffer (Ethernet + IPv4 + TCP payload).
///
/// # Returns
/// - `Some(Vec<u8>)` containing the entire TLS record (header + payload) if:
///    1. The packet is IPv4/TCP,  
///    2. The payload begins with a valid TLS content type (20–23 or ≥ 0x14), and
///    3. The version bytes look like TLS 1.0–1.3.  
/// - `None` otherwise.
///
/// Internally:
/// 1. Locate the IPv4 header.  
/// 2. Check `protocol == 6` (TCP).  
/// 3. Compute TCP header length, find payload offset.  
/// 4. If at least 5 bytes of payload remain, parse:  
///    - Byte 0: TLS content type (e.g. 0x16 for Handshake, 0x17 for Application Data).  
///    - Byte 1: Version major (should be 0x03 for TLS 1.0–1.3).  
///    - Byte 2: Version minor (0x00..0x03), or ≥ 0x7f for encrypted TLS 1.3 record.  
///    - Bytes 3–4: 16-bit record length.  
/// 5. If those checks pass, extract `5 + record_length` bytes from the payload and return them.

pub fn extract_tls_payload(data: &[u8]) -> Option<Vec<u8>> {
    let ip_offset = find_ip_header_offset(data)?;
    
    // Get IP header length
    let ihl = (data[ip_offset] & 0x0F) * 4;

    // Verify protocol is TCP
    let protocol = data[ip_offset + 9];
    if protocol != 6 {
        return None;
    }

    let tcp_header_start = ip_offset + ihl as usize;
    if data.len() < tcp_header_start + 20 {
        return None;
    }

    let tcp_header_len = (((data[tcp_header_start + 12] & 0xf0) >> 4) * 4) as usize;
    let payload_offset = tcp_header_start + tcp_header_len;
    
    if data.len() <= payload_offset {
        return None; // No payload
    }

    let payload = data[payload_offset..].to_vec();
    
    // Check if payload looks like TLS
    if payload.len() >= 5 {
        let content_type = payload[0];
        let version_major = payload[1];
        let version_minor = payload[2];
        
        // Accept 0x14–0x18 as valid TLS content types, and specific encrypted record types
        if (content_type >= 0x14 && content_type <= 0x18) || content_type == 0x80 {
            // Check for reasonable TLS versions
            if (version_major == 3 && version_minor <= 4) || // TLS 1.0-1.3
               (version_major >= 0x7f) // TLS 1.3 encrypted records
            {
                return Some(payload);
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a complete packet with Ethernet + IPv4 + TCP headers
    fn create_test_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
        window_size: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        
        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0x00; 14]); // Dummy Ethernet header
        
        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5 (20 bytes)
        packet.push(0x00); // Type of Service
        packet.extend_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes()); // Total Length
        packet.extend_from_slice(&[0x00, 0x00]); // Identification
        packet.extend_from_slice(&[0x40, 0x00]); // Flags and Fragment Offset
        packet.push(64); // TTL
        packet.push(6); // Protocol (TCP)
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum (dummy)
        packet.extend_from_slice(&src_ip); // Source IP
        packet.extend_from_slice(&dst_ip); // Destination IP
        
        // TCP header (20 bytes)
        packet.extend_from_slice(&src_port.to_be_bytes()); // Source Port
        packet.extend_from_slice(&dst_port.to_be_bytes()); // Destination Port
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Sequence Number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Acknowledgment Number
        packet.push(0x50); // Data Offset (5 * 4 = 20 bytes)
        packet.push(tcp_flags); // Flags
        packet.extend_from_slice(&window_size.to_be_bytes()); // Window Size
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum (dummy)
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer
        
        // Payload
        packet.extend_from_slice(payload);
        
        packet
    }

    // Helper function to create a TLS record
    fn create_tls_record(content_type: u8, version: u16, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(content_type);
        record.extend_from_slice(&version.to_be_bytes());
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn test_tcp_flags_default() {
        let flags = TcpFlags::default();
        assert!(!flags.fin);
        assert!(!flags.syn);
        assert!(!flags.rst);
        assert!(!flags.psh);
        assert!(!flags.ack);
        assert!(!flags.urg);
        assert!(!flags.ece);
        assert!(!flags.cwr);
    }

    #[test]
    fn test_tcp_flags_clone() {
        let flags = TcpFlags {
            fin: true,
            syn: true,
            rst: false,
            psh: true,
            ack: false,
            urg: false,
            ece: true,
            cwr: false,
        };
        let cloned = flags.clone();
        assert_eq!(flags.fin, cloned.fin);
        assert_eq!(flags.syn, cloned.syn);
        assert_eq!(flags.rst, cloned.rst);
        assert_eq!(flags.psh, cloned.psh);
        assert_eq!(flags.ack, cloned.ack);
        assert_eq!(flags.urg, cloned.urg);
        assert_eq!(flags.ece, cloned.ece);
        assert_eq!(flags.cwr, cloned.cwr);
    }

    #[test]
    fn test_tls_buffer_new() {
        let buffer = TlsBuffer::new();
        assert!(buffer.data.is_empty());
    }

    #[test]
    fn test_tls_buffer_add_data_empty() {
        let mut buffer = TlsBuffer::new();
        assert!(!buffer.add_data(&[]));
        assert!(buffer.data.is_empty());
    }

    #[test]
    fn test_tls_buffer_has_complete_record_too_short() {
        let buffer = TlsBuffer {
            data: vec![0x16, 0x03, 0x03, 0x00, 0x05], // Only header, no payload
        };
        assert!(!buffer.has_complete_record());
    }

    #[test]
    fn test_tls_buffer_has_complete_record_complete() {
        let mut buffer = TlsBuffer {
            data: vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05], // Header + 5 bytes payload
        };
        assert!(buffer.has_complete_record());
    }

    #[test]
    fn test_tls_buffer_get_record_complete() {
        let mut buffer = TlsBuffer {
            data: vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05],
        };
        let record = buffer.get_record();
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record, vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert!(buffer.data.is_empty());
    }

    #[test]
    fn test_tls_buffer_get_record_incomplete() {
        let mut buffer = TlsBuffer {
            data: vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02], // Incomplete payload
        };
        let record = buffer.get_record();
        assert!(record.is_none());
    }

    #[test]
    fn test_tls_buffer_multiple_records() {
        let mut buffer = TlsBuffer::new();
        
        // Add first record
        let record1 = create_tls_record(0x16, 0x0303, &[0x01, 0x02, 0x03]);
        let record2 = create_tls_record(0x17, 0x0303, &[0x04, 0x05, 0x06, 0x07]);
        
        buffer.add_data(&record1);
        buffer.add_data(&record2);
        
        // Get first record
        let extracted1 = buffer.get_record();
        assert!(extracted1.is_some());
        assert_eq!(extracted1.unwrap(), record1);
        
        // Get second record
        let extracted2 = buffer.get_record();
        assert!(extracted2.is_some());
        assert_eq!(extracted2.unwrap(), record2);
        
        // No more records
        assert!(buffer.get_record().is_none());
    }

    #[test]
    fn test_extract_ip_addresses_valid() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            80,
            0x18, // SYN + ACK
            65535,
            &[],
        );
        
        let result = extract_ip_addresses(&packet);
        assert!(result.is_some());
        let (src_ip, dst_ip) = result.unwrap();
        assert_eq!(src_ip, [192, 168, 1, 10]);
        assert_eq!(dst_ip, [192, 168, 1, 1]);
    }

    #[test]
    fn test_extract_ip_addresses_zero_src() {
        let packet = create_test_packet(
            [0, 0, 0, 0], // Zero source IP
            [192, 168, 1, 1],
            12345,
            80,
            0x18,
            65535,
            &[],
        );
        
        let result = extract_ip_addresses(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_ip_addresses_zero_dst() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [0, 0, 0, 0], // Zero destination IP
            12345,
            80,
            0x18,
            65535,
            &[],
        );
        
        let result = extract_ip_addresses(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_ip_addresses_too_short() {
        let result = extract_ip_addresses(&[0x45, 0x00, 0x00, 0x14]);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tcp_ports_valid() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &[],
        );
        
        let result = extract_tcp_ports(&packet);
        assert!(result.is_some());
        let (src_port, dst_port) = result.unwrap();
        assert_eq!(src_port, 12345);
        assert_eq!(dst_port, 443);
    }

    #[test]
    fn test_extract_tcp_ports_not_tcp() {
        let mut packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &[],
        );
        
        // Change protocol to UDP (17)
        packet[23] = 17;
        
        let result = extract_tcp_ports(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tcp_ports_too_short() {
        let result = extract_tcp_ports(&[0x45, 0x00, 0x00, 0x14]);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tcp_flags_syn() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x02, // SYN flag
            65535,
            &[],
        );
        
        let result = extract_tcp_flags(&packet);
        assert!(result.is_some());
        let flags = result.unwrap();
        assert!(!flags.fin);
        assert!(flags.syn);
        assert!(!flags.rst);
        assert!(!flags.psh);
        assert!(!flags.ack);
        assert!(!flags.urg);
        assert!(!flags.ece);
        assert!(!flags.cwr);
    }

    #[test]
    fn test_extract_tcp_flags_all_flags() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0xFF, // All flags
            65535,
            &[],
        );
        
        let result = extract_tcp_flags(&packet);
        assert!(result.is_some());
        let flags = result.unwrap();
        assert!(flags.fin);
        assert!(flags.syn);
        assert!(flags.rst);
        assert!(flags.psh);
        assert!(flags.ack);
        assert!(flags.urg);
        assert!(flags.ece);
        assert!(flags.cwr);
    }

    #[test]
    fn test_extract_tcp_flags_too_short() {
        let result = extract_tcp_flags(&[0x45, 0x00, 0x00, 0x14]);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_window_size_valid() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            8192, // Window size
            &[],
        );
        
        let result = extract_window_size(&packet);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 8192);
    }

    #[test]
    fn test_extract_window_size_too_short() {
        let result = extract_window_size(&[0x45, 0x00, 0x00, 0x14]);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_total_header_len_valid() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &[],
        );
        
        let result = get_total_header_len(&packet);
        assert!(result.is_some());
        // Ethernet (14) + IP (20) + TCP (20) = 54
        assert_eq!(result.unwrap(), 54);
    }

    #[test]
    fn test_get_total_header_len_too_short() {
        let result = get_total_header_len(&[0x45, 0x00, 0x00, 0x14]);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tls_payload_valid_handshake() {
        let tls_record = create_tls_record(0x16, 0x0303, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &tls_record,
        );
        
        let result = extract_tls_payload(&packet);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), tls_record);
    }

    #[test]
    fn test_extract_tls_payload_valid_application_data() {
        let tls_record = create_tls_record(0x17, 0x0303, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &tls_record,
        );
        
        let result = extract_tls_payload(&packet);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), tls_record);
    }

    #[test]
    fn test_extract_tls_payload_tls13_encrypted() {
        let tls_record = create_tls_record(0x80, 0x0304, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &tls_record,
        );
        
        let result = extract_tls_payload(&packet);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), tls_record);
    }

    #[test]
    fn test_extract_tls_payload_invalid_content_type() {
        let tls_record = create_tls_record(0x99, 0x0303, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &tls_record,
        );
        
        let result = extract_tls_payload(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tls_payload_invalid_version() {
        let tls_record = create_tls_record(0x16, 0x0404, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &tls_record,
        );
        
        let result = extract_tls_payload(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tls_payload_not_tcp() {
        let tls_record = create_tls_record(0x16, 0x0303, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &tls_record,
        );
        
        // Change protocol to UDP (17)
        packet[23] = 17;
        
        let result = extract_tls_payload(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tls_payload_no_payload() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &[], // No payload
        );
        
        let result = extract_tls_payload(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tls_payload_too_short() {
        let result = extract_tls_payload(&[0x45, 0x00, 0x00, 0x14]);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ip_header_offset_standard_ethernet() {
        let packet = create_test_packet(
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            12345,
            443,
            0x18,
            65535,
            &[],
        );
        
        // This should find the IP header at offset 14 (standard Ethernet)
        let result = extract_ip_addresses(&packet);
        assert!(result.is_some());
    }

    #[test]
    fn test_find_ip_header_offset_no_ethernet() {
        // Create packet without Ethernet header
        let mut packet = Vec::new();
        
        // IPv4 header (20 bytes)
        packet.push(0x45); // Version 4, IHL 5 (20 bytes)
        packet.push(0x00); // Type of Service
        packet.extend_from_slice(&40u16.to_be_bytes()); // Total Length
        packet.extend_from_slice(&[0x00, 0x00]); // Identification
        packet.extend_from_slice(&[0x40, 0x00]); // Flags and Fragment Offset
        packet.push(64); // TTL
        packet.push(6); // Protocol (TCP)
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum (dummy)
        packet.extend_from_slice(&[192, 168, 1, 10]); // Source IP
        packet.extend_from_slice(&[192, 168, 1, 1]); // Destination IP
        
        // TCP header (20 bytes)
        packet.extend_from_slice(&12345u16.to_be_bytes()); // Source Port
        packet.extend_from_slice(&443u16.to_be_bytes()); // Destination Port
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Sequence Number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Acknowledgment Number
        packet.push(0x50); // Data Offset (5 * 4 = 20 bytes)
        packet.push(0x18); // Flags
        packet.extend_from_slice(&65535u16.to_be_bytes()); // Window Size
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum (dummy)
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer
        
        let result = extract_ip_addresses(&packet);
        assert!(result.is_some());
        let (src_ip, dst_ip) = result.unwrap();
        assert_eq!(src_ip, [192, 168, 1, 10]);
        assert_eq!(dst_ip, [192, 168, 1, 1]);
    }

    #[test]
    fn test_edge_cases() {
        // Test with minimum valid packet
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x00; 14]); // Ethernet header
        packet.push(0x45); // IPv4 header start
        packet.push(0x00);
        packet.extend_from_slice(&40u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00]);
        packet.extend_from_slice(&[192, 168, 1, 10, 192, 168, 1, 1]);
        packet.extend_from_slice(&[12345u16.to_be_bytes(), 443u16.to_be_bytes()].concat());
        packet.extend_from_slice(&[0x00; 16]); // Rest of TCP header
        
        let result = extract_ip_addresses(&packet);
        assert!(result.is_some());
    }
}