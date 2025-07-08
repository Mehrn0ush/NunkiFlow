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
        
        // Check for valid TLS content types (20-23 for TLS 1.0-1.2, 0x14-0x17 for TLS 1.3)
        if (content_type >= 20 && content_type <= 23) || content_type >= 0x14 {
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