use std::io::{Result, Error, ErrorKind};
use pcap::Capture;

/// Represents a network packet read from a PCAP file.
///
/// Each `Packet` includes:
/// - a `timestamp` in microseconds (µs)
/// - a `Vec<u8>` containing the raw bytes of the packet

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: u64,
    pub data: Vec<u8>,
}


/// Opens a PCAP file and reads all packets contained within.
///
/// Each packet is converted into a `Packet` (see above) and returned in a `Vec<Packet>`.
/// Additionally, whenever 100,000 packets have been read, a progress message is printed to stdout.
///
/// # Parameters
/// - `filename`: The path to the PCAP file (for example, `"capture.pcap"`).
///
/// # Returns
/// - On success: `Ok(Vec<Packet>)` containing all packets read from the file.  
/// - On error opening or reading the file: `Err(std::io::Error)` with a descriptive message.
///
/// # Examples
/// ```rust
/// use std::io::Result;
///
/// fn main() -> Result<()> {
///     let packets = pcap_reader::read_all_packets("my_capture.pcap")?;
///     println!("Total packets read: {}", packets.len());
///     // Now you can process the packets...
///     Ok(())
/// }
/// ```
///
/// # Notes
/// 1. This function only retains the raw packet payload and timestamp. If you need to parse protocol headers
///    (e.g., Ethernet, IP, TCP/UDP), you must process the `data: Vec<u8>` afterwards or use additional libraries.
/// 2. Every 100,000 packets, a message “Read X packets (Y bytes)” is printed to indicate progress.
/// 3. If the PCAP file is very large, memory usage can be significant because all packets are stored in memory at once.
///
/// # Errors
/// - If the file cannot be opened or the PCAP format is invalid, an error with the message
///   `Failed to open PCAP file: …` is returned.


pub fn read_all_packets(filename: &str) -> Result<Vec<Packet>> {
    // Open the PCAP file
    let mut cap = Capture::from_file(filename)
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to open PCAP file: {}", e)))?;
    
    println!("Successfully opened PCAP file");
    
    // Get and display link layer information
    let datalink = cap.get_datalink();
    println!("Link layer type: {} ({})", datalink.get_name().unwrap_or("Unknown".to_string()), datalink.0);
    
    let mut packets = Vec::new();
    let mut packet_count = 0;
    let mut total_bytes = 0;
    
    // Read packets
    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        total_bytes += packet.header.len as u64;
        
        // Convert timestamp to microseconds
        let timestamp = (packet.header.ts.tv_sec as u64) * 1_000_000 + (packet.header.ts.tv_usec as u64);
        
        // Store the packet
        packets.push(Packet {
            timestamp,
            data: packet.data.to_vec(),
        });
        
        // Print progress
        if packet_count % 100000 == 0 {
            println!("Read {} packets ({} bytes)", packet_count, total_bytes);
        }
    }
    
    println!("Successfully read {} packets ({} bytes)", packet_count, total_bytes);
    Ok(packets)
}


/// Converts a numeric `link_type` (link-layer in PCAP) into a human-readable string.
///
/// This function maps known link-layer values (e.g., Ethernet, IEEE 802.11, etc.) to a `&'static str`.
/// If the `link_type` is not recognized, it returns `"Unknown"`.
///
/// # Parameters
/// - `link_type`: The numeric value from the PCAP header indicating the link layer.
///
/// # Returns
/// A static string describing the link-layer type.
///
/// # Examples
/// ```rust
/// assert_eq!(link_type_to_string(1), "Ethernet");
/// assert_eq!(link_type_to_string(127), "IEEE 802.11 Radiotap");
/// assert_eq!(link_type_to_string(999), "Unknown");
/// ```

fn link_type_to_string(link_type: u32) -> &'static str {
    match link_type {
        0 => "NULL",
        1 => "Ethernet",
        6 => "IEEE 802.5 Token Ring",
        7 => "ARCnet",
        8 => "SLIP",
        9 => "PPP",
        10 => "FDDI",
        100 => "LLC/SNAP-encapsulated ATM",
        101 => "Raw IP",
        105 => "IEEE 802.11 Wireless LAN",
        113 => "Linux cooked capture",
        127 => "IEEE 802.11 Radiotap",
        _ => "Unknown",
    }
} 