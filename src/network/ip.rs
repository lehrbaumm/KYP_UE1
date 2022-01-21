use std::fmt;

pub enum IPHeader {
    V4(IP4Header),
    V6(IP6Header)
}

impl IPHeader {
    pub fn get_protocol(&self) -> u8 {
        match self {
            IPHeader::V4(header) => header.protocol,
            IPHeader::V6(header) => header.next_header
        }
    }
}

impl fmt::Display for IPHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IPHeader::V4(header) => write!(f, "{}", header),
            IPHeader::V6(header) => write!(f, "{}", header)
        }
    }
}

#[derive(Copy, Clone)]
pub struct IP4Header {
    pub version_length: u8, // 4 bytes Version | 4 bytes Length
    pub service_field: u8,
    pub packet_length: u16,
    pub identification: u16,
    pub flags: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4]
}

impl IP4Header {
    pub fn new(data: &[u8]) -> IP4Header {
        let version_length = data[14];
        let service_field = data[15];
        let packet_length = ((data[16] as u16) << 8) | data[17] as u16;
        let identification = ((data[18] as u16) << 8) | data[19] as u16;
        let flags = ((data[20] as u16) << 8) | data[21] as u16;
        let ttl = data[22];
        let protocol = data[23];
        let checksum = ((data[24] as u16) << 8) | data[25] as u16;
        let mut source_ip: [u8; 4] = [0; 4];
        source_ip.clone_from_slice(&data[26..30]);
        let mut destination_ip: [u8; 4] = [0; 4];
        destination_ip.clone_from_slice(&data[30..34]);
        
        IP4Header { version_length, service_field, packet_length, identification, flags, ttl, protocol, checksum, source_ip, destination_ip }
    }
}

impl fmt::Display for IP4Header {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IP Version: {}\t", self.version_length >> 4)?;
        write!(f, "Header Length: {} Bytes\t", (self.version_length & 0x0f)*4)?;
        write!(f, "Type of Service: {:02X}\t", self.service_field)?;
        write!(f, "Packet Length: {}\t", self.packet_length)?;
        write!(f, "Identification: {:04X}\n", self.identification)?;
        write!(f, "IP Header Flags: {:04X}\t", self.flags)?;
        write!(f, "TTL: {}\t", self.ttl)?;
        write!(f, "Protocol: ({})", self.protocol)?;
        match self.protocol {
            6 => write!(f, "TCP\t"),
            17 => write!(f, "UDP\t"),
            _ => write!(f, "Unknown\t"),
        }?;
        write!(f, "Header Checksum: {:04X}\nFrom: ", self.checksum)?;
        for i in 0..4 {
            if (i+1) % 4 == 0 {
                write!(f, "{}", self.source_ip[i])?;
            } else {
                write!(f, "{}.", self.source_ip[i])?;
            }
        }
        write!(f, "\tTo: ")?;
        for i in 0..4 {
            if (i+1) % 4 == 0 {
                write!(f, "{}", self.destination_ip[i])?;
            } else {
                write!(f, "{}.", self.destination_ip[i])?;
            }
        }
        write!(f, "")
    }
}

#[derive(Copy, Clone)]
pub struct IP6Header {
    pub header_info: u32, // 4 Bit Version, 8 Bit Traffic Class, 20 Bit Flow Label
    pub payload_length: u16,
    pub identification: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_ip: [u8; 16],
    pub destination_ip: [u8; 16]
}

impl IP6Header {
    pub fn new(data: &[u8]) -> IP6Header {
        let header_info = ((data[14] as u32) << 24) | ((data[15] as u32) << 16) | ((data[16] as u32) << 8) | data[17] as u32;
        let payload_length = ((data[18] as u16) << 8) | data[19] as u16;
        let identification = ((data[20] as u16) << 8) | data[21] as u16;
        let next_header = data[22];
        let hop_limit = data[23];
        let mut source_ip: [u8; 16] = [0; 16];
        source_ip.clone_from_slice(&data[24..40]);
        let mut destination_ip: [u8; 16] = [0; 16];
        destination_ip.clone_from_slice(&data[40..56]);
        
        IP6Header { header_info, payload_length, identification, next_header, hop_limit, source_ip, destination_ip }
    }
}

impl fmt::Display for IP6Header {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Version: {}\t", self.header_info >> 28)?;
        write!(f, "Traffiv Vlass: {}\t", self.header_info >> 20)?;
        write!(f, "Flow Label: {}\t", (self.header_info | 0x000FFFFF))?;
        write!(f, "\n")
    }
}